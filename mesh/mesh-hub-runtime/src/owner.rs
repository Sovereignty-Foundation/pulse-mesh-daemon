// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Owner locks: one live owner for a hub name, and for a socket path.
//!
//! An owner takes an [`OwnerLock`] on the lock file ([`hub_lock_path`],
//! [`socket_lock_path`]) before it touches what the lock guards, and holds it
//! for its life: a second owner stops with [`LockError::Held`], having touched
//! nothing. A lock is an exclusive `flock(2)`, which the kernel releases
//! however its holder exits, so a dead holder's file is reclaimed; the holder
//! records its process id in the file for others to report, and removes the
//! file as it lets go.
//!
//! A lock guards only while its file is at its path, and temporary directories
//! are cleaned by age (macOS's `tmp_cleaner` after three idle days,
//! `systemd-tmpfiles` after ten), so the holder refreshes its file
//! ([`OwnerLock::refresh`]) and puts it back if it was removed, unless it no
//! longer owns what the lock guards: then it has been displaced
//! ([`OwnerLock::is_displaced`]) and leaves the path to the next owner.
//!
//! Hub lock files are machine-wide, as shared-memory names are
//! ([`HUB_LOCK_DIR`]), since a per-user directory would let two users' daemons
//! own one hub.

use std::fs::{File, OpenOptions, Permissions, TryLockError};
use std::io;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use core_ring::RingError;

/// The directory of hub lock files: `/dev/shm`, where the hub's shared-memory
/// objects are, which every user shares.
#[cfg(target_os = "linux")]
pub const HUB_LOCK_DIR: &str = "/dev/shm";
/// The directory of hub lock files: `/tmp`, which every user shares, as they
/// share shared-memory names.
#[cfg(not(target_os = "linux"))]
pub const HUB_LOCK_DIR: &str = "/tmp";

/// How often a holder refreshes its lock file: well inside the three idle days
/// after which macOS's `tmp_cleaner` deletes a file in `/tmp`, and soon enough
/// that a removed file is back within a minute.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Tries, a millisecond apart, before a held lock is reported
/// [`LockError::Held`], so a [`lock_holder`] probe's instant is never taken for
/// an owner.
const HELD_TRIES: u32 = 10;

/// Rounds [`OwnerLock::acquire`] makes in all, each opening the path afresh; a
/// lock still changing hands after them is reported held.
const ACQUIRE_ROUNDS: u32 = 64;

/// Bytes of a lock file read back for the holder's process id.
const PID_RECORD_MAX: usize = 32;

/// The lock file of hub `hub`: `.pms-<hub>.lock` in [`HUB_LOCK_DIR`], hidden
/// and outside the `pms-*` pattern `just clean` matches, each capital letter
/// written as `+` and its lower case, so that names differing only in case lock
/// different files on a case-insensitive volume (`Foo` locks `.pms-+foo.lock`).
///
/// # Errors
///
/// The errors of [`crate::hub_shm_names`], which also keep the name inside the
/// directory.
pub fn hub_lock_path(hub: &str) -> Result<PathBuf, RingError> {
    crate::hub_shm_names(hub)?;
    let mut stem = String::with_capacity(2 * hub.len());
    for c in hub.chars() {
        if c.is_ascii_uppercase() {
            stem.push('+');
            stem.push(c.to_ascii_lowercase());
        } else {
            stem.push(c);
        }
    }
    Ok(Path::new(HUB_LOCK_DIR).join(format!(".pms-{stem}.lock")))
}

/// The lock file beside a Unix socket: the socket's path with `.lock`
/// appended, in the socket's own directory.
#[must_use]
pub fn socket_lock_path(socket: &Path) -> PathBuf {
    let mut path = socket.as_os_str().to_os_string();
    path.push(".lock");
    PathBuf::from(path)
}

/// Why an owner lock could not be taken, or its holder read.
#[derive(Debug)]
#[non_exhaustive]
pub enum LockError {
    /// A live process holds the lock: the hub name or the socket path has
    /// an owner, and nothing it guards was touched.
    Held {
        /// The lock file.
        path: PathBuf,
        /// The process id the holder recorded in the file, when it could be
        /// read.
        pid: Option<u32>,
    },
    /// The lock file could not be opened, locked or checked: the operating
    /// system's error, such as `EACCES` for a directory this user cannot write.
    Io {
        /// The lock file.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
    /// The lock path names something other than a plain file with one name,
    /// such as a symbolic link or a hard-linked file, which could redirect the
    /// holder's writes.
    NotPlain {
        /// The lock path.
        path: PathBuf,
    },
    /// The lock file was removed while its holder lived, and its ownership
    /// check ([`OwnerLock::set_ownership_check`]) says another owner has taken
    /// what it guards: the holder is displaced, and leaves the path to the next
    /// owner.
    Displaced {
        /// The lock path.
        path: PathBuf,
    },
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Held {
                path,
                pid: Some(pid),
            } => write!(f, "{} is held by process {pid}", path.display()),
            Self::Held { path, pid: None } => {
                write!(f, "{} is held by another process", path.display())
            }
            Self::Io { path, source } => write!(f, "lock file {}: {source}", path.display()),
            Self::NotPlain { path } => write!(
                f,
                "{} is not a plain file with one name; refusing to lock it",
                path.display()
            ),
            Self::Displaced { path } => write!(
                f,
                "{} was removed, and another owner has since taken what it guarded; \
                 this holder has been displaced",
                path.display()
            ),
        }
    }
}

impl std::error::Error for LockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// The holder of a lock, as [`lock_holder`] found it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockHolder {
    /// The process id the holder recorded in the lock file, or `None` when
    /// the file holds none that parses (a holder that could not write it,
    /// or one caught between taking the lock and writing its id).
    pub pid: Option<u32>,
}

/// What [`OwnerLock::refresh`] found at the lock's path, and did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refresh {
    /// The path still names the locked file, whose access and modification
    /// times are now the present.
    Touched,
    /// The path still names the locked file, whose times this process may
    /// not set: another user's lock file, reclaimed through a read-only
    /// open. Should it be removed, the next refresh puts a new one back.
    Untouchable,
    /// The locked file had been removed: a new one is at the path, locked,
    /// and records this process.
    Restored,
}

/// An exclusive advisory lock on a lock file, held until it drops, whose own
/// thread refreshes the file every [`REFRESH_INTERVAL`]
/// ([`OwnerLock::refresh`]). Dropping it stops the thread, removes the file if
/// the path still names it, and then releases the lock.
#[derive(Debug)]
pub struct OwnerLock {
    shared: Arc<Shared>,
    /// The thread that refreshes the lock file; joined when the lock drops.
    refresher: Option<std::thread::JoinHandle<()>>,
}

/// The holder's check that it still owns what its lock guards; see
/// [`OwnerLock::set_ownership_check`].
struct OwnershipCheck(Box<dyn Fn() -> bool + Send>);

impl std::fmt::Debug for OwnershipCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OwnershipCheck")
    }
}

/// The state an [`OwnerLock`] shares with its refresher.
#[derive(Debug)]
struct Shared {
    path: PathBuf,
    /// The locked file: the one opened when the lock was taken, or the one
    /// a refresh put back at the path.
    file: Mutex<File>,
    /// Set when the lock is let go, which stops the refresher.
    stopped: Mutex<bool>,
    /// Wakes the refresher when `stopped` is set.
    wake: Condvar,
    /// The holder's ownership check, once it has set one.
    ownership: Mutex<Option<OwnershipCheck>>,
    /// Set, for good, once a refresh has found the holder displaced.
    displaced: AtomicBool,
    /// Refreshes that could not set the lock file's times, counted to
    /// rate-limit their log.
    touch_failures: Mutex<crate::FailureCount>,
}

impl OwnerLock {
    /// Take the lock at `path`, creating the file (mode 0644, so any user can
    /// see who holds it) and recording this process's id in it; a dead holder's
    /// file is reclaimed, and another user's is locked read-only, without the
    /// id. Two holders in one process exclude each other as two processes do.
    ///
    /// # Errors
    ///
    /// [`LockError::Held`] when a live process holds the lock (still held after
    /// ten tries a millisecond apart, or changing hands throughout);
    /// [`LockError::NotPlain`] for a path that is not a plain file with one
    /// name; [`LockError::Io`] when the file cannot be opened or locked, or the
    /// refresher cannot start.
    pub fn acquire(path: &Path) -> Result<Self, LockError> {
        Self::acquire_refreshing(path, REFRESH_INTERVAL)
    }

    /// [`Self::acquire`], refreshing the lock file every `every`.
    fn acquire_refreshing(path: &Path, every: Duration) -> Result<Self, LockError> {
        let file = take(path)?;
        let mut lock = Self {
            shared: Arc::new(Shared {
                path: path.to_path_buf(),
                file: Mutex::new(file),
                stopped: Mutex::new(false),
                wake: Condvar::new(),
                ownership: Mutex::new(None),
                displaced: AtomicBool::new(false),
                touch_failures: Mutex::new(crate::FailureCount::default()),
            }),
            refresher: None,
        };
        let shared = Arc::clone(&lock.shared);
        let refresher = std::thread::Builder::new()
            .name("pms-lock-refresh".into())
            .spawn(move || shared.refresh_every(every))
            // `lock` drops on the way out: it removes the file and lets go.
            .map_err(|source| io_error(path, source))?;
        lock.refresher = Some(refresher);
        Ok(lock)
    }

    /// The lock file this lock holds.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.shared.path
    }

    /// Tell the lock how its holder knows it still owns what the lock guards:
    /// `still_owner` returns `false` once another owner has taken it (a hub
    /// checks that its ring is unmarked). [`Self::refresh`] asks before putting
    /// a removed file back, and again once the new file is locked, when the
    /// answer is final; a `false` displaces the holder. Without a check, a
    /// removed file is always put back; a later call replaces the check.
    ///
    /// `still_owner` runs with the lock's state locked, so it must not call
    /// back into the lock.
    pub fn set_ownership_check<F>(&self, still_owner: F)
    where
        F: Fn() -> bool + Send + 'static,
    {
        *self
            .shared
            .ownership
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(OwnershipCheck(Box::new(still_owner)));
    }

    /// Whether a refresh has found the holder displaced
    /// ([`LockError::Displaced`]); its file is then neither put back nor
    /// refreshed. Once `true`, it stays `true`.
    #[must_use]
    pub fn is_displaced(&self) -> bool {
        self.shared.displaced.load(Ordering::Acquire)
    }

    /// Keep the lock file at its path, as the lock's thread does every
    /// [`REFRESH_INTERVAL`]: set its times to now, which keeps a cleaner that
    /// goes by age off it ([`Refresh::Touched`], or [`Refresh::Untouchable`],
    /// logged, when this process may not set them), or put a removed file back,
    /// locked and naming this process ([`Refresh::Restored`]).
    ///
    /// # Errors
    ///
    /// [`LockError::Displaced`] when the file was removed and the holder no
    /// longer owns what the lock guards, the path left alone;
    /// [`LockError::Held`] when another process has locked a new file there
    /// while the holder still owns it, which is left alone too;
    /// [`LockError::NotPlain`] and [`LockError::Io`] as for [`Self::acquire`],
    /// and the next refresh tries again.
    pub fn refresh(&self) -> Result<Refresh, LockError> {
        self.shared.refresh()
    }
}

impl Shared {
    /// The refresher's loop: [`Self::refresh`] every `every` until the lock
    /// is let go or its holder is displaced, logging what it had to put
    /// right.
    fn refresh_every(&self, every: Duration) {
        // The holder last reported for a file another process locked, so a
        // second owner is reported once rather than every minute.
        let mut reported: Option<Option<u32>> = None;
        let mut failures: u64 = 0;
        loop {
            {
                let stopped = self.stopped.lock().unwrap_or_else(PoisonError::into_inner);
                let (stopped, _) = self
                    .wake
                    .wait_timeout_while(stopped, every, |stopped| !*stopped)
                    .unwrap_or_else(PoisonError::into_inner);
                if *stopped {
                    return;
                }
            }
            match self.refresh() {
                Ok(Refresh::Restored) => {
                    reported = None;
                    tracing::warn!(
                        path = %self.path.display(),
                        "the lock file was removed while its holder lived; put a new one back"
                    );
                }
                Ok(_) => {}
                Err(LockError::Displaced { .. }) => {
                    tracing::error!(
                        path = %self.path.display(),
                        "the lock file was removed while its holder lived, and another owner has \
                         taken what it guarded since: this holder has been displaced, and the lock \
                         file is left for the next owner and no longer refreshed"
                    );
                    return;
                }
                Err(LockError::Held { pid, .. }) => {
                    if reported != Some(pid) {
                        reported = Some(pid);
                        tracing::error!(
                            path = %self.path.display(),
                            holder = ?pid,
                            "the lock file was removed while its holder lived, and another process \
                             has locked a new one: a second owner may be taking what it guards"
                        );
                    }
                }
                Err(error) => {
                    failures += 1;
                    if failures.is_power_of_two() {
                        tracing::warn!(
                            path = %self.path.display(),
                            %error,
                            failures,
                            "the lock file could not be refreshed"
                        );
                    }
                }
            }
        }
    }

    /// Whether the holder still owns what the lock guards: `false` once it
    /// has been found displaced, and otherwise its ownership check's answer
    /// (`true` without one).
    fn still_owner(&self) -> bool {
        !self.displaced.load(Ordering::Acquire)
            && self
                .ownership
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
                .is_none_or(|check| (check.0)())
    }

    /// Record that the holder has been displaced, and the error that says so.
    fn displaced(&self) -> LockError {
        self.displaced.store(true, Ordering::Release);
        LockError::Displaced {
            path: self.path.clone(),
        }
    }

    /// See [`OwnerLock::refresh`].
    fn refresh(&self) -> Result<Refresh, LockError> {
        let mut file = self.file.lock().unwrap_or_else(PoisonError::into_inner);
        if names_file(&self.path, &file)? {
            let now = SystemTime::now();
            let times = std::fs::FileTimes::new()
                .set_accessed(now)
                .set_modified(now);
            return Ok(match file.set_times(times) {
                Ok(()) => Refresh::Touched,
                // Only a file's owner may set its times to a given value.
                Err(error) => {
                    let logged = self
                        .touch_failures
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .record();
                    if let Some(failures) = logged {
                        tracing::warn!(
                            path = %self.path.display(),
                            %error,
                            failures,
                            "the lock file's times could not be set, so a cleaner that removes \
                             files by age may take it; the lock puts it back if it does"
                        );
                    }
                    Refresh::Untouchable
                }
            });
        }
        // Removed: put back only while the holder still owns what it guards, or
        // every later owner would be locked out of a name whose objects are
        // gone.
        if !self.still_owner() {
            return Err(self.displaced());
        }
        let mut held = 0;
        let (restored, writable) = loop {
            let (restored, writable) = open_lock_file(&self.path)?;
            check_plain(&restored, &self.path)?;
            match restored.try_lock() {
                Ok(()) => break (restored, writable),
                Err(TryLockError::WouldBlock) => {
                    // A probe holds a shared lock for an instant; an owner
                    // holds on.
                    held += 1;
                    if held >= HELD_TRIES {
                        if !self.still_owner() {
                            return Err(self.displaced());
                        }
                        return Err(LockError::Held {
                            path: self.path.clone(),
                            pid: read_pid(&restored),
                        });
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(TryLockError::Error(source)) => return Err(io_error(&self.path, source)),
            }
        };
        if !names_file(&self.path, &restored)? {
            return Err(io_error(
                &self.path,
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "the lock file changed hands while it was being put back",
                ),
            ));
        }
        // With the new file locked, no owner can start: asked now, the check
        // sees any that took over while the file was gone.
        if !self.still_owner() {
            // Removed while it is still locked, as a holder removes its
            // file when it lets go; `restored` closes on the way out.
            let _ = std::fs::remove_file(&self.path);
            return Err(self.displaced());
        }
        if writable {
            let _ = record_pid(&restored);
            let _ = restored.set_permissions(Permissions::from_mode(0o644));
        }
        // The file replaced closes here, and its lock with it: nobody can
        // reach it by the path any more.
        *file = restored;
        Ok(Refresh::Restored)
    }
}

impl Drop for OwnerLock {
    fn drop(&mut self) {
        // Stop the refresher first, so that nothing puts the file back
        // once it is removed below.
        *self
            .shared
            .stopped
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = true;
        self.shared.wake.notify_all();
        if let Some(refresher) = self.refresher.take() {
            let _ = refresher.join();
        }
        // Remove the file while still locked, and only if the path still names
        // it: a process that locks it after finds it gone and opens the path
        // again, and a successor's file is never removed.
        let file = self
            .shared
            .file
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if names_file(&self.shared.path, &file).unwrap_or(false) {
            let _ = std::fs::remove_file(&self.shared.path);
        }
        // The file closes after this, as `shared` drops, which releases the
        // lock.
    }
}

/// Lock the file at `path` for this process, creating it if there is none,
/// and record this process's id in it: the rounds of
/// [`OwnerLock::acquire`].
fn take(path: &Path) -> Result<File, LockError> {
    let mut held = 0;
    for _ in 0..ACQUIRE_ROUNDS {
        let (file, writable) = open_lock_file(path)?;
        check_plain(&file, path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                held += 1;
                if held >= HELD_TRIES {
                    return Err(LockError::Held {
                        path: path.to_path_buf(),
                        pid: read_pid(&file),
                    });
                }
                // Open the path again next round: a holder that lets go
                // meanwhile removes this file.
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
            Err(TryLockError::Error(source)) => return Err(io_error(path, source)),
        }
        // A file its holder removed as it let go is one no later owner will
        // lock: open the path again.
        if !names_file(path, &file)? {
            continue;
        }
        if writable {
            // The id is for other processes' messages; the lock is the
            // flock, which holds whether or not the id could be written.
            let _ = record_pid(&file);
            // Readable by every user, whatever the umask made it.
            let _ = file.set_permissions(Permissions::from_mode(0o644));
        }
        return Ok(file);
    }
    // Every round found the lock held or changing hands.
    Err(LockError::Held {
        path: path.to_path_buf(),
        pid: recorded_pid(path),
    })
}

/// Who holds the lock at `path`, if a live process does, with the process id it
/// recorded. The probe takes a shared lock for an instant, which an owner
/// taking the lock retries past.
///
/// # Errors
///
/// [`LockError::Io`] when the file exists but cannot be opened or probed, and
/// [`LockError::NotPlain`] for a symbolic link or a file that is not plain.
pub fn lock_holder(path: &Path) -> Result<Option<LockHolder>, LockError> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(open_error(path, e)),
    };
    check_plain(&file, path)?;
    match file.try_lock_shared() {
        // Nobody holds it; the shared lock goes as `file` closes.
        Ok(()) => Ok(None),
        Err(TryLockError::WouldBlock) => Ok(Some(LockHolder {
            pid: read_pid(&file),
        })),
        Err(TryLockError::Error(source)) => Err(io_error(path, source)),
    }
}

/// The process id recorded in the lock file at `path`, read without touching
/// the lock: the holder's, or a dead holder's. Unlike [`lock_holder`] it cannot
/// disturb an owner taking the lock, so it is how a process waits for an owner
/// it started to hold it.
#[must_use]
pub fn recorded_pid(path: &Path) -> Option<u32> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    read_pid(&file)
}

/// Open the lock file at `path`, creating it, without following a symbolic
/// link: read-only when this user may not write it, which still lets it be
/// locked, and `true` with it when writable.
fn open_lock_file(path: &Path) -> Result<(File, bool), LockError> {
    let writable = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path);
    match writable {
        Ok(file) => Ok((file, true)),
        Err(denied) if denied.kind() == io::ErrorKind::PermissionDenied => {
            match OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)
            {
                Ok(file) => Ok((file, false)),
                // No file to lock: the directory refused its creation, and
                // that is the error to report.
                Err(e) if e.kind() == io::ErrorKind::NotFound => Err(open_error(path, denied)),
                Err(e) => Err(open_error(path, e)),
            }
        }
        Err(e) => Err(open_error(path, e)),
    }
}

/// The error for a failed open of `path`: [`LockError::NotPlain`] for a
/// symbolic link (which `O_NOFOLLOW` refuses with `ELOOP`), and
/// [`LockError::Io`] for anything else.
fn open_error(path: &Path, source: io::Error) -> LockError {
    if source.raw_os_error() == Some(libc::ELOOP) {
        LockError::NotPlain {
            path: path.to_path_buf(),
        }
    } else {
        io_error(path, source)
    }
}

fn io_error(path: &Path, source: io::Error) -> LockError {
    LockError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// `Ok` for a plain file with at most one name, [`LockError::NotPlain`]
/// otherwise. A file with none is one its holder removed after this process
/// opened it; the caller finds that out and opens the path again.
fn check_plain(file: &File, path: &Path) -> Result<(), LockError> {
    let meta = file.metadata().map_err(|e| io_error(path, e))?;
    if meta.file_type().is_file() && meta.nlink() <= 1 {
        Ok(())
    } else {
        Err(LockError::NotPlain {
            path: path.to_path_buf(),
        })
    }
}

/// Whether `path` still names `file`: the same device and inode, the path
/// itself not followed. `false` when nothing is at the path.
fn names_file(path: &Path, file: &File) -> Result<bool, LockError> {
    let open = file.metadata().map_err(|e| io_error(path, e))?;
    match std::fs::symlink_metadata(path) {
        Ok(named) => Ok(named.dev() == open.dev() && named.ino() == open.ino()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io_error(path, e)),
    }
}

/// Replace the lock file's contents with this process's id and a newline.
fn record_pid(file: &File) -> io::Result<()> {
    file.set_len(0)?;
    file.write_all_at(format!("{}\n", std::process::id()).as_bytes(), 0)
}

/// The process id recorded in a lock file, if it holds one.
fn read_pid(file: &File) -> Option<u32> {
    let mut record = [0u8; PID_RECORD_MAX];
    let len = file.read_at(&mut record, 0).ok()?;
    std::str::from_utf8(&record[..len])
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A lock path private to this process and test, in the system's
    /// temporary directory.
    fn lock_path(tag: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "pms-owner-{tag}-{}-{}.lock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn a_second_holder_is_refused_and_told_who_holds_it() {
        let path = lock_path("held");
        let first = OwnerLock::acquire(&path).unwrap();
        match OwnerLock::acquire(&path) {
            Err(LockError::Held { pid, .. }) => assert_eq!(pid, Some(std::process::id())),
            other => panic!("expected Held, got {other:?}"),
        }
        assert_eq!(
            lock_holder(&path).unwrap(),
            Some(LockHolder {
                pid: Some(std::process::id())
            })
        );
        drop(first);
        assert!(!path.exists(), "the holder removes its file as it lets go");
        assert_eq!(lock_holder(&path).unwrap(), None);
        let again = OwnerLock::acquire(&path).expect("free once the holder let go");
        drop(again);
    }

    #[test]
    fn a_lock_file_left_by_a_dead_holder_is_reclaimed() {
        let path = lock_path("dead");
        // What a holder killed outright leaves: the file with its id, and no
        // lock, which the kernel released with the process.
        std::fs::write(&path, "4000000000\n").unwrap();
        assert_eq!(lock_holder(&path).unwrap(), None, "nobody holds it");
        let lock = OwnerLock::acquire(&path).expect("the file is reclaimed");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{}\n", std::process::id()),
            "the new holder's id replaces the dead one's"
        );
        drop(lock);
        assert!(!path.exists());
    }

    #[test]
    fn a_symbolic_link_or_a_hard_linked_file_is_refused() {
        let target = lock_path("target");
        std::fs::write(&target, "precious").unwrap();
        let link = lock_path("symlink");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(
            OwnerLock::acquire(&link),
            Err(LockError::NotPlain { .. })
        ));
        assert!(matches!(
            lock_holder(&link),
            Err(LockError::NotPlain { .. })
        ));
        let hard = lock_path("hardlink");
        std::fs::hard_link(&target, &hard).unwrap();
        assert!(matches!(
            OwnerLock::acquire(&hard),
            Err(LockError::NotPlain { .. })
        ));
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "precious",
            "nothing was written through either link"
        );
        for path in [link, hard, target] {
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn a_holder_whose_file_was_replaced_leaves_the_new_file_alone() {
        let path = lock_path("replaced");
        let first = OwnerLock::acquire(&path).unwrap();
        // Something removes the lock file and another holder takes a new one
        // at the path while the first still holds its old file.
        std::fs::remove_file(&path).unwrap();
        let second = OwnerLock::acquire(&path).expect("a new file at the path is free");
        drop(first);
        assert!(path.exists(), "the first holder removed only its own file");
        assert!(matches!(
            OwnerLock::acquire(&path),
            Err(LockError::Held { .. })
        ));
        drop(second);
        assert!(!path.exists());
    }

    #[test]
    fn holders_racing_to_take_and_let_go_never_overlap() {
        use std::sync::atomic::AtomicUsize;
        let path = lock_path("race");
        let inside = AtomicUsize::new(0);
        let taken = AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| {
                    for _ in 0..200 {
                        match OwnerLock::acquire(&path) {
                            Ok(lock) => {
                                assert_eq!(inside.fetch_add(1, Ordering::SeqCst), 0, "two holders");
                                taken.fetch_add(1, Ordering::Relaxed);
                                std::thread::yield_now();
                                inside.fetch_sub(1, Ordering::SeqCst);
                                drop(lock);
                            }
                            Err(LockError::Held { .. }) => {}
                            Err(other) => panic!("{other}"),
                        }
                    }
                });
            }
        });
        assert!(taken.load(Ordering::Relaxed) > 0);
        assert!(!path.exists(), "the last holder removed the file");
    }

    #[test]
    fn hub_and_socket_lock_paths() {
        let hub = hub_lock_path("default_hub").unwrap();
        assert_eq!(
            hub,
            Path::new(HUB_LOCK_DIR).join(".pms-default_hub.lock"),
            "hidden, and outside the pms-* pattern"
        );
        assert_eq!(
            hub_lock_path("My.Hub-2").unwrap(),
            Path::new(HUB_LOCK_DIR).join(".pms-+my.+hub-2.lock"),
            "each capital letter written as + and its lower case"
        );
        assert!(hub_lock_path("../etc").is_err());
        assert!(hub_lock_path("").is_err());
        assert!(
            hub_lock_path("a+b").is_err(),
            "+ is not a hub-name character"
        );
        assert_eq!(
            socket_lock_path(Path::new("/tmp/pms.sock")),
            Path::new("/tmp/pms.sock.lock")
        );
    }

    #[test]
    fn hubs_whose_names_differ_only_in_case_have_locks_of_their_own() {
        // On a case-insensitive volume, as /tmp is on a Mac, these must still
        // be two files.
        let upper = format!("Cs{:08x}", std::process::id()).to_uppercase();
        let lower = upper.to_lowercase();
        assert_ne!(
            hub_lock_path(&upper).unwrap(),
            hub_lock_path(&lower).unwrap()
        );
        let first = OwnerLock::acquire(&hub_lock_path(&upper).unwrap()).unwrap();
        let second = OwnerLock::acquire(&hub_lock_path(&lower).unwrap())
            .expect("a hub whose name differs only in case is another hub");
        drop((first, second));
        assert!(!hub_lock_path(&upper).unwrap().exists());
        assert!(!hub_lock_path(&lower).unwrap().exists());
    }

    /// Set the access and modification times of the file at `path` to
    /// `days` days ago.
    fn age(path: &Path, days: u64) {
        let then = SystemTime::now() - Duration::from_secs(days * 24 * 60 * 60);
        let times = std::fs::FileTimes::new()
            .set_accessed(then)
            .set_modified(then);
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_times(times)
            .unwrap();
    }

    #[test]
    fn a_refresh_keeps_the_lock_files_times_recent() {
        let path = lock_path("fresh");
        let lock = OwnerLock::acquire(&path).unwrap();
        // What macOS's tmp_cleaner deletes: a file in /tmp none of whose
        // access, modification and change times moved in three days.
        age(&path, 4);
        let three_days_ago = SystemTime::now() - Duration::from_secs(3 * 24 * 60 * 60);
        let meta = std::fs::metadata(&path).unwrap();
        assert!(meta.modified().unwrap() < three_days_ago);
        assert_eq!(lock.refresh().unwrap(), Refresh::Touched);
        let meta = std::fs::metadata(&path).unwrap();
        let recent = SystemTime::now() - Duration::from_secs(60);
        assert!(meta.modified().unwrap() > recent, "modified now");
        assert!(meta.accessed().unwrap() > recent, "accessed now");
        drop(lock);
        assert!(!path.exists());
    }

    #[test]
    fn a_lock_file_removed_from_under_its_holder_is_put_back_and_a_second_holder_refused() {
        let path = lock_path("removed");
        let lock = OwnerLock::acquire(&path).unwrap();
        // A cleaner, or a person, removes the file: a second holder could
        // now lock a new one.
        std::fs::remove_file(&path).unwrap();
        assert_eq!(lock.refresh().unwrap(), Refresh::Restored);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{}\n", std::process::id()),
            "the file put back names the holder"
        );
        match OwnerLock::acquire(&path) {
            Err(LockError::Held { pid, .. }) => assert_eq!(pid, Some(std::process::id())),
            other => panic!("expected Held, got {other:?}"),
        }
        assert_eq!(lock.refresh().unwrap(), Refresh::Touched);
        drop(lock);
        assert!(!path.exists(), "the holder removes the file it put back");
        drop(OwnerLock::acquire(&path).expect("free once the holder let go"));
    }

    #[test]
    fn the_holders_own_thread_puts_a_removed_lock_file_back() {
        let path = lock_path("thread");
        let lock = OwnerLock::acquire_refreshing(&path, Duration::from_millis(10)).unwrap();
        std::fs::remove_file(&path).unwrap();
        // The refresher creates the file, locks it, checks it still owns
        // the name and only then records its id, so the id in the file, not
        // the file's existence, shows the lock is back.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while recorded_pid(&path) != Some(std::process::id()) {
            assert!(std::time::Instant::now() < deadline, "never put back");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(matches!(
            OwnerLock::acquire(&path),
            Err(LockError::Held { .. })
        ));
        drop(lock);
        assert!(!path.exists());
    }

    #[test]
    fn a_second_holder_of_a_removed_lock_file_is_reported_and_left_alone() {
        let path = lock_path("rival");
        let first = OwnerLock::acquire(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        // Before the first holder refreshes, a second locks a new file.
        let second = OwnerLock::acquire(&path).expect("the path was free");
        match first.refresh() {
            Err(LockError::Held { pid, .. }) => assert_eq!(pid, Some(std::process::id())),
            other => panic!("expected the second holder reported, got {other:?}"),
        }
        drop(first);
        assert!(path.exists(), "the second holder's file is left alone");
        assert!(matches!(
            OwnerLock::acquire(&path),
            Err(LockError::Held { .. })
        ));
        drop(second);
        assert!(!path.exists());
    }

    /// An ownership check that says the holder owns what its lock guards
    /// until `taken` is set, as a hub's says until its ring is marked.
    fn owned_until(lock: &OwnerLock) -> Arc<AtomicBool> {
        let taken = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&taken);
        lock.set_ownership_check(move || !seen.load(Ordering::SeqCst));
        taken
    }

    #[test]
    fn a_displaced_holder_leaves_its_removed_lock_file_for_the_next_owner() {
        let path = lock_path("displaced");
        let lock = OwnerLock::acquire(&path).unwrap();
        let taken = owned_until(&lock);
        // The file is removed, and a second owner takes what the lock
        // guards and goes, all between two refreshes.
        std::fs::remove_file(&path).unwrap();
        let second = OwnerLock::acquire(&path).expect("the path was free");
        taken.store(true, Ordering::SeqCst);
        drop(second);
        assert!(!path.exists());
        assert!(!lock.is_displaced(), "not until a refresh finds it");
        // A file put back now would name the first holder and refuse every
        // later owner.
        assert!(matches!(lock.refresh(), Err(LockError::Displaced { .. })));
        assert!(lock.is_displaced());
        assert!(!path.exists(), "the file is not put back");
        let next = OwnerLock::acquire(&path).expect("the next owner takes the path");
        assert!(matches!(lock.refresh(), Err(LockError::Displaced { .. })));
        drop(lock);
        assert!(
            path.exists(),
            "the displaced holder leaves the next one's file"
        );
        drop(next);
        assert!(!path.exists());
    }

    #[test]
    fn a_holder_is_displaced_once_the_second_holder_of_its_path_takes_what_it_guards() {
        let path = lock_path("displacing");
        let first = OwnerLock::acquire(&path).unwrap();
        let taken = owned_until(&first);
        std::fs::remove_file(&path).unwrap();
        let second = OwnerLock::acquire(&path).expect("the path was free");
        assert!(
            matches!(first.refresh(), Err(LockError::Held { .. })),
            "a second holder that has not taken anything yet is reported"
        );
        assert!(!first.is_displaced());
        taken.store(true, Ordering::SeqCst);
        assert!(matches!(first.refresh(), Err(LockError::Displaced { .. })));
        assert!(first.is_displaced());
        drop(second);
        assert!(matches!(first.refresh(), Err(LockError::Displaced { .. })));
        assert!(
            !path.exists(),
            "nothing is put back once the second has gone"
        );
        drop(first);
    }

    #[test]
    fn a_holder_displaced_while_it_put_its_file_back_removes_the_file_again() {
        let path = lock_path("late");
        let lock = OwnerLock::acquire(&path).unwrap();
        // Still the owner when asked before the file is back, displaced
        // when asked again once it is locked at the path.
        let asked = Arc::new(AtomicU64::new(0));
        let count = Arc::clone(&asked);
        lock.set_ownership_check(move || count.fetch_add(1, Ordering::SeqCst) == 0);
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(lock.refresh(), Err(LockError::Displaced { .. })));
        assert_eq!(asked.load(Ordering::SeqCst), 2, "asked before and after");
        assert!(lock.is_displaced());
        assert!(!path.exists(), "the file put back is removed again");
        drop(OwnerLock::acquire(&path).expect("and the path is free"));
        drop(lock);
    }

    #[test]
    fn a_holder_that_still_owns_what_its_lock_guards_puts_its_file_back() {
        let path = lock_path("owner");
        let lock = OwnerLock::acquire(&path).unwrap();
        let _taken = owned_until(&lock);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(lock.refresh().unwrap(), Refresh::Restored);
        assert!(!lock.is_displaced());
        assert!(matches!(
            OwnerLock::acquire(&path),
            Err(LockError::Held { .. })
        ));
        drop(lock);
        assert!(!path.exists());
    }

    #[test]
    fn the_holders_own_thread_stops_once_it_is_displaced() {
        let path = lock_path("thread-displaced");
        let lock = OwnerLock::acquire_refreshing(&path, Duration::from_millis(10)).unwrap();
        let taken = owned_until(&lock);
        taken.store(true, Ordering::SeqCst);
        // While its file is at the path, a holder is not asked.
        std::thread::sleep(Duration::from_millis(50));
        assert!(!lock.is_displaced());
        std::fs::remove_file(&path).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !lock
            .refresher
            .as_ref()
            .is_some_and(std::thread::JoinHandle::is_finished)
        {
            assert!(std::time::Instant::now() < deadline, "never stopped");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(lock.is_displaced());
        assert!(!path.exists(), "and never put the file back");
        drop(lock);
    }

    /// A lock file whose times cannot be set: macOS lets a file's owner
    /// make it immutable, which Linux reserves to a privileged process.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_refresh_that_cannot_set_the_times_is_counted_for_its_log() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let path = lock_path("immutable");
        let lock = OwnerLock::acquire(&path).unwrap();
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        let set_flags = |flags: libc::c_uint| {
            // SAFETY: `name` is a valid NUL-terminated path for the duration
            // of the call, which changes only the flags of the file there.
            assert_eq!(unsafe { libc::chflags(name.as_ptr(), flags) }, 0);
        };
        set_flags(libc::UF_IMMUTABLE);
        let refreshed = [lock.refresh(), lock.refresh(), lock.refresh()];
        set_flags(0);
        for refresh in refreshed {
            assert_eq!(refresh.unwrap(), Refresh::Untouchable);
        }
        assert_eq!(
            lock.shared.touch_failures.lock().unwrap().0,
            3,
            "each failure counted; the log goes at the first and at each doubling"
        );
        assert_eq!(lock.refresh().unwrap(), Refresh::Touched);
        drop(lock);
        assert!(!path.exists());
    }
}
