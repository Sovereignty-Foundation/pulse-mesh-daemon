// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Shared-memory objects made by hand, for targets that open them with the
//! ring's and the store's own constructors.
//!
//! Each target process uses one name per kind of object, unique to the
//! process, and makes and unlinks its object once per input, so two
//! fuzzing processes, or a fuzzing process and the workspace's tests, never
//! share an object. Sizes are what `fstat(2)` reports, which on macOS is
//! the size asked for rounded up to a page.

use std::ffi::CString;

/// A shared-memory name unique to this process and `tag`, at most 30 bytes
/// (macOS allows 31, the terminator included).
#[must_use]
pub fn unique_name(tag: &str) -> String {
    let name = format!("/pmfz-{tag}-{:x}", std::process::id());
    assert!(name.len() <= 30, "{name} is longer than macOS allows");
    name
}

/// A POSIX shared-memory object, made afresh under a name, sized, mapped
/// read-write and filled by the caller; dropping it unmaps it, closes it
/// and unlinks the name.
pub struct RawObject {
    cname: CString,
    fd: libc::c_int,
    ptr: *mut u8,
    len: usize,
}

impl RawObject {
    /// Make the object `name`, sized to `len` bytes and mapped whole, as
    /// large as the system made it (macOS rounds a size up to a page), or
    /// left at size zero and unmapped when `len` is zero. Whatever a run
    /// that crashed left under the name is unlinked first.
    ///
    /// # Panics
    ///
    /// When the object cannot be made, sized or mapped: the target cannot
    /// run without it.
    #[must_use]
    pub fn create(name: &str, mut len: usize) -> Self {
        let cname = CString::new(name).expect("a name without NUL");
        // SAFETY: `cname` is a valid NUL-terminated string for the call,
        // and shm_unlink touches nothing else; a missing object is fine.
        unsafe { libc::shm_unlink(cname.as_ptr()) };
        // SAFETY: as above; the descriptor is checked before use.
        let fd = unsafe {
            libc::shm_open(
                cname.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
                0o600,
            )
        };
        assert!(
            fd >= 0,
            "shm_open {name}: {}",
            std::io::Error::last_os_error()
        );
        let mut ptr = std::ptr::null_mut();
        if len > 0 {
            let off = libc::off_t::try_from(len).expect("a size that fits a file offset");
            // SAFETY: sizes the object opened above; touches no memory.
            let rc = unsafe { libc::ftruncate(fd, off) };
            assert_eq!(
                rc,
                0,
                "ftruncate {name}: {}",
                std::io::Error::last_os_error()
            );
            len = usize::try_from(fstat_size(fd)).expect("a size that fits memory");
            // SAFETY: maps `len` bytes of the object, which `fstat` just
            // reported to be that long; the result is checked before use.
            let mapped = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    fd,
                    0,
                )
            };
            assert_ne!(mapped, libc::MAP_FAILED, "mmap {name}");
            ptr = mapped.cast::<u8>();
        }
        Self {
            cname,
            fd,
            ptr,
            len,
        }
    }

    /// The object's size as `fstat(2)` reports it.
    #[must_use]
    pub fn size(&self) -> u64 {
        fstat_size(self.fd)
    }

    /// Bytes mapped, which the caller may read and write: the object's
    /// size.
    #[must_use]
    pub fn mapped(&self) -> usize {
        self.len
    }

    /// Write `bytes` at `offset`, cut short at the end of the mapping.
    pub fn write(&self, offset: usize, bytes: &[u8]) {
        let Some(room) = self.len.checked_sub(offset) else {
            return;
        };
        let n = bytes.len().min(room);
        if n == 0 {
            // Nothing to copy, and an unsized object has no mapping.
            return;
        }
        // SAFETY: `offset + n <= len` with `n > 0`, so the object is mapped
        // and the copy stays inside the live mapping of `len` bytes; the
        // source is a distinct Rust slice.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr.add(offset), n) };
    }

    /// Read `n` bytes at `offset`, cut short at the end of the mapping.
    #[must_use]
    pub fn read(&self, offset: usize, n: usize) -> Vec<u8> {
        let room = self.len.saturating_sub(offset);
        let n = n.min(room);
        let mut out = vec![0u8; n];
        if n > 0 {
            // SAFETY: `offset + n <= len`, so the copy stays inside the live
            // mapping; the destination is a distinct buffer of `n` bytes.
            unsafe { std::ptr::copy_nonoverlapping(self.ptr.add(offset), out.as_mut_ptr(), n) };
        }
        out
    }
}

impl Drop for RawObject {
    fn drop(&mut self) {
        // SAFETY: unmaps the mapping `create` made, if any, closes the
        // descriptor it opened and unlinks the name it created; nothing else
        // uses them. Mappings the code under test made of the same object
        // stay valid until that code unmaps them.
        unsafe {
            if self.len > 0 {
                libc::munmap(self.ptr.cast::<libc::c_void>(), self.len);
            }
            libc::close(self.fd);
            libc::shm_unlink(self.cname.as_ptr());
        }
    }
}

/// The size of the object behind `fd`, from `fstat(2)`.
fn fstat_size(fd: libc::c_int) -> u64 {
    // SAFETY: `libc::stat` is a plain C struct for which all zeros is a
    // valid value.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `st` is a valid, writable `stat` for the call, and `fd` is an
    // open descriptor the caller holds.
    let rc = unsafe { libc::fstat(fd, &mut st) };
    assert_eq!(rc, 0, "fstat: {}", std::io::Error::last_os_error());
    u64::try_from(st.st_size).unwrap_or(0)
}
