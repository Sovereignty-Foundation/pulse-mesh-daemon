// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `mesh-hub-runtime`: the embedded hub, tier 2.
//!
//! [`PulseHub`] is the in-process event bus the daemon wraps and any process
//! can embed: a shared-memory ring for signals, an envelope store for
//! content-addressed persistence, schema and broadcast registries for routing,
//! and a health registry for liveness. A hub name names its objects
//! ([`hub_shm_names`]).
//!
//! A hub that broadcasts an envelope stores it and writes a Data pulse naming
//! its id and store cursor; every other hub attached to the name fetches that
//! copy when it polls. The ring has one writer, the hub that created it
//! ([`PulseHub::is_writer`]), and a hub name at most one owner, the hub from
//! [`PulseHub::create_fresh`], which holds the name's [`owner::OwnerLock`]. How
//! the names change hands is ADR-0015's
//! (`decisions/0015-ring-header-layout.md`).
//!
//! The runtime and its tests descend from sovOS™, the integrated substrate,
//! adapted to pulse-canon's instruction set.
//!
//! In the book: <https://pulse-mesh.net/docs/daemon/architecture/mesh.html> and
//! <https://pulse-mesh.net/docs/reference/spec/05-store.html>.

pub mod owner;

use core_ring::{PositionRead, PulseRing, RingError};
use core_store::{EnvelopeStore, EnvelopeStoreError};
use mesh_broadcast::{BroadcastRegistry, BroadcastResult, ListenFilter};
use mesh_health::{HealthRegistry, HeartbeatConfig};
use mesh_schema::{SchemaEntry, SchemaError, SchemaRegistry};
use owner::{LockError, OwnerLock};
use pulse_canon::{HeartbeatPayload, Instruction, NodeId, Pulse, PulseEnvelope};

/// Slots in a hub's envelope store unless its [`HubConfig::store_slots`]
/// says otherwise. At 65,600 bytes a slot, the store takes a little over
/// 16 MiB of shared memory.
pub const DEFAULT_STORE_SLOTS: usize = 256;

/// How a hub that creates its ring makes its store: reusing one of the same
/// size under the name, or creating one where the name must be free.
type MakeStore = fn(&str, usize) -> Result<EnvelopeStore, EnvelopeStoreError>;

/// The envelope store of a hub that created its ring, or `None` when `slots` is
/// zero or, logged, when it cannot be made.
fn writer_store(name: &str, slots: usize, make: MakeStore) -> Option<EnvelopeStore> {
    if slots == 0 {
        tracing::info!(store = %name, "no envelope store configured; persistence disabled");
        return None;
    }
    match make(name, slots) {
        Ok(store) => Some(store),
        Err(e) => {
            tracing::warn!(store = %name, error = %e, "envelope store unavailable; persistence disabled");
            None
        }
    }
}

/// What [`open_paired_store`] found under the store name of a ring.
enum PairedStore {
    /// The store of the ring's writer.
    Store(EnvelopeStore),
    /// No store could be opened under the name, for the reason given: the
    /// ring's writer runs without one, or has not made it yet.
    Missing(EnvelopeStoreError),
    /// The ring was superseded by the time the store name was opened, so
    /// what the name held may already be a successor's store.
    Superseded,
}

/// Open the store beside `ring` at the size its header records, and vouch that
/// it is the ring's writer's: the name is opened first and the ring's mark read
/// after. An owner makes its store before its ring, and a ring's store name
/// changes hands only after the ring is marked, so a ring still unmarked after
/// the open was its writer's throughout, and so is the store. A marked ring
/// yields [`PairedStore::Superseded`].
fn open_paired_store(ring: &PulseRing) -> PairedStore {
    let name = format!("{}{HUB_STORE_SUFFIX}", ring.name());
    let opened = EnvelopeStore::open_existing(&name);
    if ring.is_superseded() {
        return PairedStore::Superseded;
    }
    match opened {
        Ok(store) => PairedStore::Store(store),
        Err(e) => PairedStore::Missing(e),
    }
}

/// The store of a hub that attached to `ring` ([`open_paired_store`]), or
/// `None`, logged when missing, until [`PulseHub::poll`] or
/// [`PulseHub::reopen`] finds one.
fn attached_store(ring: &PulseRing) -> Option<EnvelopeStore> {
    match open_paired_store(ring) {
        PairedStore::Store(store) => Some(store),
        PairedStore::Missing(e) => {
            tracing::warn!(ring = %ring.name(), error = %e, "envelope store unavailable; signalled envelopes wait until it can be opened");
            None
        }
        PairedStore::Superseded => None,
    }
}

/// A second handle on the ring `ring` maps, through a duplicate of its
/// descriptor, since the name may by now be another's ring. It neither unlinks
/// nor marks the ring when it drops.
fn same_ring(ring: &PulseRing) -> Result<PulseRing, RingError> {
    // SAFETY: dup reads only its integer argument, the descriptor `ring`
    // holds open for as long as it lives, and touches no memory of this
    // process.
    let fd = unsafe { libc::dup(ring.raw_fd()) };
    if fd < 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(RingError::Open(errno));
    }
    // The header is published, so it is checked, never formatted.
    PulseRing::from_fd(ring.name(), fd, ring.capacity(), true, false).inspect_err(|_| {
        // SAFETY: `fd` is the duplicate made above, which `from_fd` leaves
        // open and the caller's on every error, and nothing else holds.
        unsafe { libc::close(fd) };
    })
}

/// How long [`PulseHub::create_fresh`] waits for a ring another has marked to
/// leave its name before removing it itself: a dropping hub removes its names
/// well inside this, and a mark that outlasts it belongs to a hub that died or
/// stalled, which would otherwise block the name for good.
const MARKED_RING_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// Clear `name` of the ring an earlier writer left, for
/// [`PulseHub::create_fresh`], which holds the name's lock. Whoever marks a
/// ring decides the fate of its names: a ring this call marks is its to unlink,
/// a ring another marked is left to that marker until `wait` has passed, and an
/// object that is not a ring this build reads is unlinked, since nothing else
/// ever will.
fn clear_ring_name(name: &str, wait: std::time::Duration) -> Result<(), RingError> {
    let deadline = std::time::Instant::now() + wait;
    loop {
        let this_call_decides = match PulseRing::open_existing(name) {
            Ok(stale) => stale.supersede(),
            Err(RingError::Open(libc::ENOENT)) => return Ok(()),
            Err(_) => true,
        };
        let overdue = !this_call_decides && std::time::Instant::now() >= deadline;
        if this_call_decides || overdue {
            if PulseRing::unlink(name)? {
                if overdue {
                    tracing::warn!(
                        ring = %name,
                        "replaced a shared-memory ring another had marked superseded and left under its name"
                    );
                } else {
                    tracing::warn!(ring = %name, "replaced a shared-memory ring left by an earlier hub");
                }
            }
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

/// How long a hub attached without a store waits after a failed attempt to open
/// it; the first attempt is at once.
const STORE_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Prefix of every shared-memory object a hub creates: on Linux, the files
/// `/dev/shm/pms-*` that `just clean` and the MCP `mesh_list_rings` tool
/// enumerate.
pub const HUB_SHM_PREFIX: &str = "/pms-";
/// Suffix of a hub's envelope store.
pub const HUB_STORE_SUFFIX: &str = "-envelopes";
/// Longest shared-memory name accepted: macOS allows 31 bytes, and one
/// byte of margin is kept, as the multilane ring does.
pub const SHM_NAME_MAX: usize = 30;

/// The shared-memory names a hub uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubShmNames {
    /// The pulse ring: `/pms-<hub>`.
    pub ring: String,
    /// The envelope store: `/pms-<hub>-envelopes`.
    pub store: String,
}

/// The shared-memory names for `hub`: `/pms-<hub>` and `/pms-<hub>-envelopes`.
///
/// # Errors
///
/// [`RingError::InvalidName`] unless `hub` is letters, digits, `_`, `.` and
/// `-`; [`RingError::NameTooLong`] past 15 characters, where the store name
/// would exceed [`SHM_NAME_MAX`].
pub fn hub_shm_names(hub: &str) -> Result<HubShmNames, RingError> {
    let valid = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-');
    if hub.is_empty() || !hub.bytes().all(valid) {
        return Err(RingError::InvalidName);
    }
    let ring = format!("{HUB_SHM_PREFIX}{hub}");
    let store = format!("{ring}{HUB_STORE_SUFFIX}");
    if store.len() > SHM_NAME_MAX {
        return Err(RingError::NameTooLong {
            len: store.len(),
            max: SHM_NAME_MAX,
        });
    }
    Ok(HubShmNames { ring, store })
}

/// How the hub validates the pulses an application publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ValidationMode {
    /// Each pulse must be later than the last one accepted; the default. The
    /// hub's own clock is not checked ([`PulseHub::set_monotonic_nanos`]).
    #[default]
    MonotonicOnly,
    /// No validation. Hub acts as a pure message router. Development only.
    Passthrough,
}

/// Configuration for a PulseHub instance.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HubConfig {
    /// Number of ring buffer slots (default 64).
    pub ring_size: u64,
    /// Local bus validation mode.
    pub validation: ValidationMode,
    /// Slots in the envelope store of a hub that creates its ring, zero for
    /// none (default [`DEFAULT_STORE_SLOTS`]). Each takes 65,600 bytes of
    /// shared memory ([`core_store::MAX_ENTRY_SIZE`] and a 64-byte header), all
    /// reserved when the store is made on Linux, where Docker gives a container
    /// 64 MB of `/dev/shm`; a store that does not fit is logged and left out. A
    /// hub that attaches to a ring takes the store's size from its header
    /// instead.
    pub store_slots: usize,
}

impl Default for HubConfig {
    fn default() -> Self {
        HubConfig {
            ring_size: 64,
            validation: ValidationMode::MonotonicOnly,
            store_slots: DEFAULT_STORE_SLOTS,
        }
    }
}

impl HubConfig {
    /// This configuration with `ring_size` slots in the ring.
    #[must_use]
    pub fn with_ring_size(mut self, ring_size: u64) -> Self {
        self.ring_size = ring_size;
        self
    }

    /// This configuration with the given validation mode.
    #[must_use]
    pub fn with_validation(mut self, validation: ValidationMode) -> Self {
        self.validation = validation;
        self
    }

    /// This configuration with `store_slots` slots in the envelope store
    /// (zero for no store).
    #[must_use]
    pub fn with_store_slots(mut self, store_slots: usize) -> Self {
        self.store_slots = store_slots;
        self
    }
}

/// A validated pulse event delivered to subscribers.
#[derive(Debug, Clone)]
pub struct PulseEvent {
    /// Opcode decoded from the on-wire `Pulse.instruction` u16.
    pub instruction: Instruction,
    /// The pulse's `scope`.
    pub scope: u32,
    /// The producer's monotonic timestamp, in nanoseconds.
    pub monotonic_nanos: u64,
    /// The producer's chain step, for downstream replay detection.
    pub chain_step: u64,
    /// The pulse's `origin_id`.
    pub origin_id: [u8; 16],
    /// The ring position the pulse was written at, rising with each write.
    pub write_index: u64,
}

/// Subscriber callback type.
type SubscriberFn = Box<dyn FnMut(&PulseEvent) + Send>;

/// Instruction filter for subscribers.
#[derive(Debug, Clone)]
pub enum Filter {
    /// Receive all instructions.
    All,
    /// Receive only specific instructions.
    Only(Vec<Instruction>),
}

impl Filter {
    fn matches(&self, code: Instruction) -> bool {
        match self {
            Filter::All => true,
            Filter::Only(codes) => codes.contains(&code),
        }
    }
}

struct Subscriber {
    callback: SubscriberFn,
    filter: Filter,
}

/// What the hub did with one broadcast envelope: the in-process delivery, and
/// whether the store kept it for other processes. A store refusal is reported
/// here, not as an error, and does not stop delivery.
#[derive(Debug)]
#[non_exhaustive]
pub struct BroadcastOutcome {
    /// The in-process fan-out: the listeners that matched and were called.
    pub delivery: BroadcastResult,
    /// The store's verdict: `None` when the hub runs without an envelope
    /// store, `Some(Ok(cursor))` when the envelope was stored at `cursor`,
    /// and `Some(Err(e))` when the store refused it, which the hub also
    /// counts in [`PulseHub::store_failures`] and logs.
    pub stored: Option<Result<u64, EnvelopeStoreError>>,
    /// The `monotonic_nanos` the hub stamped on the envelope: the copy it
    /// stored, signalled and dispatched carries this stamp, and the caller's
    /// copy does not, so a caller that passes the envelope on (a daemon
    /// forwarding it to a peer) sets it from here.
    pub monotonic_nanos: u64,
}

impl BroadcastOutcome {
    /// Whether the store kept the envelope, `None` without a store: the
    /// daemon's `persisted`.
    #[must_use]
    pub fn persisted(&self) -> Option<bool> {
        self.stored.as_ref().map(Result::is_ok)
    }
}

/// A failure count that asks to be logged at the first failure and at each
/// doubling, so a repeating failure costs a log line per doubling.
#[derive(Debug, Default)]
struct FailureCount(u64);

impl FailureCount {
    /// Count one failure. Returns the new total when it is a power of two
    /// (1, 2, 4, ...), which marks the failures to log.
    fn record(&mut self) -> Option<u64> {
        self.add(1)
    }

    /// Count `n` failures at once. Returns the new total when the count
    /// reached or passed a power of two on the way, so a burst is logged
    /// once, as single failures are.
    fn add(&mut self, n: u64) -> Option<u64> {
        let before = self.0;
        self.0 = before.saturating_add(n);
        let crossed = self.0 > before && (before == 0 || self.0.ilog2() > before.ilog2());
        crossed.then_some(self.0)
    }
}

/// The hub: a local event bus, its subscribers, and envelope routing. Pulses
/// (128-byte control signals) go through the ring; envelopes (variable-size
/// payloads) through the broadcast registry and, across processes, the store.
///
/// The hub that created its ring ([`PulseHub::is_writer`]) removes the hub's
/// names when it drops, unless another owner has taken them: it marks the ring
/// superseded, and whoever marks a ring decides the fate of its names
/// (ADR-0015). It removes each name only while it is still its own, so one that
/// stalls past a new owner's wait leaves the new owner's names alone; only a
/// stall inside one check and its removal, a few system calls, can still remove
/// a name a new owner has just made. The tests below stage each stall. A hub
/// that attached to its ring removes nothing.
pub struct PulseHub {
    ring: PulseRing,
    subscribers: Vec<Subscriber>,
    config: HubConfig,
    last_tick: u64,
    read_cursor: u64,
    schema_registry: SchemaRegistry,
    broadcast_registry: BroadcastRegistry,
    /// The time set with [`PulseHub::set_monotonic_nanos`], or `None` for
    /// the host's monotonic clock.
    clock: Option<u64>,
    /// See [`PulseHub::is_writer`].
    writer: bool,
    /// See [`PulseHub::ring_superseded`].
    superseded: bool,
    health_registry: Option<HealthRegistry>,
    expected_hashes: std::collections::HashMap<[u8; 16], u64>,
    envelope_store: Option<EnvelopeStore>,
    /// Envelopes `envelope_store` refused; see [`PulseHub::store_failures`].
    store_failures: FailureCount,
    /// See [`PulseHub::lost_pulses`].
    lost_pulses: FailureCount,
    /// This instance's identity; see [`PulseHub::instance_id`].
    instance_id: [u8; 16],
    /// See [`PulseHub::unfetched_envelopes`].
    unfetched_envelopes: FailureCount,
    /// When a hub attached without a store may next try to open it: `None`
    /// until an attempt fails; see `retry_store`.
    store_retry_at: Option<std::time::Instant>,
    /// Failed attempts to open the store of the ring this hub attached to,
    /// counted to rate-limit their log.
    store_retry_failures: FailureCount,
    /// The name's owner lock, held by a hub from [`PulseHub::create_fresh`]:
    /// the last field, so it lets the next owner in only after everything else
    /// has gone.
    owner: Option<OwnerLock>,
}

/// A random 16-byte identity for one hub instance, never all zeros:
/// `RandomState`'s OS-seeded keys over the process id and a per-process count,
/// so instances in one process, or in a fork, differ too.
fn new_instance_id() -> [u8; 16] {
    use std::hash::BuildHasher;
    use std::sync::atomic::{AtomicU64, Ordering};
    static MADE: AtomicU64 = AtomicU64::new(0);
    let made = MADE.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let mut id = [0u8; 16];
    for (half, bytes) in (0u8..).zip(id.chunks_exact_mut(8)) {
        let hash = std::collections::hash_map::RandomState::new().hash_one((pid, made, half));
        bytes.copy_from_slice(&hash.to_le_bytes());
    }
    if id == [0u8; 16] {
        // All zeros means "no origin" in a pulse.
        id[0] = 1;
    }
    id
}

/// CLOCK_MONOTONIC on Linux and CLOCK_UPTIME_RAW on Apple platforms, the
/// clocks `pulse_wire_udp::monotonic_nanos` reads: nanosecond steps, and no
/// time counted while the machine sleeps (macOS's CLOCK_MONOTONIC has neither).
#[cfg(target_vendor = "apple")]
const HOST_MONOTONIC: libc::clockid_t = libc::CLOCK_UPTIME_RAW;
#[cfg(not(target_vendor = "apple"))]
const HOST_MONOTONIC: libc::clockid_t = libc::CLOCK_MONOTONIC;

/// The host's monotonic clock now, in nanoseconds: the clock a Pulse's
/// `monotonic_nanos` is defined on, one clock for every process on the host,
/// and the same one `pulse_wire_udp::monotonic_nanos` reads.
fn clock_monotonic_nanos() -> u64 {
    // SAFETY: `timespec` is a plain C struct of integers, for which all
    // zeros is a valid value.
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: `now` is a valid, writable `timespec` for the duration of the
    // call, and `clock_gettime` writes nothing else.
    if unsafe { libc::clock_gettime(HOST_MONOTONIC, &mut now) } != 0 {
        // Only a clock the platform lacks fails, and every platform this
        // crate builds for has this one.
        return 0;
    }
    let seconds = u64::try_from(now.tv_sec).unwrap_or(0);
    let nanos = u64::try_from(now.tv_nsec).unwrap_or(0);
    seconds.saturating_mul(1_000_000_000).saturating_add(nanos)
}

/// A read-only view of a hub's ring, what [`PulseHub::ring`] returns: the
/// reads an inspector needs, and none of the writes, so the ring's
/// single-writer rule cannot be bypassed through a hub.
#[derive(Clone, Copy)]
pub struct RingView<'a> {
    ring: &'a PulseRing,
}

impl std::fmt::Debug for RingView<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingView")
            .field("name", &self.ring.name())
            .field("cursor", &self.ring.cursor_position())
            .field("capacity", &self.ring.capacity())
            .finish()
    }
}

impl RingView<'_> {
    /// The write cursor: the position the next publish takes.
    #[must_use]
    pub fn cursor_position(&self) -> u64 {
        self.ring.cursor_position()
    }

    /// How many publishes the ring has taken.
    #[must_use]
    pub fn write_count(&self) -> u64 {
        self.ring.write_count()
    }

    /// The ring's capacity in slots.
    #[must_use]
    pub fn capacity(&self) -> u64 {
        self.ring.capacity()
    }

    /// The shared-memory name the ring was created or opened under.
    #[must_use]
    pub fn name(&self) -> &str {
        self.ring.name()
    }

    /// A consistent copy of the pulse in `slot`, or `None` when the slot is
    /// mid-write or torn; see [`PulseRing::read_slot`].
    #[must_use]
    pub fn read_slot(&self, slot: u64) -> Option<Pulse> {
        self.ring.read_slot(slot)
    }

    /// The pulse written at `position`, for a reader that walks the write
    /// positions in order; see [`PulseRing::read_position`].
    #[must_use]
    pub fn read_position(&self, position: u64) -> core_ring::PositionRead {
        self.ring.read_position(position)
    }
}

impl PulseHub {
    fn assemble(ring: PulseRing, config: HubConfig, store: Option<EnvelopeStore>) -> Self {
        // Start at the oldest pulse held, so `lost_pulses` counts only what
        // this hub missed.
        let read_cursor = ring.cursor_position().saturating_sub(ring.capacity());
        let writer = ring.is_creator();
        PulseHub {
            ring,
            subscribers: Vec::new(),
            config,
            last_tick: 0,
            read_cursor,
            schema_registry: SchemaRegistry::new(),
            broadcast_registry: BroadcastRegistry::new(),
            clock: None,
            writer,
            superseded: false,
            health_registry: None,
            expected_hashes: std::collections::HashMap::new(),
            envelope_store: store,
            store_failures: FailureCount::default(),
            lost_pulses: FailureCount::default(),
            instance_id: new_instance_id(),
            unfetched_envelopes: FailureCount::default(),
            store_retry_at: None,
            store_retry_failures: FailureCount::default(),
            owner: None,
        }
    }

    /// Create the hub `name`; if its ring exists already, attach to it
    /// instead, read-only as a hub from [`Self::open`] is. A creator makes, or
    /// reuses, a store of `config.store_slots` slots; an attacher takes the
    /// creator's store at its recorded size.
    ///
    /// # Errors
    ///
    /// [`RingError::InvalidName`] or [`RingError::NameTooLong`] for a bad name
    /// ([`hub_shm_names`]), and otherwise the errors of
    /// [`PulseRing::create_or_open`]. A store that cannot be made is logged,
    /// not an error.
    pub fn create(name: &str, config: HubConfig) -> Result<Self, RingError> {
        let names = hub_shm_names(name)?;
        let ring = PulseRing::create_or_open(&names.ring, config.ring_size)?;
        let store = if ring.is_creator() {
            writer_store(
                &names.store,
                config.store_slots,
                EnvelopeStore::create_or_open,
            )
        } else {
            attached_store(&ring)
        };
        Ok(Self::assemble(ring, config, store))
    }

    /// Create the hub `name` as its one owner, removing whatever an earlier
    /// owner left under the name.
    ///
    /// It takes the name's owner lock ([`owner::hub_lock_path`]) before it
    /// touches any shared memory, and holds it until it drops: a second owner
    /// of a live hub is refused with [`OwnerError::Owned`], having touched
    /// nothing, and the lock keeps its file at its path meanwhile
    /// ([`owner::OwnerLock::refresh`]). The old ring is marked superseded and
    /// removed first, the store replaced next and the new ring made last, so a
    /// hub that finds the new ring under the name finds the new store beside it
    /// ([`Self::reopen`]). Should a second owner take the name all the same,
    /// its lock file removed, neither removes the other's objects (see
    /// [`PulseHub`]). Only this constructor takes the lock, so it treats a ring
    /// from [`Self::create`] or [`Self::create_exclusive`] as left behind.
    /// Checked by `tests/fresh_shm.rs`.
    ///
    /// # Errors
    ///
    /// [`OwnerError::Owned`] when a live hub owns the name, with the process id
    /// its lock records; [`OwnerError::Lock`] when the lock cannot be taken
    /// otherwise; [`OwnerError::Ring`] for a bad hub name, a stale ring that
    /// cannot be removed, or the errors of [`Self::create_exclusive`]. A store
    /// that cannot be removed or made is logged, and the hub runs without one;
    /// a `config.store_slots` of zero still removes a stale store.
    pub fn create_fresh(name: &str, config: HubConfig) -> Result<Self, OwnerError> {
        let names = hub_shm_names(name)?;
        let lock = OwnerLock::acquire(&owner::hub_lock_path(name)?).map_err(|e| match e {
            LockError::Held { pid, .. } => OwnerError::Owned {
                hub: name.to_string(),
                pid,
            },
            other => OwnerError::Lock(other),
        })?;
        // Marked first, so hubs still polling the old ring reopen.
        clear_ring_name(&names.ring, MARKED_RING_WAIT)?;
        // The store before the ring, so the new ring's readers find the new
        // store.
        let store = match EnvelopeStore::unlink(&names.store) {
            Ok(removed) => {
                if removed {
                    tracing::warn!(store = %names.store, "replaced an envelope store left by an earlier hub");
                }
                writer_store(
                    &names.store,
                    config.store_slots,
                    EnvelopeStore::create_exclusive,
                )
            }
            Err(e) => {
                tracing::warn!(store = %names.store, error = %e, "envelope store unavailable; persistence disabled");
                None
            }
        };
        // A ring that cannot be created drops the store just made, which
        // unlinks its name: nothing is left under either name.
        let ring = PulseRing::create_exclusive(&names.ring, config.ring_size)?;
        // A removed lock file is put back only while this hub's ring is
        // unmarked, that is, while it has not been displaced.
        match same_ring(&ring) {
            Ok(watch) => lock.set_ownership_check(move || !watch.is_superseded()),
            Err(e) => tracing::warn!(
                ring = %names.ring,
                error = %e,
                "the owner lock cannot watch the ring; a removed lock file will be put back even \
                 if another owner has taken the name"
            ),
        }
        let mut hub = Self::assemble(ring, config, store);
        hub.owner = Some(lock);
        Ok(hub)
    }

    /// Create the hub `name`, failing if its ring exists.
    ///
    /// # Errors
    ///
    /// [`RingError::InvalidName`] or [`RingError::NameTooLong`] for a bad name,
    /// and otherwise the errors of [`PulseRing::create_exclusive`]
    /// ([`RingError::Open`] with `EEXIST` when the ring exists).
    pub fn create_exclusive(name: &str, config: HubConfig) -> Result<Self, RingError> {
        let names = hub_shm_names(name)?;
        let ring = PulseRing::create_exclusive(&names.ring, config.ring_size)?;
        let store = writer_store(
            &names.store,
            config.store_slots,
            EnvelopeStore::create_or_open,
        );
        Ok(Self::assemble(ring, config, store))
    }

    /// Attach to the existing hub `name`, read-only on its ring
    /// ([`Self::is_writer`]): it polls, fetches the envelopes other hubs
    /// signal, and dispatches to its own subscribers and listeners. It takes
    /// the ring's writer's store at the size the store's header records, and
    /// only while the ring is still that writer's; a store it cannot open yet
    /// is opened by a later [`Self::poll`].
    ///
    /// # Errors
    ///
    /// [`RingError::InvalidName`] or [`RingError::NameTooLong`] for a bad name,
    /// and otherwise the errors of [`PulseRing::open`]: most often
    /// [`RingError::Open`] with `ENOENT` while no hub has created the ring, and
    /// [`RingError::LayoutMismatch`] when its size is not `config.ring_size`.
    pub fn open(name: &str, config: HubConfig) -> Result<Self, RingError> {
        let names = hub_shm_names(name)?;
        let ring = PulseRing::open(&names.ring, config.ring_size)?;
        let store = attached_store(&ring);
        Ok(Self::assemble(ring, config, store))
    }

    /// Validate `pulse` under the hub's [`ValidationMode`] and write it into
    /// the ring; an all-zero `origin_id` is written as this hub's
    /// [`Self::instance_id`].
    ///
    /// # Errors
    ///
    /// [`HubError::ReadOnly`] from a hub that did not create its ring, with
    /// nothing written; [`HubError::TemporalViolation`] under
    /// [`ValidationMode::MonotonicOnly`] when the pulse is not later than the
    /// last one accepted.
    pub fn publish(&mut self, pulse: &Pulse) -> Result<u64, HubError> {
        self.ensure_writer()?;
        self.validate_local(pulse)?;
        if pulse.origin_id != [0u8; 16] {
            return Ok(self.ring.publish(pulse));
        }
        let mut own = *pulse;
        own.origin_id = self.instance_id;
        Ok(self.ring.publish(&own))
    }

    /// Register a subscriber that receives all pulse events.
    pub fn subscribe<F>(&mut self, callback: F)
    where
        F: FnMut(&PulseEvent) + Send + 'static,
    {
        self.subscribers.push(Subscriber {
            callback: Box::new(callback),
            filter: Filter::All,
        });
    }

    /// Register a subscriber with an instruction filter.
    pub fn subscribe_filtered<F>(&mut self, codes: &[Instruction], callback: F)
    where
        F: FnMut(&PulseEvent) + Send + 'static,
    {
        self.subscribers.push(Subscriber {
            callback: Box::new(callback),
            filter: Filter::Only(codes.to_vec()),
        });
    }

    /// Dispatch the ring's new pulses, in write order and each once, to the
    /// subscribers whose filter matches, and return how many were dispatched.
    ///
    /// A heartbeat also feeds the health registry, if enabled. A Data pulse
    /// another hub wrote that names an envelope delivers it to the envelope
    /// listeners: the copy at the store cursor the pulse names, if it is still
    /// there with the pulse's id (the cursor says which copy, since equal
    /// content shares an id); one that cannot be fetched is counted in
    /// [`Self::unfetched_envelopes`]. Pulses the writer overwrote before this
    /// poll reached them are counted in [`Self::lost_pulses`], never
    /// dispatched.
    ///
    /// A ring whose writer has left it is marked superseded: the first poll
    /// that finds the mark dispatches what the ring still held and reports it
    /// through [`Self::ring_superseded`], once. The hub follows the new ring
    /// only when the application calls [`Self::reopen`].
    pub fn poll(&mut self) -> u64 {
        // The mark before the cursor: a writer is marked only after its last
        // publish, so a marked ring's cursor is final.
        let superseded = self.ring.is_superseded();
        let head = self.ring.cursor_position();
        let mut dispatched = 0;

        while self.read_cursor < head {
            let position = self.read_cursor;
            let pulse = match self.ring.read_position(position) {
                PositionRead::Pulse(pulse) => pulse,
                PositionRead::Lost { next } => {
                    self.count_lost(next - position);
                    self.read_cursor = next;
                    continue;
                }
                // Only when the ring was re-created under this name since
                // `head` was loaded: nothing below `head` is left to read.
                PositionRead::NotWritten => break,
            };
            self.read_cursor = position + 1;
            let code = pulse.instruction_code();
            if code == Instruction::Null {
                continue;
            }
            if code == Instruction::Heartbeat {
                if let Some(payload) = pulse.heartbeat_payload() {
                    self.process_heartbeat(&pulse.origin_id, pulse.monotonic_nanos, &payload);
                }
            }
            if code == Instruction::Data {
                self.deliver_signalled_envelope(&pulse);
            }

            let event = PulseEvent {
                instruction: code,
                scope: pulse.scope,
                monotonic_nanos: pulse.monotonic_nanos,
                chain_step: pulse.chain_step,
                origin_id: pulse.origin_id,
                write_index: position,
            };

            for sub in &mut self.subscribers {
                if sub.filter.matches(code) {
                    (sub.callback)(&event);
                }
            }

            dispatched += 1;
        }

        if superseded && !self.superseded {
            self.superseded = true;
            if self.writer {
                // Its own ring, which this hub marks only as it drops.
                tracing::error!(
                    ring = %self.ring.name(),
                    "another owner has marked this hub's ring and taken its name: hubs attached \
                     by name no longer read what this hub publishes, and it should be dropped"
                );
            } else {
                tracing::warn!(
                    ring = %self.ring.name(),
                    "the ring's writer has left it; reopen the hub to follow the ring now under its name"
                );
            }
        }
        dispatched
    }

    /// Whether [`Self::poll`] has found this hub's ring superseded, every pulse
    /// it held dispatched; `true` until [`Self::reopen`]. A writer killed
    /// outright cannot mark its ring, so its readers learn when the next owner
    /// replaces it.
    #[must_use]
    pub fn ring_superseded(&self) -> bool {
        self.superseded
    }

    /// Whether another owner has taken this hub's name: the hub writes its
    /// ring, and something else has marked it, as a new owner
    /// ([`Self::create_fresh`]) does before replacing it. Hubs attached by name
    /// then follow the new owner, and this hub should be dropped. One atomic
    /// load, no poll; `false` on a hub that attached to its ring.
    #[must_use]
    pub fn is_displaced(&self) -> bool {
        self.writer && self.ring.is_superseded()
    }

    /// Attach to the ring and store the hub's name holds now, in place of a
    /// superseded ring ([`Self::ring_superseded`]), keeping the subscribers,
    /// listeners, schemas, health registry and counters. The hub then reads the
    /// new ring from its oldest pulse, read-only, with the new writer's store,
    /// paired as [`Self::open`] pairs one.
    ///
    /// Returns `Ok(false)`, to be called again later, while there is nothing to
    /// attach to: the ring is not superseded, the name still holds the
    /// superseded ring, or the new ring was superseded meanwhile; and always on
    /// the ring's writer, which should be dropped instead.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::open`], the hub left on its superseded ring: most
    /// often [`RingError::Open`] with `ENOENT` while no ring is under the name.
    pub fn reopen(&mut self) -> Result<bool, RingError> {
        if !self.superseded || self.writer {
            return Ok(false);
        }
        let ring_name = self.ring.name().to_string();
        let ring = PulseRing::open(&ring_name, self.config.ring_size)?;
        if ring.is_superseded() {
            return Ok(false);
        }
        let store = match open_paired_store(&ring) {
            PairedStore::Store(store) => Some(store),
            PairedStore::Missing(e) => {
                tracing::warn!(ring = %ring_name, error = %e, "reopened without an envelope store; signalled envelopes wait until it can be opened");
                None
            }
            PairedStore::Superseded => return Ok(false),
        };
        self.read_cursor = ring.cursor_position().saturating_sub(ring.capacity());
        self.ring = ring;
        self.envelope_store = store;
        self.store_retry_at = None;
        self.superseded = false;
        tracing::info!(ring = %ring_name, "reopened the hub on the ring now under its name");
        Ok(true)
    }

    /// How many pulses the ring overwrote before [`Self::poll`] read them,
    /// since the hub was created or opened; logged at the first loss and at
    /// each doubling.
    #[must_use]
    pub fn lost_pulses(&self) -> u64 {
        self.lost_pulses.0
    }

    /// Count `n` pulses the ring overwrote before `poll` read them.
    fn count_lost(&mut self, n: u64) {
        if let Some(lost) = self.lost_pulses.add(n) {
            tracing::warn!(
                ring = %self.ring.name(),
                lost,
                "pulses overwritten before the hub polled them"
            );
        }
    }

    /// Dispatch the envelope a Data pulse names, as the sovOS hub runtime did
    /// (see [`Self::poll`]); a pulse this hub wrote delivers nothing, its
    /// envelope dispatched when broadcast.
    fn deliver_signalled_envelope(&mut self, pulse: &Pulse) {
        let Some(id) = pulse.envelope_id() else {
            return;
        };
        if pulse.origin_id == self.instance_id {
            return;
        }
        let cursor = pulse.store_cursor();
        if cursor.is_some() && self.envelope_store.is_none() {
            // The writer signals a store cursor only for an envelope its
            // store kept, so it has a store this hub has not opened.
            self.retry_store();
        }
        let fetched = match (self.envelope_store.as_ref(), cursor) {
            (Some(store), Some(cursor)) => store.fetch_at(cursor, &id),
            _ => None,
        };
        match fetched {
            Some(envelope) => {
                // The listeners' Instruction and Scope filters match on the
                // Pulse that signalled the envelope; an envelope dispatched
                // where it was broadcast has no such Pulse and passes None.
                self.broadcast_registry.dispatch(
                    &envelope,
                    Some(pulse.instruction_code()),
                    Some(pulse.scope),
                );
            }
            None => {
                if let Some(unfetched) = self.unfetched_envelopes.record() {
                    tracing::warn!(
                        envelope = %id,
                        cursor = ?cursor,
                        unfetched,
                        "signalled envelope not in the store at its cursor; skipped"
                    );
                }
            }
        }
    }

    /// Open the store of the ring this hub attached to, paired as in
    /// [`open_paired_store`], at most once every [`STORE_RETRY_INTERVAL`]; the
    /// ring's writer never needs to.
    fn retry_store(&mut self) {
        if self.writer {
            return;
        }
        let now = std::time::Instant::now();
        if self.store_retry_at.is_some_and(|at| now < at) {
            return;
        }
        match open_paired_store(&self.ring) {
            PairedStore::Store(store) => {
                tracing::info!(store = %store.name(), "opened the envelope store its writer made after this hub attached");
                self.envelope_store = Some(store);
                self.store_retry_at = None;
            }
            PairedStore::Missing(e) => {
                self.store_retry_at = Some(now + STORE_RETRY_INTERVAL);
                if let Some(failures) = self.store_retry_failures.record() {
                    tracing::warn!(
                        ring = %self.ring.name(),
                        error = %e,
                        failures,
                        "a signal names a store cursor, and the ring's envelope store cannot be opened"
                    );
                }
            }
            // `poll` reports the mark; `reopen` pairs the next ring with
            // its store.
            PairedStore::Superseded => self.store_retry_at = Some(now + STORE_RETRY_INTERVAL),
        }
    }

    /// This hub instance's random identity, its own on every handle of a hub
    /// name: the `origin_id` of its envelope signals and of the pulses it
    /// publishes without one, so its [`Self::poll`] skips its own signals.
    #[must_use]
    pub fn instance_id(&self) -> [u8; 16] {
        self.instance_id
    }

    /// Whether this hub created its ring and so is its one writer: one from
    /// [`Self::create_fresh`], [`Self::create_exclusive`], or [`Self::create`]
    /// on a free name. Any other hub refuses every write to the ring with
    /// [`HubError::ReadOnly`]; its process publishes by sending to the daemon.
    #[must_use]
    pub fn is_writer(&self) -> bool {
        self.writer
    }

    /// `Ok` on the hub that writes its ring, [`HubError::ReadOnly`] on any
    /// other: two writers racing for the ring's cursor would overwrite each
    /// other's pulses.
    fn ensure_writer(&self) -> Result<(), HubError> {
        if self.writer {
            Ok(())
        } else {
            Err(HubError::ReadOnly)
        }
    }

    /// How many envelope signals from other hubs [`Self::poll`] read without
    /// the store returning their envelope: overwritten, never stored, failing
    /// verification, naming no cursor, or no store. Each is still dispatched as
    /// a pulse; logged at the first and at each doubling.
    #[must_use]
    pub fn unfetched_envelopes(&self) -> u64 {
        self.unfetched_envelopes.0
    }

    fn process_heartbeat(
        &mut self,
        origin_id: &[u8; 16],
        monotonic_nanos: u64,
        payload: &HeartbeatPayload,
    ) {
        let node_id = NodeId::from_bytes(*origin_id);

        if let Some(ref mut registry) = self.health_registry {
            registry.heartbeat(&node_id, monotonic_nanos);
            // Record what the node reported: its schema version, which is
            // the catalog hash sovOS recorded with `set_catalog`, and its
            // stage count.
            if let Some(health) = registry.get_mut(&node_id) {
                health.set_schema(payload.schema_version, u32::from(payload.stage_count));
            }
        }

        // Drift: the reported catalog hash against the expected one.
        if let Some(&expected) = self.expected_hashes.get(origin_id) {
            if expected != payload.schema_version {
                let node_hex: String = origin_id.iter().map(|b| format!("{:02x}", b)).collect();
                tracing::warn!(
                    target: "mesh_hub_runtime::drift",
                    node = %node_hex,
                    expected = format!("{:016x}", expected),
                    got = format!("{:016x}", payload.schema_version),
                    "schema_version mismatch (drift)"
                );
                if let Some(ref mut registry) = self.health_registry {
                    if let Some(health) = registry.get_mut(&node_id) {
                        health.record_drift();
                    }
                }
            }
        }
    }

    /// Set expected catalog hashes for drift detection. Typically built
    /// once at startup from the registered service catalogue.
    pub fn set_expected_hashes(&mut self, hashes: std::collections::HashMap<[u8; 16], u64>) {
        self.expected_hashes = hashes;
    }

    /// Number of registered subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }

    /// The hub's validation mode.
    pub fn validation_mode(&self) -> ValidationMode {
        self.config.validation
    }

    /// A read-only view of the hub's ring ([`RingView`]).
    pub fn ring(&self) -> RingView<'_> {
        RingView { ring: &self.ring }
    }

    /// Enable heartbeat tracking. Heartbeat pulses read during `poll()`
    /// will automatically update the registry.
    pub fn enable_health(&mut self, config: HeartbeatConfig) {
        self.health_registry = Some(HealthRegistry::new(config));
    }

    /// Register a node for health tracking.
    pub fn register_node(&mut self, node_id: NodeId) {
        if let Some(ref mut reg) = self.health_registry {
            reg.register(node_id);
        }
    }

    /// Run one health tick — increments miss counters for nodes that
    /// haven't heartbeated since the last tick. Returns escalation events.
    pub fn health_tick(&mut self) -> Vec<(NodeId, mesh_health::NodeState)> {
        if let Some(ref mut reg) = self.health_registry {
            reg.tick()
        } else {
            Vec::new()
        }
    }

    /// Access the health registry (read-only).
    pub fn health_registry(&self) -> Option<&HealthRegistry> {
        self.health_registry.as_ref()
    }

    /// Register an envelope schema.
    ///
    /// # Errors
    ///
    /// [`HubError::Schema`] with the error of [`SchemaRegistry::register`].
    pub fn register_schema(&mut self, entry: SchemaEntry) -> Result<(), HubError> {
        self.schema_registry
            .register(entry)
            .map_err(HubError::Schema)
    }

    /// Get a schema by type ID.
    pub fn get_schema(&self, type_id: u16) -> Option<&SchemaEntry> {
        self.schema_registry.get(type_id)
    }

    /// Get a schema by name.
    pub fn get_schema_by_name(&self, name: &str) -> Option<&SchemaEntry> {
        self.schema_registry.get_by_name(name)
    }

    /// Add a producer to a registered schema.
    ///
    /// # Errors
    ///
    /// [`HubError::Schema`] with the error of [`SchemaRegistry::add_producer`].
    pub fn add_producer(&mut self, type_id: u16, node: NodeId) -> Result<(), HubError> {
        self.schema_registry
            .add_producer(type_id, node)
            .map_err(HubError::Schema)
    }

    /// Add a consumer to a registered schema.
    ///
    /// # Errors
    ///
    /// [`HubError::Schema`] with the error of [`SchemaRegistry::add_consumer`].
    pub fn add_consumer(&mut self, type_id: u16, node: NodeId) -> Result<(), HubError> {
        self.schema_registry
            .add_consumer(type_id, node)
            .map_err(HubError::Schema)
    }

    /// Register the check a [`mesh_schema::ValidationMode::Custom`] schema
    /// runs on every envelope of its type that its producer list admits.
    ///
    /// # Errors
    ///
    /// [`HubError::Schema`] with the error of
    /// [`SchemaRegistry::register_validator`].
    pub fn register_validator<F>(&mut self, type_id: u16, validator: F) -> Result<(), HubError>
    where
        F: Fn(&PulseEnvelope, &NodeId) -> Result<(), SchemaError> + Send + Sync + 'static,
    {
        self.schema_registry
            .register_validator(type_id, validator)
            .map_err(HubError::Schema)
    }

    /// Register a listener for envelopes matching the filter.
    /// Returns a listener ID that can be used to unregister.
    pub fn listen<F>(&mut self, node_id: NodeId, filter: ListenFilter, callback: F) -> u64
    where
        F: FnMut(&PulseEnvelope) + Send + 'static,
    {
        self.broadcast_registry.listen(node_id, filter, callback)
    }

    /// Unregister a listener by ID.
    pub fn unlisten(&mut self, listener_id: u64) -> bool {
        self.broadcast_registry.unlisten(listener_id)
    }

    /// Unregister all listeners for a node.
    pub fn unlisten_node(&mut self, node_id: &NodeId) {
        self.broadcast_registry.unlisten_node(node_id)
    }

    /// Number of registered envelope listeners.
    pub fn listener_count(&self) -> usize {
        self.broadcast_registry.len()
    }

    /// Drive the hub's clock from the application: from now on it stamps `tick`
    /// on the envelope signals it writes and the envelopes it routes, instead
    /// of reading the host's monotonic clock. Set it before the hub writes anything, or
    /// keep it on that clock's scale, or the times in the ring step back.
    /// It is separate from [`ValidationMode::MonotonicOnly`], which checks only
    /// the pulses [`Self::publish`] takes.
    pub fn set_monotonic_nanos(&mut self, tick: u64) {
        self.clock = Some(tick);
    }

    /// The time the hub stamps now: the value last set with
    /// [`Self::set_monotonic_nanos`], or else a reading of the host's monotonic clock in
    /// nanoseconds, which never decreases.
    #[must_use]
    pub fn monotonic_nanos(&self) -> u64 {
        self.clock.unwrap_or_else(clock_monotonic_nanos)
    }

    /// Route an envelope: every envelope is broadcast, as
    /// [`Self::broadcast_envelope`] does.
    ///
    /// # Errors
    ///
    /// As [`Self::broadcast_envelope`].
    pub fn route_envelope(
        &mut self,
        mut envelope: PulseEnvelope,
        origin: &NodeId,
    ) -> Result<BroadcastOutcome, HubError> {
        self.ensure_writer()?;

        self.schema_registry
            .validate(&envelope, origin)
            .map_err(HubError::Schema)?;

        envelope.monotonic_nanos = self.monotonic_nanos();

        Ok(self.broadcast_envelope_internal(&envelope))
    }

    /// Broadcast an envelope stamped with the hub's clock: store it, signal it
    /// on the ring for the other hubs attached to the name (which deliver it
    /// when they poll), and call every matching listener in this process,
    /// whatever the store said. A store refusal is reported in the
    /// [`BroadcastOutcome`] and counted in [`Self::store_failures`], and is not
    /// signalled.
    ///
    /// # Errors
    ///
    /// [`HubError::ReadOnly`] from a hub that did not create its ring, and
    /// [`HubError::Schema`] when the schema registry refuses the envelope, in
    /// either case with nothing stored, signalled or dispatched.
    pub fn broadcast_envelope(
        &mut self,
        mut envelope: PulseEnvelope,
        origin: &NodeId,
    ) -> Result<BroadcastOutcome, HubError> {
        self.ensure_writer()?;
        self.schema_registry
            .validate(&envelope, origin)
            .map_err(HubError::Schema)?;

        envelope.monotonic_nanos = self.monotonic_nanos();

        Ok(self.broadcast_envelope_internal(&envelope))
    }

    /// How many envelopes the hub's store has refused, too large for an entry
    /// ([`core_store::MAX_ENTRY_SIZE`]) or finding every slot it tried held;
    /// each was still delivered in this process.
    #[must_use]
    pub fn store_failures(&self) -> u64 {
        self.store_failures.0
    }

    /// Slots in the hub's envelope store, or `None` while it has none: a
    /// writer's configured store, or an attached hub's writer's store once
    /// opened.
    #[must_use]
    pub fn store_slots(&self) -> Option<usize> {
        self.envelope_store.as_ref().map(EnvelopeStore::capacity)
    }

    /// Store, signal and dispatch an envelope already validated and stamped.
    fn broadcast_envelope_internal(&mut self, envelope: &PulseEnvelope) -> BroadcastOutcome {
        let stored = self
            .envelope_store
            .as_ref()
            .map(|store| store.store(envelope));
        match stored {
            Some(Ok(cursor)) => {
                // A Data pulse naming the envelope and the cursor of this copy
                // (sovOS used Execute), with this hub's identity so its own
                // poll skips it.
                let mut signal = Pulse::zeroed();
                signal.set_store_cursor(cursor);
                signal.monotonic_nanos = self.monotonic_nanos();
                signal.origin_id = self.instance_id;
                signal.set_envelope_id(&envelope.id());
                let _ = self.ring.publish(&signal);
            }
            Some(Err(ref error)) => {
                if let Some(failures) = self.store_failures.record() {
                    let store = self.envelope_store.as_ref().map_or("", EnvelopeStore::name);
                    tracing::warn!(
                        store = %store,
                        failures,
                        error = %error,
                        "envelope not persisted"
                    );
                }
            }
            None => {}
        }

        BroadcastOutcome {
            delivery: self.broadcast_registry.dispatch(envelope, None, None),
            stored,
            monotonic_nanos: envelope.monotonic_nanos,
        }
    }

    /// Dispatch an envelope to this process's matching listeners only, never
    /// stored or signalled, so any hub can; `true` when a listener received it.
    /// `_dest` is ignored.
    ///
    /// # Errors
    ///
    /// [`HubError::Schema`] when the schema registry refuses the envelope.
    pub fn send_envelope(
        &mut self,
        mut envelope: PulseEnvelope,
        origin: &NodeId,
        _dest: &NodeId,
    ) -> Result<bool, HubError> {
        self.schema_registry
            .validate(&envelope, origin)
            .map_err(HubError::Schema)?;

        envelope.monotonic_nanos = self.monotonic_nanos();

        let result = self.broadcast_registry.dispatch(&envelope, None, None);

        Ok(result.delivered > 0)
    }

    fn validate_local(&mut self, pulse: &Pulse) -> Result<(), HubError> {
        match self.config.validation {
            ValidationMode::Passthrough => Ok(()),
            ValidationMode::MonotonicOnly => {
                if pulse.monotonic_nanos <= self.last_tick && self.last_tick > 0 {
                    return Err(HubError::TemporalViolation {
                        pulse_tick: pulse.monotonic_nanos,
                        last_tick: self.last_tick,
                    });
                }
                // SIG-T05, the temporal invariant sovOS's
                // `validate_temporal_invariant` names, and nothing else: chain
                // steps and the instructions a type admits are the
                // application's rules.
                self.last_tick = pulse.monotonic_nanos;
                Ok(())
            }
        }
    }
}

impl Drop for PulseHub {
    fn drop(&mut self) {
        self.release_names(|_| {});
    }
}

/// The points in [`PulseHub::release_names`] where a hub that stalls lets a
/// new owner of its name in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReleaseStep {
    /// The hub has marked its ring and removed nothing yet.
    Marked,
    /// The hub has let its store go, and its store's name with it where the
    /// name still held the store.
    StoreReleased,
}

/// What a hub that marked its own ring finds under the ring's name as it
/// removes its names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnderRingName {
    /// A ring marked superseded: the hub's own, or one whose marker is
    /// removing its names. The hub's names are still its to remove.
    Marked,
    /// Nothing.
    Gone,
    /// A ring not marked, or an object that is not a ring this build reads
    /// (one being made, say): a new owner's, made after the name was
    /// cleared, and so is the store's name by then.
    Taken,
    /// The name could not be looked at for another reason, such as a
    /// process out of descriptors. The hub goes on as it did before it
    /// looked, as if its ring were still there.
    Unknown,
}

/// Look at what the ring's name `name` holds, for a hub that marked its own
/// ring and is removing its names.
fn under_ring_name(name: &str) -> UnderRingName {
    match PulseRing::open_existing(name) {
        Ok(ring) if ring.is_superseded() => UnderRingName::Marked,
        Ok(_) => UnderRingName::Taken,
        Err(RingError::Open(libc::ENOENT)) => UnderRingName::Gone,
        Err(RingError::LayoutMismatch { .. } | RingError::RegionTooSmall { .. }) => {
            UnderRingName::Taken
        }
        Err(_) => UnderRingName::Unknown,
    }
}

impl PulseHub {
    /// What the hub's drop does, once, for a hub that created its ring (see
    /// [`PulseHub`]). `pause` runs at each [`ReleaseStep`] so the tests can
    /// stand a stall there; the drop passes one that does nothing.
    fn release_names(&mut self, mut pause: impl FnMut(ReleaseStep)) {
        if !std::mem::take(&mut self.writer) {
            return;
        }
        if !self.ring.supersede() {
            // Another's mark: a new owner's, whose names these are now.
            if let Some(store) = self.envelope_store.as_mut() {
                store.disown();
            }
            tracing::warn!(
                ring = %self.ring.name(),
                "another owner has taken this hub's name; its names are left to that owner"
            );
            return;
        }
        // This hub's mark: a new owner waits for the ring's name to go
        // (`clear_ring_name`), so both names are still this hub's, the store's
        // to go first.
        pause(ReleaseStep::Marked);
        // Past the wait, a new owner's ring under the name means its store is
        // beside it, made first: leave both. Otherwise the store's drop unlinks
        // its name only while its unlink token comes back through it.
        if under_ring_name(self.ring.name()) == UnderRingName::Taken {
            if let Some(store) = self.envelope_store.as_mut() {
                store.disown();
            }
            tracing::warn!(
                ring = %self.ring.name(),
                "a new owner took this hub's name while it was dropping; its names are left to that owner"
            );
            return;
        }
        drop(self.envelope_store.take());
        pause(ReleaseStep::StoreReleased);
        // The ring's name goes only while a marked ring is under it: after a
        // stall past the wait it may be the new owner's unmarked ring.
        match under_ring_name(self.ring.name()) {
            UnderRingName::Marked | UnderRingName::Unknown => {
                if let Err(error) = PulseRing::unlink(self.ring.name()) {
                    tracing::warn!(ring = %self.ring.name(), %error, "the ring's name could not be removed");
                }
            }
            UnderRingName::Gone => {}
            UnderRingName::Taken => tracing::warn!(
                ring = %self.ring.name(),
                "a new owner took this hub's ring name while it was dropping; the name is left to that owner"
            ),
        }
    }
}

/// Errors raised by [`PulseHub`] operations.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum HubError {
    /// A published pulse was not later than the last one accepted, the SIG-T05
    /// invariant: clock skew or a replay. Nothing was written.
    TemporalViolation {
        /// The offending pulse's `monotonic_nanos` value.
        pulse_tick: u64,
        /// The previously-accepted highest `monotonic_nanos` value.
        last_tick: u64,
    },
    /// The schema registry refused the envelope.
    Schema(SchemaError),
    /// This hub did not create its ring, whose one writer is its creator;
    /// nothing was written. Publish by sending to the daemon instead.
    ReadOnly,
}

impl std::fmt::Display for HubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TemporalViolation {
                pulse_tick,
                last_tick,
            } => {
                write!(
                    f,
                    "temporal violation: tick {} <= last {}",
                    pulse_tick, last_tick
                )
            }
            Self::Schema(e) => write!(f, "schema error: {}", e),
            Self::ReadOnly => f.write_str(
                "read-only hub: only the hub that created the ring publishes into it; \
                 send to the daemon over the port protocol instead",
            ),
        }
    }
}

impl From<SchemaError> for HubError {
    fn from(e: SchemaError) -> Self {
        HubError::Schema(e)
    }
}

impl std::error::Error for HubError {}

/// Why [`PulseHub::create_fresh`] could not make a hub its name's owner.
#[derive(Debug)]
#[non_exhaustive]
pub enum OwnerError {
    /// A live hub owns the name; nothing was removed or created.
    Owned {
        /// The hub name.
        hub: String,
        /// The process id the owner recorded in its lock file, when it
        /// could be read.
        pid: Option<u32>,
    },
    /// The name's lock file could not be taken for a reason other than a
    /// live owner (see [`LockError`]); nothing was removed or created.
    Lock(LockError),
    /// The hub name is invalid, or the hub's ring could not be removed or
    /// created.
    Ring(RingError),
}

impl std::fmt::Display for OwnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Owned { hub, pid } => {
                write!(f, "hub '{hub}' already has an owner")?;
                if let Some(pid) = pid {
                    write!(f, ", process {pid}")?;
                }
                f.write_str(
                    "; a second owner would remove its shared memory, so this one stops \
                     without touching it",
                )
            }
            Self::Lock(e) => write!(f, "the hub's owner lock could not be taken: {e}"),
            Self::Ring(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for OwnerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Lock(e) => Some(e),
            Self::Ring(e) => Some(e),
            Self::Owned { .. } => None,
        }
    }
}

impl From<RingError> for OwnerError {
    fn from(e: RingError) -> Self {
        OwnerError::Ring(e)
    }
}

// Tests vendored from sovOS `a_mesh/core/`, adapted to pulse-canon.
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    /// Slots in the store of a hub a test creates: the default's 16 MiB per
    /// parallel test does not fit Docker's 64 MB `/dev/shm`. Only
    /// `create_hub_default_config` makes a default store.
    const TEST_STORE_SLOTS: usize = 16;

    /// A hub name no other test can collide with: the pid keeps runs apart, the
    /// counter parallel tests.
    fn unique_name() -> String {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        format!(
            "ph{:x}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn make_pulse(tick: u64, code: Instruction) -> Pulse {
        let mut p = Pulse::zeroed();
        p.monotonic_nanos = tick;
        p.instruction = code as u16;
        p.scope = 1;
        p
    }

    /// A Data pulse carrying `step` in its chain step, to tell pulses apart.
    fn marked_pulse(step: u64) -> Pulse {
        let mut p = make_pulse(step + 1, Instruction::Data);
        p.chain_step = step;
        p
    }

    /// Subscribe to every pulse, recording each event's write index and
    /// chain step.
    fn record_events(hub: &mut PulseHub) -> Arc<Mutex<Vec<(u64, u64)>>> {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        hub.subscribe(move |event| {
            sink.lock()
                .unwrap()
                .push((event.write_index, event.chain_step));
        });
        seen
    }

    /// `(index, index)` for each index in `range`: pulses dispatched each
    /// under its own write index.
    fn under_own_index(range: std::ops::Range<u64>) -> Vec<(u64, u64)> {
        range.map(|i| (i, i)).collect()
    }

    fn small_ring() -> HubConfig {
        HubConfig {
            ring_size: 8,
            validation: ValidationMode::Passthrough,
            store_slots: TEST_STORE_SLOTS,
        }
    }

    #[test]
    fn hub_shm_names_are_prefixed() {
        let names = hub_shm_names("default_hub").unwrap();
        assert_eq!(names.ring, "/pms-default_hub");
        assert_eq!(names.store, "/pms-default_hub-envelopes");
        assert!(names.store.len() <= SHM_NAME_MAX);
    }

    #[test]
    fn hub_shm_names_reject_long_or_odd_names() {
        assert!(matches!(hub_shm_names(""), Err(RingError::InvalidName)));
        assert!(matches!(hub_shm_names("a/b"), Err(RingError::InvalidName)));
        assert!(matches!(
            hub_shm_names("with space"),
            Err(RingError::InvalidName)
        ));
        assert!(hub_shm_names("fifteen-chars-x").is_ok());
        assert!(matches!(
            hub_shm_names("sixteen-chars-xx"),
            Err(RingError::NameTooLong { len: 31, max: 30 })
        ));
    }

    #[test]
    fn create_hub_default_config() {
        let name = unique_name();
        let hub = PulseHub::create(&name, HubConfig::default()).unwrap();
        assert_eq!(hub.subscriber_count(), 0);
        assert_eq!(hub.validation_mode(), ValidationMode::MonotonicOnly);
        assert_eq!(hub.store_slots(), Some(DEFAULT_STORE_SLOTS));
    }

    #[test]
    fn publish_and_poll() {
        let name = unique_name();
        let mut hub = PulseHub::create(
            &name,
            HubConfig {
                ring_size: 8,
                validation: ValidationMode::Passthrough,
                store_slots: TEST_STORE_SLOTS,
            },
        )
        .unwrap();

        let received = Arc::new(AtomicU64::new(0));
        let r = received.clone();
        hub.subscribe(move |_event| {
            r.fetch_add(1, Ordering::SeqCst);
        });

        let p = make_pulse(100, Instruction::Data);
        hub.publish(&p).unwrap();
        hub.publish(&make_pulse(200, Instruction::Heartbeat))
            .unwrap();

        let dispatched = hub.poll();
        assert_eq!(dispatched, 2);
        assert_eq!(received.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn subscribe_filtered() {
        let name = unique_name();
        let mut hub = PulseHub::create(
            &name,
            HubConfig {
                ring_size: 8,
                validation: ValidationMode::Passthrough,
                store_slots: TEST_STORE_SLOTS,
            },
        )
        .unwrap();

        let write_count = Arc::new(AtomicU64::new(0));
        let w = write_count.clone();
        hub.subscribe_filtered(&[Instruction::Data], move |_event| {
            w.fetch_add(1, Ordering::SeqCst);
        });

        let all_count = Arc::new(AtomicU64::new(0));
        let a = all_count.clone();
        hub.subscribe(move |_event| {
            a.fetch_add(1, Ordering::SeqCst);
        });

        hub.publish(&make_pulse(100, Instruction::Data)).unwrap();
        hub.publish(&make_pulse(200, Instruction::Heartbeat))
            .unwrap();
        hub.publish(&make_pulse(300, Instruction::Heartbeat))
            .unwrap();
        hub.poll();

        assert_eq!(write_count.load(Ordering::SeqCst), 1);
        assert_eq!(all_count.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn temporal_only_rejects_backwards_tick() {
        let name = unique_name();
        let mut hub = PulseHub::create(
            &name,
            HubConfig {
                ring_size: 8,
                validation: ValidationMode::MonotonicOnly,
                store_slots: TEST_STORE_SLOTS,
            },
        )
        .unwrap();

        hub.publish(&make_pulse(200, Instruction::Heartbeat))
            .unwrap();
        let result = hub.publish(&make_pulse(100, Instruction::Heartbeat));
        assert!(matches!(result, Err(HubError::TemporalViolation { .. })));
    }

    #[test]
    fn temporal_only_accepts_increasing_ticks() {
        let name = unique_name();
        let mut hub = PulseHub::create(
            &name,
            HubConfig {
                ring_size: 8,
                validation: ValidationMode::MonotonicOnly,
                store_slots: TEST_STORE_SLOTS,
            },
        )
        .unwrap();

        for i in 1..=10 {
            assert!(hub
                .publish(&make_pulse(i * 100, Instruction::Heartbeat))
                .is_ok());
        }
    }

    #[test]
    fn passthrough_accepts_any_tick() {
        let name = unique_name();
        let mut hub = PulseHub::create(
            &name,
            HubConfig {
                ring_size: 8,
                validation: ValidationMode::Passthrough,
                store_slots: TEST_STORE_SLOTS,
            },
        )
        .unwrap();

        hub.publish(&make_pulse(500, Instruction::Heartbeat))
            .unwrap();
        hub.publish(&make_pulse(100, Instruction::Heartbeat))
            .unwrap();
        hub.publish(&make_pulse(300, Instruction::Heartbeat))
            .unwrap();
    }

    #[test]
    fn default_config_enforces_temporal() {
        let name = unique_name();
        let mut hub = PulseHub::create(
            &name,
            HubConfig {
                ring_size: 8,
                store_slots: TEST_STORE_SLOTS,
                ..HubConfig::default()
            },
        )
        .unwrap();

        hub.publish(&make_pulse(200, Instruction::Heartbeat))
            .unwrap();
        let result = hub.publish(&make_pulse(100, Instruction::Heartbeat));
        assert!(matches!(result, Err(HubError::TemporalViolation { .. })));
    }

    #[test]
    fn poll_returns_zero_when_empty() {
        let name = unique_name();
        let config = HubConfig {
            store_slots: TEST_STORE_SLOTS,
            ..HubConfig::default()
        };
        let mut hub = PulseHub::create(&name, config).unwrap();
        assert_eq!(hub.poll(), 0);
    }

    #[test]
    fn poll_incremental() {
        let name = unique_name();
        let mut hub = PulseHub::create(
            &name,
            HubConfig {
                ring_size: 8,
                validation: ValidationMode::Passthrough,
                store_slots: TEST_STORE_SLOTS,
            },
        )
        .unwrap();

        let count = Arc::new(AtomicU64::new(0));
        let c = count.clone();
        hub.subscribe(move |_| {
            c.fetch_add(1, Ordering::SeqCst);
        });

        hub.publish(&make_pulse(100, Instruction::Heartbeat))
            .unwrap();
        assert_eq!(hub.poll(), 1);

        hub.publish(&make_pulse(200, Instruction::Heartbeat))
            .unwrap();
        hub.publish(&make_pulse(300, Instruction::Heartbeat))
            .unwrap();
        assert_eq!(hub.poll(), 2);

        assert_eq!(count.load(Ordering::SeqCst), 3);

        assert_eq!(hub.poll(), 0);
    }

    #[test]
    fn a_lapped_poller_counts_the_overrun_and_dispatches_each_pulse_once() {
        let mut hub = PulseHub::create(&unique_name(), small_ring()).unwrap();
        let seen = record_events(&mut hub);
        for step in 0..20 {
            hub.publish(&marked_pulse(step)).unwrap();
        }
        assert_eq!(hub.poll(), 8);
        assert_eq!(
            *seen.lock().unwrap(),
            under_own_index(12..20),
            "the eight newest, in order, none twice"
        );
        assert_eq!(hub.lost_pulses(), 12);
        assert_eq!(hub.poll(), 0);
        assert_eq!(hub.lost_pulses(), 12);
    }

    #[test]
    fn a_poller_that_keeps_up_loses_nothing() {
        let mut hub = PulseHub::create(&unique_name(), small_ring()).unwrap();
        let seen = record_events(&mut hub);
        let mut step = 0;
        // Rounds of three and of a full ring's eight: a poller never more
        // than a capacity behind keeps every pulse, the oldest of a full
        // ring included.
        for round in [3, 8, 8, 3, 8] {
            for _ in 0..round {
                hub.publish(&marked_pulse(step)).unwrap();
                step += 1;
            }
            assert_eq!(hub.poll(), round);
        }
        assert_eq!(*seen.lock().unwrap(), under_own_index(0..step));
        assert_eq!(hub.lost_pulses(), 0);
    }

    #[test]
    fn a_writer_paused_between_its_slot_write_and_its_cursor_move_is_not_polled_early() {
        let name = unique_name();
        let mut hub = PulseHub::create(&name, small_ring()).unwrap();
        let seen = record_events(&mut hub);
        for step in 0..8 {
            hub.publish(&marked_pulse(step)).unwrap();
        }
        // A second handle on the ring, as another process holds, writes
        // position 8, whose slot holds position 0.
        let mut writer = PulseRing::open(&hub_shm_names(&name).unwrap().ring, 8).unwrap();
        let barrier = std::sync::Barrier::new(2);
        let during = std::thread::scope(|s| {
            s.spawn(|| {
                // The slot write of position 8; the cursor still says 8.
                writer.publish_at_slot(8, &marked_pulse(8));
                barrier.wait();
                // Paused here while the hub polls.
                barrier.wait();
                // The cursor move. `publish` writes position 8 once more
                // on the way, which leaves the rest of the test unchanged.
                writer.publish(&marked_pulse(8));
            });
            barrier.wait();
            let during = (hub.poll(), hub.lost_pulses());
            barrier.wait();
            during
        });
        assert_eq!(
            during,
            (7, 1),
            "position 0 is lost, and position 8's pulse is not dispatched under it"
        );
        assert_eq!(hub.poll(), 1);
        assert_eq!(
            *seen.lock().unwrap(),
            under_own_index(1..9),
            "position 8 once, under its own index"
        );
        assert_eq!(hub.lost_pulses(), 1);
    }

    #[test]
    fn a_hub_attached_to_a_written_ring_starts_at_the_oldest_pulse_held() {
        let name = unique_name();
        let mut writer = PulseHub::create(&name, small_ring()).unwrap();
        for step in 0..20 {
            writer.publish(&marked_pulse(step)).unwrap();
        }
        let mut reader = PulseHub::open(&name, small_ring()).unwrap();
        let seen = record_events(&mut reader);
        assert_eq!(reader.poll(), 8);
        assert_eq!(*seen.lock().unwrap(), under_own_index(12..20));
        assert_eq!(
            reader.lost_pulses(),
            0,
            "the ring's history before the hub attached is not a loss"
        );
    }

    /// The chain steps `seen` recorded, in order.
    fn steps(seen: &Mutex<Vec<(u64, u64)>>) -> Vec<u64> {
        seen.lock().unwrap().iter().map(|&(_, step)| step).collect()
    }

    #[test]
    fn an_attached_hub_is_told_its_writer_left_and_reopens_on_the_next() {
        let name = unique_name();
        let mut first = PulseHub::create_fresh(&name, small_ring()).unwrap();
        let mut reader = PulseHub::open(&name, small_ring()).unwrap();
        let seen = record_events(&mut reader);
        for step in 0..3 {
            first.publish(&marked_pulse(step)).unwrap();
        }
        assert_eq!(reader.poll(), 3);
        assert!(!reader.ring_superseded());

        // The writer exits: its ring is marked superseded as its name goes.
        drop(first);
        assert_eq!(reader.poll(), 0);
        assert!(reader.ring_superseded(), "told on the next poll");
        assert!(
            matches!(reader.reopen(), Err(RingError::Open(libc::ENOENT))),
            "no ring to reopen until a writer starts"
        );
        assert!(reader.ring_superseded(), "still told");

        // The restarted writer publishes eight pulses: the old ring holds
        // none of them, and nothing counts them lost.
        let mut restarted = PulseHub::create_fresh(&name, small_ring()).unwrap();
        for step in 3..11 {
            restarted.publish(&marked_pulse(step)).unwrap();
        }
        assert_eq!(reader.poll(), 0);
        assert_eq!(reader.lost_pulses(), 0);
        assert!(reader.reopen().unwrap(), "reopened on the new ring");
        assert!(!reader.ring_superseded());
        assert!(!reader.is_writer());
        assert_eq!(reader.poll(), 8, "the new writer's pulses");
        assert_eq!(steps(&seen), (0..11).collect::<Vec<_>>());
        assert_eq!(reader.lost_pulses(), 0);
    }

    #[test]
    fn a_superseded_ring_is_drained_first_and_reported_once() {
        let name = unique_name();
        let mut first = PulseHub::create_fresh(&name, small_ring()).unwrap();
        let mut reader = PulseHub::open(&name, small_ring()).unwrap();
        let seen = record_events(&mut reader);
        for step in 0..5 {
            first.publish(&marked_pulse(step)).unwrap();
        }
        drop(first);
        // The poll that finds the mark still dispatches what the ring held.
        assert_eq!(reader.poll(), 5);
        assert!(reader.ring_superseded());
        for _ in 0..3 {
            assert_eq!(reader.poll(), 0);
            assert!(reader.ring_superseded());
        }
        assert_eq!(steps(&seen), (0..5).collect::<Vec<_>>());
    }

    #[test]
    fn reopen_waits_while_the_name_still_holds_the_superseded_ring() {
        let name = unique_name();
        let ring_name = hub_shm_names(&name).unwrap().ring;
        let mut writer = PulseHub::create(&name, small_ring()).unwrap();
        let mut reader = PulseHub::open(&name, small_ring()).unwrap();
        // A new owner has marked the ring and not yet replaced it.
        assert!(PulseRing::open(&ring_name, 8).unwrap().supersede());
        assert_eq!(reader.poll(), 0);
        assert!(reader.ring_superseded());
        assert!(!reader.reopen().unwrap(), "the same ring is still named");
        assert!(reader.ring_superseded());

        // The hub that created the ring is not reopened, and as its ring was
        // marked by another it leaves the name alone when it drops.
        assert_eq!(writer.poll(), 0);
        assert!(writer.ring_superseded());
        assert!(!writer.reopen().unwrap(), "a writer is not reopened");
        drop(writer);
        assert!(PulseRing::unlink(&ring_name).unwrap(), "the name was left");
        let mut successor = PulseHub::create_fresh(&name, small_ring()).unwrap();
        successor.publish(&marked_pulse(0)).unwrap();
        assert!(reader.reopen().unwrap());
        assert_eq!(reader.poll(), 1);
    }

    #[test]
    fn a_reopened_hub_fetches_the_new_writers_envelopes_from_its_store() {
        let name = unique_name();
        let first = PulseHub::create_fresh(&name, small_ring()).unwrap();
        let mut reader = PulseHub::open(&name, small_ring()).unwrap();
        let seen = record_envelopes(&mut reader);
        drop(first);
        reader.poll();
        let mut restarted = PulseHub::create_fresh(&name, small_ring()).unwrap();
        restarted
            .broadcast_envelope(
                PulseEnvelope::typed("app/after-restart", vec![1]),
                &NodeId::from_name("o"),
            )
            .unwrap();
        assert!(reader.reopen().unwrap());
        assert_eq!(reader.poll(), 1);
        assert_eq!(reader.unfetched_envelopes(), 0);
        assert_eq!(*seen.lock().unwrap(), ["app/after-restart"]);
    }

    /// The store sizes of the first owner in the restart races below and of
    /// the next: a reader's store size says whose store it holds.
    const OLD_SLOTS: usize = 1;
    const NEW_SLOTS: usize = 4;

    fn owner_config(store_slots: usize) -> HubConfig {
        HubConfig {
            store_slots,
            ..small_ring()
        }
    }

    /// How the first owner of a restart race goes.
    #[derive(Clone, Copy, Debug)]
    enum FirstOwner {
        /// It drops: its ring is marked superseded and both names go.
        Exits,
        /// It dies: its ring and store stay under their names, the ring
        /// unmarked, and it holds no lock, as when a daemon is killed with
        /// -9.
        Dies,
    }

    /// One restart race: a reader attached to the first owner's hub spins
    /// on `poll` and `reopen` while the next owner starts in another
    /// thread. Returns the reader's store size once it reopened, and how
    /// many of three envelopes the next owner then broadcasts reach it.
    fn restart_race(first: FirstOwner) -> (Option<usize>, usize) {
        let name = unique_name();
        let names = hub_shm_names(&name).unwrap();
        let (owner, dead) = match first {
            FirstOwner::Exits => (
                Some(PulseHub::create_fresh(&name, owner_config(OLD_SLOTS)).unwrap()),
                None,
            ),
            // A killed owner never unlinks. Its handles are dropped only
            // once the next owner has replaced the ring and the store, when
            // their drops leave the next owner's names alone: the ring's
            // because it was marked, the store's because the name is no
            // longer its store.
            FirstOwner::Dies => (
                None,
                Some((
                    PulseRing::create_exclusive(&names.ring, 8).unwrap(),
                    EnvelopeStore::create_exclusive(&names.store, OLD_SLOTS).unwrap(),
                )),
            ),
        };
        let mut reader = PulseHub::open(&name, small_ring()).unwrap();
        assert_eq!(reader.store_slots(), Some(OLD_SLOTS));
        let seen = record_envelopes(&mut reader);
        drop(owner);
        let go = Arc::new(std::sync::Barrier::new(2));
        let next = std::thread::spawn({
            let (go, name) = (go.clone(), name.clone());
            move || {
                go.wait();
                PulseHub::create_fresh(&name, owner_config(NEW_SLOTS)).unwrap()
            }
        });
        go.wait();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            reader.poll();
            if reader.ring_superseded() && matches!(reader.reopen(), Ok(true)) {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "never reopened");
        }
        let mut next = next.join().unwrap();
        drop(dead);
        let slots = reader.store_slots();
        assert_eq!(
            EnvelopeStore::open_existing(&names.store)
                .map(|store| store.capacity())
                .ok(),
            Some(NEW_SLOTS),
            "the next owner's store is still under the name"
        );
        for i in 0..3u8 {
            next.broadcast_envelope(
                PulseEnvelope::typed("app/next", vec![i]),
                &NodeId::from_name("o"),
            )
            .unwrap();
        }
        reader.poll();
        let delivered = seen.lock().unwrap().len();
        (slots, delivered)
    }

    #[test]
    fn a_reopen_racing_a_restart_gets_the_next_owners_store() {
        // Before the store was made ahead of the ring, a reopen that won
        // the race attached the next ring with no store (about 5% of
        // trials on macOS) or, after a death, the dead owner's store.
        for first in [FirstOwner::Exits, FirstOwner::Dies] {
            for trial in 0..100 {
                assert_eq!(
                    restart_race(first),
                    (Some(NEW_SLOTS), 3),
                    "{first:?}, trial {trial}: the store after reopen, and the envelopes it delivered"
                );
            }
        }
    }

    #[test]
    fn an_owner_displaced_while_its_lock_file_was_gone_leaves_the_name_free() {
        let name = unique_name();
        let names = hub_shm_names(&name).unwrap();
        let path = owner::hub_lock_path(&name).unwrap();
        let mut first = PulseHub::create_fresh(&name, owner_config(OLD_SLOTS)).unwrap();
        assert!(!first.is_displaced());
        // The lock file is removed, and a second owner takes the name and
        // exits before the first owner's lock is refreshed.
        std::fs::remove_file(&path).unwrap();
        let second =
            PulseHub::create_fresh(&name, owner_config(NEW_SLOTS)).expect("the lock file was gone");
        assert!(first.is_displaced(), "the second owner marked its ring");
        assert!(!second.is_displaced());
        drop(second);

        // Put back, a file naming the first owner would refuse every later
        // owner, and a reader would find no ring to open.
        let lock = first.owner.as_ref().unwrap();
        assert!(matches!(lock.refresh(), Err(LockError::Displaced { .. })));
        assert!(lock.is_displaced());
        assert!(!path.exists(), "the lock file is not put back");
        let mut third = PulseHub::create_fresh(&name, owner_config(OLD_SLOTS + 2))
            .expect("the name is free for the next owner");
        let mut reader = PulseHub::open(&name, small_ring()).expect("its ring is named");
        assert_eq!(reader.store_slots(), Some(OLD_SLOTS + 2));
        third.publish(&marked_pulse(0)).unwrap();
        assert_eq!(reader.poll(), 1);

        // The displaced owner's own poll says so too, and its drop leaves the
        // third owner's lock file, ring and store alone.
        first.poll();
        assert!(first.ring_superseded());
        drop(first);
        assert!(path.exists(), "the third owner's lock file");
        assert!(
            PulseRing::open(&names.ring, 8).is_ok(),
            "the third owner's ring"
        );
        assert_eq!(
            EnvelopeStore::open_existing(&names.store)
                .map(|store| store.capacity())
                .ok(),
            Some(OLD_SLOTS + 2),
            "the third owner's store"
        );
        drop(third);
        assert!(!path.exists());
    }

    #[test]
    fn an_owner_whose_lock_file_alone_was_removed_puts_it_back() {
        let name = unique_name();
        let path = owner::hub_lock_path(&name).unwrap();
        let hub = PulseHub::create_fresh(&name, small_ring()).unwrap();
        std::fs::remove_file(&path).unwrap();
        let lock = hub.owner.as_ref().unwrap();
        assert_eq!(lock.refresh().unwrap(), owner::Refresh::Restored);
        assert!(!lock.is_displaced());
        assert!(!hub.is_displaced());
        assert!(
            matches!(
                PulseHub::create_fresh(&name, small_ring()),
                Err(OwnerError::Owned { .. })
            ),
            "the owner still holds the name"
        );
        drop(hub);
        assert!(!path.exists());
    }

    #[test]
    fn a_writer_without_a_lock_is_displaced_when_an_owner_takes_its_name() {
        let name = unique_name();
        let mut writer = PulseHub::create(&name, small_ring()).unwrap();
        let mut reader = PulseHub::open(&name, small_ring()).unwrap();
        assert!(writer.is_writer());
        assert!(!writer.is_displaced());
        let owner = PulseHub::create_fresh(&name, small_ring()).unwrap();
        assert!(writer.is_displaced(), "no poll needed");
        assert!(!owner.is_displaced());
        writer.poll();
        assert!(writer.ring_superseded());
        reader.poll();
        assert!(reader.ring_superseded());
        assert!(
            !reader.is_displaced(),
            "a hub that attached follows the name"
        );
        assert!(reader.reopen().unwrap());
        assert!(!reader.is_displaced());
    }

    #[test]
    fn a_ring_another_has_marked_is_left_for_its_marker_to_remove() {
        let name = unique_name();
        let names = hub_shm_names(&name).unwrap();
        // A writer that holds no lock is dropping, as one from `create`
        // does: it has marked its ring, and stalls before it removes its
        // store's name and then its ring's.
        let ring = PulseRing::create_exclusive(&names.ring, 8).unwrap();
        let store = EnvelopeStore::create_exclusive(&names.store, OLD_SLOTS).unwrap();
        assert!(ring.supersede());
        let started = std::time::Instant::now();
        let marker = std::thread::spawn({
            let names = names.clone();
            move || {
                std::thread::sleep(std::time::Duration::from_millis(50));
                EnvelopeStore::unlink(&names.store).unwrap();
                PulseRing::unlink(&names.ring).unwrap();
            }
        });
        let owner = PulseHub::create_fresh(&name, owner_config(NEW_SLOTS)).unwrap();
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(50),
            "the new owner waited for the marker"
        );
        marker.join().unwrap();
        // Unlinked at once, the marked ring's late removals would take the new
        // owner's names.
        assert_eq!(
            PulseRing::open_existing(&names.ring)
                .map(|ring| ring.is_superseded())
                .ok(),
            Some(false),
            "the new owner's ring is under the name"
        );
        assert_eq!(
            EnvelopeStore::open_existing(&names.store)
                .map(|store| store.capacity())
                .ok(),
            Some(NEW_SLOTS),
            "and its store"
        );
        drop((ring, store));
        assert!(PulseRing::open_existing(&names.ring).is_ok());
        assert!(EnvelopeStore::open_existing(&names.store).is_ok());
        drop(owner);
    }

    #[test]
    fn a_ring_is_cleared_at_once_when_marked_here_and_after_the_wait_when_not() {
        let name = unique_name();
        let names = hub_shm_names(&name).unwrap();
        let gone = || {
            matches!(
                PulseRing::open_existing(&names.ring),
                Err(RingError::Open(libc::ENOENT))
            )
        };
        // Unmarked: its writer died, or holds no lock. This call marks it,
        // so the ring is its to remove, and it does not wait.
        let left = PulseRing::create_exclusive(&names.ring, 8).unwrap();
        let started = std::time::Instant::now();
        clear_ring_name(&names.ring, std::time::Duration::from_secs(30)).unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        assert!(left.is_superseded() && gone());
        drop(left);
        // Marked by something that never removes it, as a hub killed between
        // its mark and its removals leaves a ring: removed after the wait.
        let marked = PulseRing::create_exclusive(&names.ring, 8).unwrap();
        assert!(marked.supersede());
        let wait = std::time::Duration::from_millis(30);
        let started = std::time::Instant::now();
        clear_ring_name(&names.ring, wait).unwrap();
        assert!(started.elapsed() >= wait, "the marker was given the wait");
        assert!(gone());
        drop(marked);
        clear_ring_name(&names.ring, wait).unwrap();
    }

    #[test]
    fn a_writer_whose_ring_another_marked_leaves_both_names_to_it() {
        let name = unique_name();
        let names = hub_shm_names(&name).unwrap();
        let writer = PulseHub::create(&name, small_ring()).unwrap();
        assert!(writer.is_writer());
        // A new owner has marked the ring and has yet to replace the objects:
        // they are its to remove now, the store included.
        assert!(PulseRing::open_existing(&names.ring).unwrap().supersede());
        drop(writer);
        assert!(PulseRing::open_existing(&names.ring).is_ok());
        assert_eq!(
            EnvelopeStore::open_existing(&names.store)
                .map(|store| store.capacity())
                .ok(),
            Some(TEST_STORE_SLOTS)
        );
        assert!(PulseRing::unlink(&names.ring).unwrap());
        assert!(EnvelopeStore::unlink(&names.store).unwrap());
    }

    #[test]
    fn a_store_is_taken_only_while_its_ring_is_its_writers() {
        let name = unique_name();
        let names = hub_shm_names(&name).unwrap();
        let ring = PulseRing::create_exclusive(&names.ring, 8).unwrap();
        let _store = EnvelopeStore::create_exclusive(&names.store, TEST_STORE_SLOTS).unwrap();
        assert!(matches!(open_paired_store(&ring), PairedStore::Store(_)));
        // A new owner has marked the ring: what the store name holds may be
        // its store by now, so a hub attaching takes none.
        assert!(ring.supersede());
        assert!(matches!(open_paired_store(&ring), PairedStore::Superseded));
        let mut attached = PulseHub::open(&name, small_ring()).unwrap();
        assert_eq!(attached.store_slots(), None);
        attached.poll();
        assert!(
            attached.ring_superseded(),
            "and learns why on its first poll"
        );
        // The creator leaves a ring another has marked under its name.
        drop(ring);
        assert!(PulseRing::unlink(&names.ring).unwrap());
    }

    #[test]
    fn a_hub_attached_before_its_writers_store_existed_opens_it_at_the_first_signal() {
        let name = unique_name();
        let names = hub_shm_names(&name).unwrap();
        // A writer made by `create` makes its ring, then its store: a hub
        // that attaches in between finds no store.
        let ring = PulseRing::create_exclusive(&names.ring, 8).unwrap();
        let mut reader = PulseHub::open(&name, small_ring()).unwrap();
        assert_eq!(reader.store_slots(), None);
        let seen = record_envelopes(&mut reader);
        let store = EnvelopeStore::create_exclusive(&names.store, TEST_STORE_SLOTS).unwrap();
        let mut writer = PulseHub::assemble(ring, small_ring(), Some(store));
        assert!(writer.is_writer());
        writer.publish(&marked_pulse(0)).unwrap();
        assert_eq!(reader.poll(), 1);
        assert_eq!(
            reader.store_slots(),
            None,
            "a pulse that names no store cursor opens nothing"
        );
        writer
            .broadcast_envelope(
                PulseEnvelope::typed("app/late-store", vec![1]),
                &NodeId::from_name("o"),
            )
            .unwrap();
        assert_eq!(reader.poll(), 1);
        assert_eq!(reader.store_slots(), Some(TEST_STORE_SLOTS));
        assert_eq!(*seen.lock().unwrap(), ["app/late-store"]);
        assert_eq!(reader.unfetched_envelopes(), 0);
    }

    #[test]
    fn a_store_that_cannot_be_opened_is_tried_again_at_most_once_a_second() {
        let name = unique_name();
        let names = hub_shm_names(&name).unwrap();
        let ring = PulseRing::create_exclusive(&names.ring, 8).unwrap();
        let mut reader = PulseHub::open(&name, small_ring()).unwrap();
        let seen = record_envelopes(&mut reader);
        // A writer whose store the reader cannot open: made after the
        // reader attached, and its name gone since.
        let store = EnvelopeStore::create_exclusive(&names.store, TEST_STORE_SLOTS).unwrap();
        let mut writer = PulseHub::assemble(ring, small_ring(), Some(store));
        assert!(EnvelopeStore::unlink(&names.store).unwrap());
        let origin = NodeId::from_name("o");
        let mut broadcast = |i: u8| {
            writer
                .broadcast_envelope(PulseEnvelope::typed("app/unopenable", vec![i]), &origin)
                .unwrap();
        };
        for i in 0..3 {
            broadcast(i);
        }
        assert_eq!(reader.poll(), 3);
        assert_eq!(reader.store_slots(), None);
        assert_eq!(reader.unfetched_envelopes(), 3);
        assert_eq!(
            reader.store_retry_failures.0, 1,
            "one attempt for three signals"
        );
        // Once the wait is over, the next signal tries again.
        reader.store_retry_at = Some(std::time::Instant::now());
        broadcast(3);
        assert_eq!(reader.poll(), 1);
        assert_eq!(reader.store_retry_failures.0, 2);
        assert!(seen.lock().unwrap().is_empty());
    }

    #[test]
    fn pulse_event_carries_metadata() {
        let name = unique_name();
        let mut hub = PulseHub::create(
            &name,
            HubConfig {
                ring_size: 8,
                validation: ValidationMode::Passthrough,
                store_slots: TEST_STORE_SLOTS,
            },
        )
        .unwrap();

        let captured_tick = Arc::new(AtomicU64::new(0));
        let t = captured_tick.clone();
        hub.subscribe(move |event| {
            t.store(event.monotonic_nanos, Ordering::SeqCst);
            assert_eq!(event.instruction, Instruction::Heartbeat);
            assert_eq!(event.scope, 1);
        });

        hub.publish(&make_pulse(42000, Instruction::Heartbeat))
            .unwrap();
        hub.poll();

        assert_eq!(captured_tick.load(Ordering::SeqCst), 42000);
    }

    #[test]
    fn hub_error_display() {
        let err = HubError::TemporalViolation {
            pulse_tick: 100,
            last_tick: 200,
        };
        let s = format!("{}", err);
        assert!(s.contains("temporal violation"));
    }

    #[test]
    fn hub_config_defaults() {
        let cfg = HubConfig::default();
        assert_eq!(cfg.ring_size, 64);
        assert_eq!(cfg.validation, ValidationMode::MonotonicOnly);
        assert_eq!(cfg.store_slots, DEFAULT_STORE_SLOTS);
        assert_eq!(DEFAULT_STORE_SLOTS, 256);
    }

    #[test]
    fn validation_mode_default() {
        let mode = ValidationMode::default();
        assert_eq!(mode, ValidationMode::MonotonicOnly);
    }

    #[test]
    fn monotonic_nanos_set_and_get() {
        let name = unique_name();
        let mut hub = PulseHub::create(&name, small_ring()).unwrap();
        let before = hub.monotonic_nanos();
        assert!(
            before > 0,
            "an unset clock reads the host's monotonic clock"
        );
        assert!(hub.monotonic_nanos() >= before, "and never goes back");

        hub.set_monotonic_nanos(42000);
        assert_eq!(hub.monotonic_nanos(), 42000);
        assert_eq!(hub.monotonic_nanos(), 42000, "a set clock stays set");
    }

    #[test]
    fn signals_carry_the_hubs_clock() {
        let mut hub = PulseHub::create(&unique_name(), small_ring()).unwrap();
        let origin = NodeId::from_name("o");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        hub.listen(NodeId::from_name("l"), ListenFilter::All, move |env| {
            sink.lock().unwrap().push(env.monotonic_nanos);
        });
        for i in 0..3u8 {
            let envelope = PulseEnvelope::typed("app/clock", vec![i]);
            hub.broadcast_envelope(envelope, &origin).unwrap();
        }
        // Unset, the clock is CLOCK_MONOTONIC: every signal and envelope
        // carries a real time, none earlier than the one before.
        let signal_times: Vec<u64> = (0..3)
            .map(|slot| hub.ring().read_slot(slot).unwrap().monotonic_nanos)
            .collect();
        assert!(signal_times[0] > 0, "{signal_times:?}");
        assert!(
            signal_times.windows(2).all(|w| w[0] <= w[1]),
            "{signal_times:?}"
        );
        let envelope_times = seen.lock().unwrap().clone();
        assert!(envelope_times[0] > 0, "{envelope_times:?}");
        assert!(
            envelope_times.windows(2).all(|w| w[0] <= w[1]),
            "{envelope_times:?}"
        );

        // Set, the application's clock is what the hub stamps, and the
        // outcome says which stamp the envelope carries.
        hub.set_monotonic_nanos(7);
        let outcome = hub
            .broadcast_envelope(PulseEnvelope::typed("app/clock", vec![3]), &origin)
            .unwrap();
        assert_eq!(hub.ring().read_slot(3).unwrap().monotonic_nanos, 7);
        assert_eq!(seen.lock().unwrap().last(), Some(&7));
        assert_eq!(outcome.monotonic_nanos, 7);
    }

    #[test]
    fn the_hub_that_creates_the_ring_is_its_one_writer() {
        let name = unique_name();
        let creator = PulseHub::create(&name, small_ring()).unwrap();
        assert!(creator.is_writer());
        assert!(
            !PulseHub::create(&name, small_ring()).unwrap().is_writer(),
            "a create that attached"
        );
        assert!(!PulseHub::open(&name, small_ring()).unwrap().is_writer());
        let fresh = unique_name();
        assert!(PulseHub::create_fresh(&fresh, small_ring())
            .unwrap()
            .is_writer());
        let exclusive = unique_name();
        assert!(PulseHub::create_exclusive(&exclusive, small_ring())
            .unwrap()
            .is_writer());
    }

    #[test]
    fn an_attached_hub_refuses_to_publish_and_leaves_the_ring_untouched() {
        let name = unique_name();
        let creator = PulseHub::create(&name, small_ring()).unwrap();
        let mut attached = PulseHub::open(&name, small_ring()).unwrap();
        let origin = NodeId::from_name("o");
        let received = Arc::new(AtomicU64::new(0));
        let count = received.clone();
        attached.listen(NodeId::from_name("l"), ListenFilter::All, move |_| {
            count.fetch_add(1, Ordering::SeqCst);
        });

        assert_eq!(
            attached.publish(&make_pulse(1, Instruction::Data)),
            Err(HubError::ReadOnly)
        );
        let mut beat = make_pulse(2, Instruction::Heartbeat);
        beat.set_heartbeat_payload(&HeartbeatPayload::zeroed());
        assert_eq!(attached.publish(&beat), Err(HubError::ReadOnly));
        let envelope = || PulseEnvelope::typed("app/refused", vec![1]);
        assert!(matches!(
            attached.broadcast_envelope(envelope(), &origin),
            Err(HubError::ReadOnly)
        ));
        assert!(matches!(
            attached.route_envelope(envelope(), &origin),
            Err(HubError::ReadOnly)
        ));
        assert_eq!(received.load(Ordering::SeqCst), 0, "nothing dispatched");
        assert_eq!(creator.ring().cursor_position(), 0, "the ring is untouched");
        assert_eq!(creator.ring().write_count(), 0);
        let store = EnvelopeStore::open_existing(&hub_shm_names(&name).unwrap().store).unwrap();
        assert_eq!(store.write_cursor(), 0, "the store is untouched");

        // Dispatch within the attached hub's own process still works.
        assert_eq!(
            attached.send_envelope(envelope(), &origin, &origin),
            Ok(true)
        );
        assert_eq!(received.load(Ordering::SeqCst), 1);
        assert_eq!(attached.poll(), 0);
    }

    #[test]
    fn the_creators_publishes_reach_an_attached_hubs_poll() {
        let name = unique_name();
        let mut creator = PulseHub::create(&name, small_ring()).unwrap();
        let mut attached = PulseHub::open(&name, small_ring()).unwrap();
        let pulses = record_events(&mut attached);
        let envelopes = record_envelopes(&mut attached);

        creator.publish(&marked_pulse(0)).unwrap();
        creator
            .broadcast_envelope(
                PulseEnvelope::typed("app/from-creator", vec![5]),
                &NodeId::from_name("o"),
            )
            .unwrap();

        assert_eq!(attached.poll(), 2);
        let pulses = pulses.lock().unwrap();
        assert_eq!(pulses.len(), 2);
        assert_eq!(pulses[0], (0, 0), "the published pulse");
        assert_eq!(pulses[1].0, 1, "then the envelope's signal");
        assert_eq!(*envelopes.lock().unwrap(), ["app/from-creator"]);
    }

    #[test]
    fn hub_schema_integration() {
        let name = unique_name();
        let mut hub = PulseHub::create(
            &name,
            HubConfig {
                ring_size: 8,
                validation: ValidationMode::Passthrough,
                store_slots: TEST_STORE_SLOTS,
            },
        )
        .unwrap();

        let entry = mesh_schema::SchemaEntry::new(0x0010, "test_type");
        hub.register_schema(entry).unwrap();

        assert!(hub.get_schema(0x0010).is_some());
        assert_eq!(hub.get_schema(0x0010).unwrap().name, "test_type");
        assert!(hub.get_schema_by_name("test_type").is_some());
        assert!(hub.get_schema(0x9999).is_none());
    }

    #[test]
    fn hub_listen_and_broadcast() {
        use std::sync::atomic::AtomicUsize;

        let name = unique_name();
        let mut hub = PulseHub::create(
            &name,
            HubConfig {
                ring_size: 8,
                validation: ValidationMode::Passthrough,
                store_slots: TEST_STORE_SLOTS,
            },
        )
        .unwrap();

        let node = NodeId::from_name("test");
        let origin = NodeId::from_name("origin");

        let entry = mesh_schema::SchemaEntry::new(0x0010, "test_type");
        hub.register_schema(entry).unwrap();

        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        hub.listen(node, mesh_broadcast::ListenFilter::All, move |_| {
            c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });

        assert_eq!(hub.listener_count(), 1);

        hub.set_monotonic_nanos(1000);
        let env = PulseEnvelope::new(0x0010, vec![]);
        let result = hub.broadcast_envelope(env, &origin).unwrap();
        assert_eq!(result.delivery.delivered, 1);
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn a_refused_envelope_is_counted_reported_and_still_delivered() {
        let mut hub = PulseHub::create(
            &unique_name(),
            HubConfig {
                ring_size: 8,
                validation: ValidationMode::Passthrough,
                store_slots: TEST_STORE_SLOTS,
            },
        )
        .unwrap();
        let delivered = Arc::new(AtomicU64::new(0));
        let d = delivered.clone();
        hub.listen(NodeId::from_name("l"), ListenFilter::All, move |_| {
            d.fetch_add(1, Ordering::SeqCst);
        });
        let origin = NodeId::from_name("origin");

        let small = hub
            .broadcast_envelope(PulseEnvelope::typed("app/small", vec![7u8; 64]), &origin)
            .unwrap();
        assert_eq!(small.persisted(), Some(true));
        assert!(matches!(small.stored, Some(Ok(_))));
        assert_eq!(hub.store_failures(), 0);

        // A payload one byte over the entry limit: its canonical encoding,
        // which adds the envelope's framing, cannot fit an entry.
        let big = PulseEnvelope::typed("app/big", vec![0u8; core_store::MAX_ENTRY_SIZE + 1]);
        let refused = hub.broadcast_envelope(big, &origin).unwrap();
        assert_eq!(refused.persisted(), Some(false));
        assert!(
            matches!(
                refused.stored,
                Some(Err(EnvelopeStoreError::EnvelopeTooLarge { max, .. }))
                    if max == core_store::MAX_ENTRY_SIZE
            ),
            "{:?}",
            refused.stored
        );
        assert_eq!(hub.store_failures(), 1, "the refusal is counted");
        assert_eq!(refused.delivery.delivered, 1, "and still delivered");
        assert_eq!(delivered.load(Ordering::SeqCst), 2);
        assert_eq!(
            hub.ring().cursor_position(),
            1,
            "only the stored envelope was signalled on the ring"
        );
    }

    #[test]
    fn store_failures_are_logged_at_the_first_and_at_each_doubling() {
        let mut count = FailureCount::default();
        let logged: Vec<u64> = (0..1000).filter_map(|_| count.record()).collect();
        assert_eq!(logged, [1, 2, 4, 8, 16, 32, 64, 128, 256, 512]);
        assert_eq!(count.0, 1000, "every failure is counted, logged or not");
    }

    #[test]
    fn a_hub_without_a_store_reports_no_persistence() {
        let names = hub_shm_names(&unique_name()).unwrap();
        let ring = PulseRing::create(&names.ring, 8).unwrap();
        let mut hub = PulseHub::assemble(ring, HubConfig::default(), None);
        let outcome = hub
            .broadcast_envelope(
                PulseEnvelope::typed("app/x", vec![1u8]),
                &NodeId::from_name("o"),
            )
            .unwrap();
        assert_eq!(outcome.persisted(), None);
        assert_eq!(hub.store_failures(), 0);
    }

    /// Listen for every envelope on `hub`, recording each one's payload.
    fn record_payloads(hub: &mut PulseHub) -> Arc<Mutex<Vec<Vec<u8>>>> {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        hub.listen(
            NodeId::from_name("payloads"),
            ListenFilter::All,
            move |env| {
                sink.lock().unwrap().push(env.payload().to_bytes());
            },
        );
        seen
    }

    #[test]
    fn a_small_store_holds_as_many_envelopes_as_it_has_slots() {
        let name = unique_name();
        let config = HubConfig {
            store_slots: 4,
            ..small_ring()
        };
        let mut creator = PulseHub::create(&name, config).unwrap();
        assert_eq!(creator.store_slots(), Some(4));
        // Attached by name, with a config that asks for another size.
        let mut attached = PulseHub::open(&name, small_ring()).unwrap();
        assert_eq!(attached.store_slots(), Some(4));
        let seen = record_payloads(&mut attached);

        let origin = NodeId::from_name("o");
        for i in 0..6u8 {
            let envelope = PulseEnvelope::typed("app/small-store", vec![i]);
            let outcome = creator.broadcast_envelope(envelope, &origin).unwrap();
            assert!(
                matches!(outcome.stored, Some(Ok(cursor)) if cursor == u64::from(i)),
                "{:?}",
                outcome.stored
            );
        }
        // Six envelopes through four slots: the two oldest are overwritten
        // before the attached hub polls, and it fetches the four newest.
        assert_eq!(attached.poll(), 6, "every signal is a pulse");
        assert_eq!(attached.unfetched_envelopes(), 2);
        let expected: Vec<Vec<u8>> = (2..6u8).map(|i| vec![i]).collect();
        assert_eq!(*seen.lock().unwrap(), expected);
    }

    #[test]
    fn a_hub_attached_by_name_takes_the_store_size_from_the_store() {
        let name = unique_name();
        let config = HubConfig {
            store_slots: 3,
            ..small_ring()
        };
        let creator = PulseHub::create_fresh(&name, config).unwrap();
        assert_eq!(creator.store_slots(), Some(3));
        // Neither attaching constructor is told the creator's size, and
        // their own configs ask for another and for none.
        let opened = PulseHub::open(
            &name,
            HubConfig {
                store_slots: DEFAULT_STORE_SLOTS,
                ..small_ring()
            },
        )
        .unwrap();
        let joined = PulseHub::create(
            &name,
            HubConfig {
                store_slots: 0,
                ..small_ring()
            },
        )
        .unwrap();
        assert!(!joined.is_writer(), "create attached to the creator's ring");
        assert_eq!(opened.store_slots(), Some(3));
        assert_eq!(joined.store_slots(), Some(3));
    }

    #[test]
    fn a_hub_configured_with_no_store_slots_runs_without_a_store() {
        let none = HubConfig {
            store_slots: 0,
            ..small_ring()
        };
        let name = unique_name();
        let names = hub_shm_names(&name).unwrap();
        // A store an earlier owner left under the name.
        std::mem::forget(EnvelopeStore::create_exclusive(&names.store, 2).unwrap());
        let mut hub = PulseHub::create_fresh(&name, none.clone()).unwrap();
        assert_eq!(hub.store_slots(), None);
        assert!(
            matches!(
                EnvelopeStore::open_existing(&names.store),
                Err(EnvelopeStoreError::Open(libc::ENOENT))
            ),
            "the earlier owner's store is removed and none is made"
        );
        let outcome = hub
            .broadcast_envelope(
                PulseEnvelope::typed("app/unkept", vec![1]),
                &NodeId::from_name("o"),
            )
            .unwrap();
        assert_eq!(outcome.persisted(), None);
        assert_eq!(hub.store_failures(), 0);
        assert_eq!(hub.ring().cursor_position(), 0, "nothing is signalled");
        let attached = PulseHub::open(&name, small_ring()).unwrap();
        assert_eq!(attached.store_slots(), None, "there is no store to open");

        // The other constructors that create a ring make none either.
        for make in [PulseHub::create, PulseHub::create_exclusive] {
            let name = unique_name();
            let hub = make(&name, none.clone()).unwrap();
            assert!(hub.is_writer());
            assert_eq!(hub.store_slots(), None);
            let store = hub_shm_names(&name).unwrap().store;
            assert!(EnvelopeStore::open_existing(&store).is_err(), "{store}");
        }
    }

    #[test]
    fn hub_unlisten() {
        let name = unique_name();
        let mut hub = PulseHub::create(
            &name,
            HubConfig {
                ring_size: 8,
                validation: ValidationMode::Passthrough,
                store_slots: TEST_STORE_SLOTS,
            },
        )
        .unwrap();

        let node = NodeId::from_name("test");
        let id = hub.listen(node, mesh_broadcast::ListenFilter::All, |_| {});
        assert_eq!(hub.listener_count(), 1);

        hub.unlisten(id);
        assert_eq!(hub.listener_count(), 0);
    }

    #[test]
    fn hub_unlisten_node() {
        let name = unique_name();
        let mut hub = PulseHub::create(
            &name,
            HubConfig {
                ring_size: 8,
                validation: ValidationMode::Passthrough,
                store_slots: TEST_STORE_SLOTS,
            },
        )
        .unwrap();

        let node = NodeId::from_name("test");
        hub.listen(node, mesh_broadcast::ListenFilter::All, |_| {});
        hub.listen(node, mesh_broadcast::ListenFilter::Type(0x0010), |_| {});
        assert_eq!(hub.listener_count(), 2);

        hub.unlisten_node(&node);
        assert_eq!(hub.listener_count(), 0);
    }

    #[test]
    fn hub_add_producer_consumer() {
        let name = unique_name();
        let mut hub = PulseHub::create(
            &name,
            HubConfig {
                ring_size: 8,
                validation: ValidationMode::Passthrough,
                store_slots: TEST_STORE_SLOTS,
            },
        )
        .unwrap();

        let entry = mesh_schema::SchemaEntry::new(0x0010, "test");
        hub.register_schema(entry).unwrap();

        let producer = NodeId::from_name("prod");
        let consumer = NodeId::from_name("cons");
        hub.add_producer(0x0010, producer).unwrap();
        hub.add_consumer(0x0010, consumer).unwrap();

        let schema = hub.get_schema(0x0010).unwrap();
        assert!(schema.producers.contains(&producer));
        assert!(schema.consumers.contains(&consumer));
    }

    #[test]
    fn hub_route_envelope_stamps_monotonic() {
        let name = unique_name();
        let mut hub = PulseHub::create(
            &name,
            HubConfig {
                ring_size: 8,
                validation: ValidationMode::Passthrough,
                store_slots: TEST_STORE_SLOTS,
            },
        )
        .unwrap();

        let origin = NodeId::from_name("origin");
        let entry = mesh_schema::SchemaEntry::new(0x0010, "test");
        hub.register_schema(entry).unwrap();

        let captured_tick = Arc::new(AtomicU64::new(0));
        let t = captured_tick.clone();
        let node = NodeId::from_name("listener");
        hub.listen(node, mesh_broadcast::ListenFilter::All, move |env| {
            t.store(env.monotonic_nanos, Ordering::SeqCst);
        });

        hub.set_monotonic_nanos(7777);
        let env = PulseEnvelope::new(0x0010, vec![]);
        hub.route_envelope(env, &origin).unwrap();

        assert_eq!(captured_tick.load(Ordering::SeqCst), 7777);
    }

    #[test]
    fn hub_schema_error_propagates() {
        let name = unique_name();
        let mut hub = PulseHub::create(
            &name,
            HubConfig {
                ring_size: 8,
                validation: ValidationMode::Passthrough,
                store_slots: TEST_STORE_SLOTS,
            },
        )
        .unwrap();

        let origin = NodeId::from_name("origin");
        let env = PulseEnvelope::new(0x9999, vec![]);
        let result = hub.route_envelope(env, &origin);
        assert!(matches!(result, Err(HubError::Schema(_))));
    }

    #[test]
    fn hub_error_from_schema_error() {
        let se = mesh_schema::SchemaError::UnknownType(0x1234);
        let he: HubError = se.into();
        assert!(matches!(
            he,
            HubError::Schema(mesh_schema::SchemaError::UnknownType(0x1234))
        ));
    }

    #[test]
    fn cross_process_envelope_routing() {
        let name = unique_name();

        let mut writer_hub = PulseHub::create(
            &name,
            HubConfig {
                ring_size: 64,
                validation: ValidationMode::Passthrough,
                store_slots: TEST_STORE_SLOTS,
            },
        )
        .unwrap();
        writer_hub.set_monotonic_nanos(1000);

        let mut reader_hub = PulseHub::create(
            &name,
            HubConfig {
                ring_size: 64,
                validation: ValidationMode::Passthrough,
                store_slots: TEST_STORE_SLOTS,
            },
        )
        .unwrap();

        let received = Arc::new(Mutex::new(Vec::<String>::new()));
        let rx = received.clone();
        let node = NodeId::from_name("reader");
        reader_hub.listen(
            node,
            mesh_broadcast::ListenFilter::TypeName("app/tool_auth".into()),
            move |env| {
                if let Some(tn) = env.type_name() {
                    rx.lock().unwrap().push(tn.to_string());
                }
            },
        );

        let origin = NodeId::from_name("writer");
        let env = PulseEnvelope::typed("app/tool_auth", vec![1, 2, 3]);
        writer_hub.broadcast_envelope(env, &origin).unwrap();

        reader_hub.poll();

        let topics = received.lock().unwrap();
        assert_eq!(topics.len(), 1);
        assert_eq!(topics[0], "app/tool_auth");
    }

    /// Listen for every envelope on `hub`, recording each one's type name.
    fn record_envelopes(hub: &mut PulseHub) -> Arc<Mutex<Vec<String>>> {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        hub.listen(
            NodeId::from_name("recorder"),
            ListenFilter::All,
            move |env| {
                sink.lock().unwrap().push(env.effective_type_name());
            },
        );
        seen
    }

    #[test]
    fn a_signal_names_its_envelope_and_the_hub_that_broadcast_it() {
        let mut hub = PulseHub::create(&unique_name(), small_ring()).unwrap();
        let envelope = PulseEnvelope::typed("app/named", vec![4, 2]);
        let id = envelope.id();
        hub.broadcast_envelope(envelope, &NodeId::from_name("o"))
            .unwrap();
        let signal = hub.ring().read_slot(0).expect("the signal");
        assert_eq!(signal.instruction_code(), Instruction::Data);
        assert_eq!(signal.envelope_id(), Some(id));
        assert_eq!(signal.store_cursor(), Some(0), "the copy it signals");
        assert_eq!(signal.origin_id, hub.instance_id());
    }

    /// The origin and time of each envelope a listener received.
    type OriginsSeen = Arc<Mutex<Vec<([u8; 16], u64)>>>;

    /// Listen for every envelope on `hub`, recording each one's origin and
    /// time.
    fn record_origins(hub: &mut PulseHub) -> OriginsSeen {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        hub.listen(
            NodeId::from_name("origins"),
            ListenFilter::All,
            move |env| {
                sink.lock().unwrap().push((env.origin, env.monotonic_nanos));
            },
        );
        seen
    }

    /// The same content from `origin`: every such envelope has one id.
    fn reading_from(origin: [u8; 16]) -> PulseEnvelope {
        let mut envelope = PulseEnvelope::typed("sensor/level", b"42".to_vec());
        envelope.origin = origin;
        envelope
    }

    #[test]
    fn same_content_from_two_origins_reaches_an_attached_hub_once_from_each() {
        let name = unique_name();
        let mut writer = PulseHub::create(&name, small_ring()).unwrap();
        let mut reader = PulseHub::open(&name, small_ring()).unwrap();
        let seen = record_origins(&mut reader);
        let (a, b) = ([0xaa; 16], [0xbb; 16]);
        let from_b = Arc::new(AtomicU64::new(0));
        let count = from_b.clone();
        reader.listen(
            NodeId::from_name("only-b"),
            ListenFilter::Origin(NodeId::from_bytes(b)),
            move |_| {
                count.fetch_add(1, Ordering::SeqCst);
            },
        );

        assert_eq!(
            reading_from(a).id(),
            reading_from(b).id(),
            "one id for both"
        );
        for (origin, time) in [(a, 100), (b, 200)] {
            writer.set_monotonic_nanos(time);
            writer
                .broadcast_envelope(reading_from(origin), &NodeId::from_bytes(origin))
                .unwrap();
        }
        assert_eq!(reader.poll(), 2);
        assert_eq!(
            *seen.lock().unwrap(),
            vec![(a, 100), (b, 200)],
            "each signal delivers its own copy, with its own origin and time"
        );
        assert_eq!(
            from_b.load(Ordering::SeqCst),
            1,
            "B's listener hears B once"
        );
        assert_eq!(reader.unfetched_envelopes(), 0);
    }

    #[test]
    fn a_signal_whose_copy_was_lapped_is_counted_not_given_the_later_copy() {
        let name = unique_name();
        let one_slot = HubConfig {
            store_slots: 1,
            ..small_ring()
        };
        let mut writer = PulseHub::create(&name, one_slot).unwrap();
        let mut reader = PulseHub::open(&name, small_ring()).unwrap();
        let seen = record_origins(&mut reader);
        // B's copy of the same content takes A's slot before the reader
        // polls: A's signal names a copy that is gone, and the copy now in
        // its slot, though it carries the same id, is B's.
        let (a, b) = ([0xaa; 16], [0xbb; 16]);
        writer.set_monotonic_nanos(100);
        writer
            .broadcast_envelope(reading_from(a), &NodeId::from_bytes(a))
            .unwrap();
        writer.set_monotonic_nanos(200);
        writer
            .broadcast_envelope(reading_from(b), &NodeId::from_bytes(b))
            .unwrap();
        assert_eq!(reader.poll(), 2, "both signals are pulses");
        assert_eq!(
            *seen.lock().unwrap(),
            vec![(b, 200)],
            "B once, and A never as B"
        );
        assert_eq!(reader.unfetched_envelopes(), 1, "A's signal is counted");
    }

    #[test]
    fn a_pulse_published_without_an_origin_carries_the_hubs_identity() {
        let mut hub = PulseHub::create(&unique_name(), small_ring()).unwrap();
        let other = PulseHub::create(&unique_name(), small_ring()).unwrap();
        assert_ne!(hub.instance_id(), [0u8; 16]);
        assert_ne!(hub.instance_id(), other.instance_id());

        let unset = make_pulse(1, Instruction::Data);
        hub.publish(&unset).unwrap();
        let mut set = make_pulse(2, Instruction::Data);
        set.origin_id = [7u8; 16];
        hub.publish(&set).unwrap();

        assert_eq!(
            hub.ring().read_slot(0).unwrap().origin_id,
            hub.instance_id()
        );
        assert_eq!(
            unset.origin_id, [0u8; 16],
            "the caller's pulse is untouched"
        );
        assert_eq!(
            hub.ring().read_slot(1).unwrap().origin_id,
            [7u8; 16],
            "an origin the caller set is kept"
        );
    }

    #[test]
    fn a_hub_polling_its_own_signal_does_not_deliver_the_envelope_twice() {
        let mut hub = PulseHub::create(&unique_name(), small_ring()).unwrap();
        let seen = record_envelopes(&mut hub);
        hub.broadcast_envelope(
            PulseEnvelope::typed("app/own", vec![1]),
            &NodeId::from_name("o"),
        )
        .unwrap();
        assert_eq!(seen.lock().unwrap().len(), 1, "delivered when broadcast");
        assert_eq!(hub.poll(), 1, "the signal is still a pulse");
        assert_eq!(seen.lock().unwrap().len(), 1, "and is not delivered again");
        assert_eq!(hub.unfetched_envelopes(), 0);
    }

    #[test]
    fn unfetchable_signals_are_counted_and_skipped() {
        let name = unique_name();
        let config = HubConfig {
            ring_size: 512,
            validation: ValidationMode::Passthrough,
            store_slots: TEST_STORE_SLOTS,
        };
        let mut writer = PulseHub::create(&name, config.clone()).unwrap();
        let mut reader = PulseHub::create(&name, config).unwrap();
        let seen = record_envelopes(&mut reader);
        let origin = NodeId::from_name("w");

        // A signal naming an envelope no store holds.
        let mut ghost = make_pulse(1, Instruction::Data);
        ghost.set_envelope_id(&PulseEnvelope::typed("app/ghost", vec![0]).id());
        writer.publish(&ghost).unwrap();
        // An envelope overwritten in the store before the reader polls: as
        // many more stored after it as the store has slots.
        writer
            .broadcast_envelope(PulseEnvelope::typed("app/first", vec![1]), &origin)
            .unwrap();
        for i in 0..TEST_STORE_SLOTS as u32 {
            let later = PulseEnvelope::typed("app/later", i.to_le_bytes().to_vec());
            writer.broadcast_envelope(later, &origin).unwrap();
        }
        // A signal naming a stored envelope by id alone, with no store
        // cursor, as an application publishing its own Data pulse would:
        // it names no copy, so none is looked up by id.
        let mut bare = make_pulse(2, Instruction::Data);
        bare.set_envelope_id(&PulseEnvelope::typed("app/later", 0u32.to_le_bytes().to_vec()).id());
        writer.publish(&bare).unwrap();

        let signals = 3 + TEST_STORE_SLOTS as u64;
        assert_eq!(reader.poll(), signals, "every signal is still a pulse");
        assert_eq!(reader.unfetched_envelopes(), 3);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), TEST_STORE_SLOTS);
        assert!(seen.iter().all(|t| t == "app/later"), "{seen:?}");
    }

    #[test]
    fn a_heartbeat_records_the_nodes_schema_version_and_stage_count() {
        let mut hub = PulseHub::create(&unique_name(), small_ring()).unwrap();
        hub.enable_health(HeartbeatConfig::default());
        let node = NodeId::from_name("worker");
        hub.register_node(node);

        let mut payload = HeartbeatPayload::zeroed();
        payload.schema_version = 0x00c0_ffee;
        payload.stage_count = 7;
        let mut beat = make_pulse(1, Instruction::Heartbeat);
        beat.origin_id = *node.as_bytes();
        beat.set_heartbeat_payload(&payload);
        hub.publish(&beat).unwrap();
        hub.poll();

        let health = hub.health_registry().unwrap().get(&node).unwrap();
        assert_eq!(health.schema_version(), 0x00c0_ffee);
        assert_eq!(health.stage_count(), 7);
    }

    /// A heartbeat pulse from `node` at `tick`, reporting `schema_version`.
    fn heartbeat_from(node: NodeId, tick: u64, schema_version: u64) -> Pulse {
        let mut payload = HeartbeatPayload::zeroed();
        payload.schema_version = schema_version;
        let mut beat = make_pulse(tick, Instruction::Heartbeat);
        beat.origin_id = *node.as_bytes();
        beat.set_heartbeat_payload(&payload);
        beat
    }

    /// `health_tick` counts a miss only for a node that has not heartbeated
    /// since the last tick, so one that heartbeats before every tick is never
    /// escalated, and a drifting node's Degraded state lasts past the next
    /// tick.
    #[test]
    fn health_tick_counts_only_silent_nodes_and_keeps_drift() {
        use mesh_health::NodeState;
        let mut hub = PulseHub::create(&unique_name(), small_ring()).unwrap();
        hub.enable_health(
            HeartbeatConfig::default()
                .with_interval_ms(500)
                .with_warn_after(1)
                .with_restart_after(3)
                .with_isolate_after(5),
        );
        let (punctual, drifter) = (NodeId::from_name("punctual"), NodeId::from_name("drifter"));
        hub.register_node(punctual);
        hub.register_node(drifter);
        hub.set_expected_hashes([(*drifter.as_bytes(), 0x1111)].into_iter().collect());
        let state = |hub: &PulseHub, node: &NodeId| {
            hub.health_registry().unwrap().get(node).unwrap().state()
        };
        let mut tick = 0;
        for round in 0..3 {
            for node in [punctual, drifter] {
                tick += 1;
                hub.publish(&heartbeat_from(node, tick, 0x2222)).unwrap();
            }
            hub.poll();
            assert_eq!(hub.health_tick(), [], "round {round}");
            assert_eq!(state(&hub, &punctual), NodeState::Healthy, "round {round}");
            assert_eq!(state(&hub, &drifter), NodeState::Degraded, "round {round}");
        }
        // Silent from here: the first tick escalates both, the drift kept.
        let mut escalated = hub.health_tick();
        escalated.sort_by_key(|(node, _)| *node.as_bytes());
        let mut want = vec![
            (punctual, NodeState::Warning),
            (drifter, NodeState::Warning),
        ];
        want.sort_by_key(|(node, _)| *node.as_bytes());
        assert_eq!(escalated, want);
        assert!(hub
            .health_registry()
            .unwrap()
            .get(&drifter)
            .unwrap()
            .drifted());
    }

    /// A hub that drops while a new owner takes its name: it runs
    /// `release_names` and stalls at `step` while the new owner's
    /// `create_fresh` runs. The new owner waits a second for the marked
    /// ring's name to go, finds it still there, and replaces both names.
    /// Returns the new owner, whose store has 3 slots against the old
    /// hub's `TEST_STORE_SLOTS`, so the two stores can be told apart.
    fn successor_during_release(name: &str, step: ReleaseStep) -> PulseHub {
        let mut old = PulseHub::create(name, small_ring()).unwrap();
        assert!(old.is_writer());
        let mut new = None;
        old.release_names(|at| {
            if at == step {
                let config = HubConfig {
                    store_slots: 3,
                    ..small_ring()
                };
                new = Some(PulseHub::create_fresh(name, config).expect("the new owner starts"));
            }
        });
        drop(old);
        new.expect("the stall came")
    }

    /// Both of `name`'s names hold the new owner's objects: its unmarked
    /// ring, and its 3-slot store, which a hub attaching by name finds.
    fn names_are_the_new_owners(name: &str, new: &PulseHub) {
        let names = hub_shm_names(name).unwrap();
        let ring = PulseRing::open_existing(&names.ring).expect("the new owner's ring name");
        assert!(
            !ring.is_superseded(),
            "the ring under the name is not the new owner's"
        );
        let store = EnvelopeStore::open_existing(&names.store).expect("the new owner's store name");
        assert_eq!(
            store.capacity(),
            3,
            "the store under the name is not the new owner's"
        );
        let reader = PulseHub::open(name, small_ring()).expect("a hub attaches by name");
        assert_eq!(reader.store_slots(), Some(3));
        assert!(!new.is_displaced());
    }

    /// A hub stalled for longer than the new owner's wait after marking its
    /// ring finds the new owner's ring under the name and leaves both names
    /// alone.
    #[test]
    fn a_hub_stalled_after_its_mark_leaves_a_new_owners_names() {
        let name = unique_name();
        let new = successor_during_release(&name, ReleaseStep::Marked);
        names_are_the_new_owners(&name, &new);
    }

    /// As above, the stall falling after the hub has removed its store's
    /// name: the new owner waits out the old ring's name and makes both
    /// objects, and the old hub leaves the new ring's name alone.
    #[test]
    fn a_hub_stalled_after_its_store_leaves_a_new_owners_ring() {
        let name = unique_name();
        let new = successor_during_release(&name, ReleaseStep::StoreReleased);
        names_are_the_new_owners(&name, &new);
    }

    /// With no new owner, a hub that marked its ring removes both of its names.
    #[test]
    fn a_hub_with_no_successor_removes_both_names() {
        let name = unique_name();
        let names = hub_shm_names(&name).unwrap();
        let hub = PulseHub::create(&name, small_ring()).unwrap();
        drop(hub);
        assert!(matches!(
            PulseRing::open_existing(&names.ring),
            Err(RingError::Open(libc::ENOENT))
        ));
        assert!(EnvelopeStore::open_existing(&names.store).is_err());
    }
}
