// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A hub created fresh replaces the objects an earlier owner left behind
//! and unlinks its own when it drops, and while it lives a second owner of
//! its name is refused before it touches them.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_ring::{PulseRing, RingError};
use core_store::{EnvelopeStore, EnvelopeStoreError};
use mesh_hub_runtime::{hub_shm_names, HubConfig, PulseHub};
use pulse_canon::{Instruction, Pulse, PulseEnvelope};

/// `ENOENT` on every platform this crate builds for.
const ENOENT: i32 = 2;

/// A hub name of at most fifteen characters, unique per test and process.
fn hub_name(tag: &str) -> String {
    format!("{tag}{:08x}", std::process::id())
}

/// Slots in the store of the hub each test creates: a few are enough, and
/// they keep the test within a container's small `/dev/shm`.
const STORE_SLOTS: usize = 16;

fn config() -> HubConfig {
    HubConfig::default()
        .with_ring_size(64)
        .with_store_slots(STORE_SLOTS)
}

#[test]
fn create_fresh_replaces_objects_left_by_a_dead_owner() {
    let name = hub_name("fresh-a");
    let names = hub_shm_names(&name).unwrap();

    // A daemon killed outright never drops its handles, so its objects stay
    // behind with their state: leak a ring holding three pulses and a store
    // holding one envelope.
    let mut leaked_ring = PulseRing::create_exclusive(&names.ring, 64).unwrap();
    let mut pulse = Pulse::zeroed();
    pulse.instruction = Instruction::Data as u16;
    for _ in 0..3 {
        leaked_ring.publish(&pulse);
    }
    std::mem::forget(leaked_ring);
    let leaked_store = EnvelopeStore::create_exclusive(&names.store, 4).unwrap();
    leaked_store
        .store(&PulseEnvelope::typed("left.behind", b"x".to_vec()))
        .unwrap();
    std::mem::forget(leaked_store);

    let hub = PulseHub::create_fresh(&name, config()).expect("a fresh hub over stale objects");
    assert_eq!(
        hub.ring().cursor_position(),
        0,
        "the ring is new, not the leaked one"
    );
    assert_eq!(
        hub.store_slots(),
        Some(STORE_SLOTS),
        "the store is new, not the leaked one of four slots"
    );

    drop(hub);
    assert!(
        matches!(
            PulseRing::open(&names.ring, 64),
            Err(RingError::Open(ENOENT))
        ),
        "the ring name is gone after the owner drops"
    );
    assert!(
        matches!(
            EnvelopeStore::open_existing(&names.store),
            Err(EnvelopeStoreError::Open(ENOENT))
        ),
        "the store name is gone after the owner drops"
    );
}

#[test]
fn create_fresh_on_a_clean_name_owns_and_unlinks() {
    let name = hub_name("fresh-b");
    let names = hub_shm_names(&name).unwrap();
    assert!(matches!(
        PulseRing::open(&names.ring, 64),
        Err(RingError::Open(ENOENT))
    ));

    let hub = PulseHub::create_fresh(&name, config()).unwrap();
    PulseRing::open(&names.ring, 64)
        .expect("another process can open the ring while the hub lives");
    drop(hub);

    assert!(matches!(
        PulseRing::open(&names.ring, 64),
        Err(RingError::Open(ENOENT))
    ));
}

#[test]
fn unlink_reports_whether_anything_existed() {
    let name = format!("/pms-unl{:08x}", std::process::id());
    assert!(!PulseRing::unlink(&name).unwrap());
    let ring = PulseRing::create_exclusive(&name, 8).unwrap();
    std::mem::forget(ring);
    assert!(PulseRing::unlink(&name).unwrap());
    assert!(!PulseRing::unlink(&name).unwrap());
}

#[test]
fn a_second_owner_of_a_live_hub_is_refused_and_touches_nothing() {
    use mesh_broadcast::ListenFilter;
    use mesh_hub_runtime::owner::{hub_lock_path, lock_holder};
    use mesh_hub_runtime::OwnerError;
    use pulse_canon::NodeId;
    use std::sync::{Arc, Mutex};

    let name = hub_name("fresh-c");
    let names = hub_shm_names(&name).unwrap();
    let mut first = PulseHub::create_fresh(&name, config()).unwrap();
    let mut reader = PulseHub::open(&name, config()).unwrap();
    let payloads = Arc::new(Mutex::new(Vec::new()));
    let sink = payloads.clone();
    reader.listen(NodeId::from_name("r"), ListenFilter::All, move |e| {
        sink.lock().unwrap().push(e.payload().to_bytes())
    });
    let origin = NodeId::from_name("o");
    first
        .broadcast_envelope(PulseEnvelope::typed("app/before", vec![1]), &origin)
        .unwrap();
    assert_eq!(
        lock_holder(&hub_lock_path(&name).unwrap()).unwrap(),
        Some(mesh_hub_runtime::owner::LockHolder {
            pid: Some(std::process::id())
        }),
        "the owner's lock names this process"
    );

    // A second owner, as a second daemon or embedded mesh would make.
    match PulseHub::create_fresh(&name, config()) {
        Err(OwnerError::Owned { hub, pid }) => {
            assert_eq!(hub, name);
            assert_eq!(pid, Some(std::process::id()));
        }
        Err(other) => panic!("expected Owned, got {other}"),
        Ok(_) => panic!("a second owner of a live hub must be refused"),
    }

    // The first hub's ring and store are the ones it made, and they serve.
    let ring = PulseRing::open(&names.ring, 64).expect("the first hub's ring is still named");
    assert_eq!(ring.cursor_position(), 1, "its ring holds its one signal");
    let store = EnvelopeStore::open_existing(&names.store).expect("and its store");
    assert_eq!(store.capacity(), STORE_SLOTS);
    first
        .broadcast_envelope(PulseEnvelope::typed("app/after", vec![2]), &origin)
        .unwrap();
    assert_eq!(reader.poll(), 2);
    assert_eq!(*payloads.lock().unwrap(), vec![vec![1u8], vec![2u8]]);
    assert_eq!(reader.unfetched_envelopes(), 0);

    // Once the first owner has gone, the name is free for the next.
    drop(first);
    assert_eq!(lock_holder(&hub_lock_path(&name).unwrap()).unwrap(), None);
    assert!(
        !hub_lock_path(&name).unwrap().exists(),
        "the owner removes its lock file as it lets go"
    );
    let next = PulseHub::create_fresh(&name, config()).expect("the next owner starts");
    assert!(next.is_writer());
}

#[test]
fn an_owner_whose_lock_file_was_removed_leaves_the_next_owners_objects_alone() {
    use mesh_hub_runtime::owner::hub_lock_path;

    let name = hub_name("fresh-d");
    let names = hub_shm_names(&name).unwrap();
    let first = PulseHub::create_fresh(&name, config()).unwrap();
    // A cleaner removes the lock file, and before the first owner puts it
    // back a second owner takes the name, replacing the ring and the store.
    std::fs::remove_file(hub_lock_path(&name).unwrap()).unwrap();
    let second_config = config().with_store_slots(2);
    let second = PulseHub::create_fresh(&name, second_config).expect("the lock file was gone");

    // The first owner exits: its ring was marked by the second, and its
    // store is no longer the one under the name, so both names stay the
    // second owner's.
    drop(first);
    let attached = PulseHub::open(&name, config()).expect("the second owner's ring is named");
    assert!(!attached.is_writer());
    assert_eq!(attached.ring().cursor_position(), 0);
    assert_eq!(
        attached.store_slots(),
        Some(2),
        "the second owner's store is still under the name"
    );
    drop(attached);

    drop(second);
    assert!(matches!(
        PulseRing::open(&names.ring, 64),
        Err(RingError::Open(ENOENT))
    ));
    assert!(matches!(
        EnvelopeStore::open_existing(&names.store),
        Err(EnvelopeStoreError::Open(ENOENT))
    ));
}
