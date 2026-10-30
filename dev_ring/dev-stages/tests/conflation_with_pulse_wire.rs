// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! `ConflationRing` over a real `PulseRing`: N publishes to a key drain as one
//! delivery of the latest payload.

use core_ring::PulseRing;
use dev_stages::conflation::{BytesExtractor, ConflationRing};

fn make_ring(name: &str) -> PulseRing {
    PulseRing::create(name, 1024).expect("create ring")
}

/// Build a 120-byte logical payload: [symbol_id u32 | price_cents u64 | zero...].
fn payload_for(symbol_id: u32, price_cents: u64) -> [u8; 120] {
    let mut p = [0u8; 120];
    p[0..4].copy_from_slice(&symbol_id.to_le_bytes());
    p[4..12].copy_from_slice(&price_cents.to_le_bytes());
    p
}

fn read_price(payload: &[u8]) -> u64 {
    let mut p = [0u8; 8];
    p.copy_from_slice(&payload[4..12]);
    u64::from_le_bytes(p)
}

#[test]
fn n_publishes_one_key_collapses_to_one_drain() {
    let name = format!("/test-conflation-{}", std::process::id());
    let ring = make_ring(&name);
    let mut conflation = ConflationRing::new(ring, BytesExtractor::<0, 4>);

    let symbol_aapl: u32 = 1;
    for tick in 0..100u64 {
        let p = payload_for(symbol_aapl, 15000 + tick);
        conflation.publish(&p).expect("publish");
    }
    assert_eq!(
        conflation.tracked_keys(),
        1,
        "100 AAPL ticks → 1 tracked key"
    );

    let mut delivered = 0usize;
    let mut last_price: u64 = 0;
    let drained = conflation.drain_latest(10, |key, payload| {
        delivered += 1;
        assert_eq!(*key, symbol_aapl as u64);
        last_price = read_price(payload);
    });

    assert_eq!(drained, 1);
    assert_eq!(
        delivered, 1,
        "100 publishes for AAPL collapse to 1 drain entry"
    );
    assert_eq!(
        last_price,
        15000 + 99,
        "drain reports the most recent price"
    );
    assert_eq!(
        conflation.tracked_keys(),
        0,
        "drain clears the per-key index"
    );
}

#[test]
fn three_keys_drained_independently() {
    let name = format!("/test-conflation-3k-{}", std::process::id());
    let ring = make_ring(&name);
    let mut conflation = ConflationRing::new(ring, BytesExtractor::<0, 4>);

    for tick in 0..30u64 {
        for sym in [1u32, 2, 3] {
            conflation
                .publish(&payload_for(sym, 10000 + (sym as u64 * 1000) + tick))
                .expect("publish");
        }
    }
    assert_eq!(conflation.tracked_keys(), 3);

    let mut seen = std::collections::HashMap::<u64, u64>::new();
    let drained = conflation.drain_latest(100, |key, payload| {
        seen.insert(*key, read_price(payload));
    });

    assert_eq!(drained, 3);
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[&1], 10000 + 1000 + 29);
    assert_eq!(seen[&2], 10000 + 2000 + 29);
    assert_eq!(seen[&3], 10000 + 3000 + 29);
}

#[test]
fn second_epoch_is_independent_of_first() {
    let name = format!("/test-conflation-epoch-{}", std::process::id());
    let ring = make_ring(&name);
    let mut conflation = ConflationRing::new(ring, BytesExtractor::<0, 4>);

    conflation.publish(&payload_for(1, 100)).unwrap();
    conflation.publish(&payload_for(1, 200)).unwrap();

    let mut first_epoch_price = 0u64;
    let n1 = conflation.drain_latest(10, |_k, payload| first_epoch_price = read_price(payload));
    assert_eq!(n1, 1);
    assert_eq!(first_epoch_price, 200);

    conflation.publish(&payload_for(1, 999)).unwrap();
    let mut second_epoch_price = 0u64;
    let n2 = conflation.drain_latest(10, |_k, payload| second_epoch_price = read_price(payload));
    assert_eq!(n2, 1);
    assert_eq!(second_epoch_price, 999);
    assert_eq!(conflation.current_epoch(), 2);
}

#[test]
fn payload_too_large_rejected() {
    let name = format!("/test-conflation-toobig-{}", std::process::id());
    let ring = make_ring(&name);
    let mut conflation = ConflationRing::new(ring, BytesExtractor::<0, 4>);

    let big = [0u8; 200]; // > MAX_LOGICAL_PAYLOAD
    let result = conflation.publish(&big);
    assert!(matches!(
        result,
        Err(dev_stages::conflation::ConflationError::PayloadTooLarge { got: 200 })
    ));
}
