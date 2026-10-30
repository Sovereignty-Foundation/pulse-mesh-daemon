// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The hop limit a forwarded pulse carries in its `chain_step` (ADR-0021,
//! item 5). A daemon forwards its own clients' sends with a limit of
//! [`ORIGIN_HOP_LIMIT`], two; a relay (item 9) spends one hop to pass a
//! send on, and passes it on only while a hop is left after that, so a send
//! crosses at most one relay. On a pulse a link forwards, `chain_step` is
//! the hops it may still take; other carriers use the field for their own
//! ends (core-ring marks overruns in it), so it means a hop limit on
//! forwarded pulses alone.

use std::num::NonZeroU64;

use pulse_canon::Pulse;

/// The hop limit a forward leaves its origin daemon with: 2. The peer it
/// goes to delivers it, and, when that peer is a relay, may pass it on once
/// more ([`next_hop`]), after which no hop is left and no daemon forwards it
/// again.
pub const ORIGIN_HOP_LIMIT: u64 = 2;

/// The hops a forwarded pulse may still take, `None` at zero: a daemon
/// delivers such a pulse to its own subscribers and forwards it no further.
///
/// The hop limit is `chain_step` on a pulse a link forwards, and nothing
/// else: other carriers use the field for their own ends (core-ring marks
/// overruns in it). A forward from a build before relays carries 0.
#[must_use]
pub fn hops_left(pulse: &Pulse) -> Option<NonZeroU64> {
    NonZeroU64::new(pulse.chain_step)
}

/// `pulse` with a hop limit of `hops`, as the daemon that forwards it
/// first sets it.
#[must_use]
pub fn with_hop_limit(mut pulse: Pulse, hops: u64) -> Pulse {
    pulse.chain_step = hops;
    pulse
}

/// `pulse` as it is forwarded one hop further, its hop limit one less, or
/// `None` when the limit is zero and it goes no further.
#[must_use]
pub fn next_hop(pulse: &Pulse) -> Option<Pulse> {
    let hops = hops_left(pulse)?;
    Some(with_hop_limit(*pulse, hops.get() - 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pulse_takes_as_many_hops_as_its_limit_and_no_more() {
        let mut pulse = with_hop_limit(Pulse::zeroed(), ORIGIN_HOP_LIMIT);
        let mut hops = 0;
        while let Some(next) = next_hop(&pulse) {
            pulse = next;
            hops += 1;
        }
        assert_eq!(hops, 2);
        assert_eq!(hops_left(&pulse), None);
        assert_eq!(next_hop(&Pulse::zeroed()), None);
        let one = with_hop_limit(Pulse::zeroed(), 1);
        assert_eq!(hops_left(&one).map(NonZeroU64::get), Some(1));
        // A relay passes on what has a hop left after its own: from the
        // origin's limit, once.
        let relayed = next_hop(&with_hop_limit(Pulse::zeroed(), ORIGIN_HOP_LIMIT));
        assert_eq!(
            relayed.and_then(|p| hops_left(&p)).map(NonZeroU64::get),
            Some(1)
        );
        assert_eq!(
            relayed
                .and_then(|p| next_hop(&p))
                .and_then(|p| hops_left(&p)),
            None
        );
    }
}
