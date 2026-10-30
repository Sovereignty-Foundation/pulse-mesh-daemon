// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! How often a summary is sent (ADR-0021, item 4), and an announcement of
//! clients with it (item 6).

use std::num::NonZeroU32;
use std::time::{Duration, Instant};

use crate::{Announcement, Interest};

/// Summaries a [`SummaryPacer`] sends in a second at most, by default.
pub const DEFAULT_SUMMARIES_PER_SECOND: u32 = 4;

/// How long a [`SummaryPacer`] waits, by default, after its last summary
/// before it sends the latest one again: 5 seconds.
pub const DEFAULT_REFRESH: Duration = Duration::from_secs(5);

const DEFAULT_RATE: NonZeroU32 = match NonZeroU32::new(DEFAULT_SUMMARIES_PER_SECOND) {
    Some(rate) => rate,
    None => NonZeroU32::MIN,
};

/// How a [`SummaryPacer`] paces summaries.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PacerConfig {
    /// The most summaries sent in a second: consecutive ones are at least
    /// a second divided by this apart. [`DEFAULT_SUMMARIES_PER_SECOND`] by
    /// default.
    pub max_per_second: NonZeroU32,
    /// Send the latest summary again, at its generation, when this long
    /// has passed since one was sent, so that a peer which lost it catches
    /// up; a peer that has it ignores the copy. Links run over lossy UDP, so
    /// this is on by default, every [`DEFAULT_REFRESH`] (5 seconds) while
    /// nothing changes, at a cost of one summary per peer per period;
    /// `None` turns it off ([`PacerConfig::without_refresh`]). A refresh
    /// counts against [`PacerConfig::max_per_second`] like any summary.
    pub refresh: Option<Duration>,
}

impl Default for PacerConfig {
    fn default() -> Self {
        Self {
            max_per_second: DEFAULT_RATE,
            refresh: Some(DEFAULT_REFRESH),
        }
    }
}

impl PacerConfig {
    /// This configuration sending at most `max_per_second` summaries a
    /// second.
    #[must_use]
    pub fn with_max_per_second(mut self, max_per_second: NonZeroU32) -> Self {
        self.max_per_second = max_per_second;
        self
    }

    /// This configuration sending the latest summary again after `every`
    /// without one.
    #[must_use]
    pub fn with_refresh(mut self, every: Duration) -> Self {
        self.refresh = Some(every);
        self
    }

    /// This configuration sending each summary once, for a link that
    /// loses nothing.
    #[must_use]
    pub fn without_refresh(mut self) -> Self {
        self.refresh = None;
        self
    }
}

/// What a [`SummaryPacer`] paces: a value a daemon replaces whole when it
/// changes and stamps with a generation as it sends it, so that a receiver
/// keeps the newest. An [`Interest`] summary is one, and an
/// [`Announcement`] of clients another.
pub trait Paced: Clone {
    /// Whether `other` says what this says, whatever their generations.
    fn same_as(&self, other: &Self) -> bool;

    /// The same value at `generation`.
    #[must_use]
    fn at_generation(self, generation: u64) -> Self;
}

impl Paced for Interest {
    fn same_as(&self, other: &Self) -> bool {
        self.same_summary(other)
    }

    fn at_generation(self, generation: u64) -> Self {
        self.with_generation(generation)
    }
}

impl Paced for Announcement {
    fn same_as(&self, other: &Self) -> bool {
        self.same_nodes(other)
    }

    fn at_generation(self, generation: u64) -> Self {
        self.with_generation(generation)
    }
}

/// Coalesces a daemon's changes of interest into the summaries it sends a
/// peer: at most [`PacerConfig::max_per_second`] in a second, and always,
/// in the end, the latest. A daemon paces its announcements of clients
/// ([`Announcement`]) with a pacer of their own, by the same rules.
///
/// The daemon reports each new summary with [`SummaryPacer::changed`] and
/// asks [`SummaryPacer::poll`] what to send, now or at
/// [`SummaryPacer::next_due`]. A change that arrives inside the interval
/// replaces the one waiting, so a burst of subscribes costs one summary; a
/// change back to what was last sent cancels the one waiting. Each summary
/// sent is stamped with the next generation, from 1, so the receiver can
/// tell the newest; while nothing changes, the latest is sent again at its
/// generation every [`PacerConfig::refresh`]. The pacer reads no clock: the caller passes the time,
/// and the tests pass made-up times.
#[derive(Debug, Clone)]
pub struct SummaryPacer<T = Interest> {
    interval: Duration,
    refresh: Option<Duration>,
    pending: Option<T>,
    sent: Option<(Instant, T)>,
    generation: u64,
}

impl<T: Paced> SummaryPacer<T> {
    /// A pacer that has sent nothing.
    #[must_use]
    pub fn new(config: &PacerConfig) -> Self {
        Self {
            interval: Duration::from_secs(1) / config.max_per_second.get(),
            refresh: config.refresh,
            pending: None,
            sent: None,
            generation: 0,
        }
    }

    /// The shortest time between two summaries.
    #[must_use]
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// The summary is now `interest`; its generation is ignored.
    pub fn changed(&mut self, interest: T) {
        let unchanged = self
            .sent
            .as_ref()
            .is_some_and(|(_, sent)| sent.same_as(&interest));
        self.pending = if unchanged { None } else { Some(interest) };
    }

    /// The summary to send at `now`, if one is due: the latest change,
    /// stamped with the next generation, or a refresh of the last one.
    pub fn poll(&mut self, now: Instant) -> Option<T> {
        if now < self.next_due(now)? {
            return None;
        }
        let summary = match self.pending.take() {
            Some(pending) => {
                self.generation = self.generation.saturating_add(1);
                pending.at_generation(self.generation)
            }
            None => self.sent.as_ref()?.1.clone(),
        };
        self.sent = Some((now, summary.clone()));
        Some(summary)
    }

    /// When [`SummaryPacer::poll`] next has a summary to send, `now` when
    /// one is due already, or `None` when nothing is waiting and no
    /// refresh is configured.
    #[must_use]
    pub fn next_due(&self, now: Instant) -> Option<Instant> {
        let Some((at, _)) = &self.sent else {
            return self.pending.as_ref().map(|_| now);
        };
        let wait = if self.pending.is_some() {
            self.interval
        } else {
            self.refresh?.max(self.interval)
        };
        at.checked_add(wait).map(|due| due.max(now))
    }

    /// The generation of the last summary sent; 0 before the first.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use mesh_port_protocol::FilterSpec;
    use proptest::prelude::*;

    fn on(channel: &str) -> Interest {
        Interest::from_filters(&[FilterSpec {
            channel: Some(channel.into()),
            ..FilterSpec::default()
        }])
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn a_burst_of_changes_costs_one_summary_per_interval() {
        let t0 = Instant::now();
        let mut pacer = SummaryPacer::new(&PacerConfig::default());
        assert_eq!(pacer.interval(), ms(250));
        assert_eq!(pacer.poll(t0), None, "nothing to send yet");
        pacer.changed(on("a"));
        let first = pacer.poll(t0).unwrap();
        assert!(first.same_summary(&on("a")));
        assert_eq!(first.generation(), 1);
        pacer.changed(on("b"));
        pacer.changed(on("c"));
        assert_eq!(pacer.poll(t0 + ms(100)), None, "inside the interval");
        assert_eq!(pacer.next_due(t0 + ms(100)), Some(t0 + ms(250)));
        let second = pacer.poll(t0 + ms(250)).unwrap();
        assert!(
            second.same_summary(&on("c")),
            "the latest, not the first waiting"
        );
        assert_eq!(second.generation(), 2);
        assert_eq!(pacer.poll(t0 + ms(900)), None);
        // On by default: the latest again, five seconds after it was sent.
        assert_eq!(PacerConfig::default().refresh, Some(DEFAULT_REFRESH));
        assert_eq!(DEFAULT_REFRESH, ms(5_000));
        assert_eq!(pacer.next_due(t0 + ms(900)), Some(t0 + ms(5_250)));
        assert_eq!(pacer.poll(t0 + ms(5_249)), None);
        assert_eq!(pacer.poll(t0 + ms(5_250)), Some(second));
        assert_eq!(pacer.generation(), 2);
    }

    #[test]
    fn an_announcement_is_paced_by_the_same_rules() {
        use crate::{DaemonId, QualifiedOrigin};
        let node = |name: &str| QualifiedOrigin::new(DaemonId::from_bytes([1; 8]), name).unwrap();
        let t0 = Instant::now();
        let mut pacer: SummaryPacer<Announcement> = SummaryPacer::new(&PacerConfig::default());
        pacer.changed(Announcement::new([node("a")].into_iter().collect()));
        let first = pacer.poll(t0).unwrap();
        assert_eq!(first.generation(), 1);
        pacer.changed(Announcement::new(
            [node("a"), node("b")].into_iter().collect(),
        ));
        assert_eq!(pacer.poll(t0 + ms(100)), None, "inside the interval");
        let second = pacer.poll(t0 + ms(250)).unwrap();
        assert_eq!((second.generation(), second.nodes().len()), (2, 2));
        pacer.changed(second.clone().with_generation(0));
        assert_eq!(
            pacer.next_due(t0 + ms(250)),
            Some(t0 + ms(5_250)),
            "no change"
        );
        assert_eq!(pacer.poll(t0 + ms(5_250)), Some(second), "the refresh");
    }

    #[test]
    fn without_refresh_a_summary_is_sent_once() {
        let t0 = Instant::now();
        let mut pacer = SummaryPacer::new(&PacerConfig::default().without_refresh());
        pacer.changed(on("a"));
        pacer.poll(t0).unwrap();
        assert_eq!(pacer.next_due(t0 + ms(60_000)), None);
        assert_eq!(pacer.poll(t0 + ms(60_000)), None);
    }

    #[test]
    fn a_change_back_to_what_was_sent_cancels_the_one_waiting() {
        let t0 = Instant::now();
        let mut pacer = SummaryPacer::new(&PacerConfig::default());
        pacer.changed(on("a"));
        pacer.poll(t0).unwrap();
        pacer.changed(on("b"));
        pacer.changed(on("a"));
        assert_eq!(
            pacer.next_due(t0),
            Some(t0 + DEFAULT_REFRESH),
            "only the refresh"
        );
        assert_eq!(pacer.poll(t0 + ms(500)), None);
        assert_eq!(pacer.generation(), 1);
    }

    #[test]
    fn a_refresh_sends_the_last_summary_again_at_its_generation() {
        let t0 = Instant::now();
        let config = PacerConfig::default()
            .with_max_per_second(NonZeroU32::new(10).unwrap())
            .with_refresh(ms(1_000));
        let mut pacer = SummaryPacer::new(&config);
        pacer.changed(on("a"));
        let first = pacer.poll(t0).unwrap();
        assert_eq!(pacer.poll(t0 + ms(999)), None);
        assert_eq!(pacer.poll(t0 + ms(1_000)), Some(first.clone()));
        assert_eq!(pacer.next_due(t0 + ms(1_000)), Some(t0 + ms(2_000)));
        assert_eq!(first.generation(), pacer.generation());
    }

    proptest! {
        /// Whatever the changes, the times polled and the refresh period,
        /// none included: consecutive summaries are an interval apart, each
        /// is a new generation one above the last or a refresh of the last
        /// at its generation, and polling when next due leaves the latest
        /// change sent.
        #[test]
        fn summaries_are_spaced_and_the_latest_is_sent_in_the_end(
            rate in 1u32..20,
            refresh in proptest::option::of(0u64..3_000),
            steps in proptest::collection::vec((0u64..400, proptest::option::of(0u8..4)), 1..60),
        ) {
            let t0 = Instant::now();
            let config = PacerConfig::default().with_max_per_second(NonZeroU32::new(rate).unwrap());
            let config = match refresh {
                Some(every) => config.with_refresh(ms(every)),
                None => config.without_refresh(),
            };
            let mut pacer = SummaryPacer::new(&config);
            let mut now = t0;
            let mut sent: Vec<(Instant, Interest)> = Vec::new();
            let mut latest = None;
            for (advance, change) in steps {
                now += ms(advance);
                if let Some(c) = change {
                    let interest = on(&c.to_string());
                    pacer.changed(interest.clone());
                    latest = Some(interest);
                }
                if let Some(summary) = pacer.poll(now) {
                    sent.push((now, summary));
                }
            }
            if let Some(due) = pacer.next_due(now) {
                let summary = pacer.poll(due).unwrap();
                sent.push((due, summary));
            }
            if refresh.is_none() {
                prop_assert_eq!(pacer.next_due(now + ms(10_000)), None);
            }
            for pair in sent.windows(2) {
                prop_assert!(pair[1].0 - pair[0].0 >= pacer.interval());
                let (before, after) = (&pair[0].1, &pair[1].1);
                if after.generation() == before.generation() {
                    prop_assert!(refresh.is_some(), "a repeat without a refresh");
                    prop_assert_eq!(after, before);
                } else {
                    prop_assert_eq!(after.generation(), before.generation() + 1);
                }
            }
            if let Some(latest) = latest {
                let (_, last) = sent.last().unwrap();
                prop_assert!(last.same_summary(&latest));
            }
        }
    }
}
