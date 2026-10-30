// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A connection's outbound event queue, bounded in events and in bytes, and the
//! daemon-wide budget ([`QueueTotal`]) all the queues share by longest-queue
//! drop, as [`crate::ConnectionPolicy::total_queue_bytes`] states.
//!
//! An event past any bound is dropped and counted for its subscription. An
//! event's JSON is built once per send and shared by the subscriptions it
//! reaches; each connection counts its whole size from queuing until it is
//! written and dropped, and the transports write it without a copy, so the
//! budgets count all the event memory the daemon holds
//! (`tests/event_memory.rs`). Which queue gives up what is checked by the tests
//! below and `tests/fanout.rs`.

use parking_lot::Mutex;
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use tokio::sync::Notify;

/// The most events one connection's queue holds, whatever it is asked for:
/// 1,048,576.
pub const MAX_QUEUE_EVENTS: usize = 1 << 20;

/// How many times in a row an offer may find the largest holder with nothing
/// left to give up (taken meanwhile) before its event is dropped.
const ROOM_ATTEMPTS: usize = 64;

/// A connection's event queue: the sink the bridge offers events to (one clone
/// per subscription) and the end the connection takes them from. It holds at
/// most `events` events, clamped to 1..=[`MAX_QUEUE_EVENTS`], and `bytes`
/// bytes, and charges what it holds to `total`, shared up to `total_bytes`; a
/// zero byte budget drops every event.
#[must_use]
pub(crate) fn event_queue(
    events: usize,
    bytes: usize,
    total: Arc<QueueTotal>,
    total_bytes: usize,
) -> (EventSink, EventQueue) {
    let shared = Arc::new(Shared {
        entries: Mutex::new(VecDeque::new()),
        held: Arc::new(AtomicUsize::new(0)),
        waiting: AtomicUsize::new(0),
        sinks: AtomicUsize::new(1),
        closed: AtomicBool::new(false),
        ready: Notify::new(),
    });
    total.queues.lock().push(Arc::downgrade(&shared));
    (
        EventSink {
            shared: Arc::clone(&shared),
            capacity: events.clamp(1, MAX_QUEUE_EVENTS),
            budget: bytes,
            total: Arc::clone(&total),
            total_budget: total_bytes,
        },
        EventQueue { shared, total },
    )
}

/// The daemon-wide queue budget's state: the bytes queued across all
/// connections, the queues that share it, and the events dropped at it. A
/// daemon has one, in its registry.
#[derive(Debug, Default)]
pub struct QueueTotal {
    held: AtomicUsize,
    dropped: AtomicU64,
    queues: Mutex<Vec<Weak<Shared>>>,
}

impl QueueTotal {
    /// Bytes queued now across the connections, the events being written
    /// included.
    #[must_use]
    pub fn held_bytes(&self) -> usize {
        self.held.load(Ordering::Acquire)
    }

    /// Events dropped at the daemon-wide budget, refused or given up to make
    /// room; each also counts for its subscription.
    #[must_use]
    pub fn events_dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// How many connections' queues share this total now: those made and
    /// not yet closed.
    #[must_use]
    pub fn queues(&self) -> usize {
        self.queues
            .lock()
            .iter()
            .filter(|queue| queue.strong_count() > 0)
            .count()
    }

    /// Count one event dropped at the daemon-wide budget, logging the first
    /// and each doubling after.
    fn count_drop(&self, budget: usize) {
        let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        if dropped.is_power_of_two() {
            tracing::warn!(
                dropped,
                budget,
                "the daemon's queued events reached --total-queue-bytes; an event was \
                 dropped from the connection holding the most or refused to one over its share"
            );
        }
    }

    /// The queue that gives up events for `claimant`: the other queue holding
    /// the most with events waiting (the first made among equals), if it holds
    /// more than `claimant` and `claimant` is within its share of `budget`.
    fn victim(&self, claimant: &Shared, budget: usize) -> Option<Arc<Shared>> {
        let claimed = claimant.held.load(Ordering::Acquire);
        let mut holding = 1usize;
        let mut largest: Option<(usize, Arc<Shared>)> = None;
        {
            let queues = self.queues.lock();
            for queue in queues.iter().filter_map(Weak::upgrade) {
                if std::ptr::eq(Arc::as_ptr(&queue), claimant) {
                    continue;
                }
                let held = queue.held.load(Ordering::Acquire);
                if held == 0 {
                    continue;
                }
                holding += 1;
                let waiting = queue.waiting.load(Ordering::Acquire) > 0;
                if waiting && largest.as_ref().is_none_or(|(most, _)| held > *most) {
                    largest = Some((held, queue));
                }
            }
        }
        if claimed > budget / holding {
            return None;
        }
        largest
            .filter(|(held, _)| *held > claimed)
            .map(|(_, queue)| queue)
    }
}

/// Reserve `amount` against `held`, keeping it within `bound`; `false`,
/// with nothing reserved, when that would pass the bound.
fn reserve(held: &AtomicUsize, amount: usize, bound: usize) -> bool {
    held.fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
        held.checked_add(amount).filter(|&total| total <= bound)
    })
    .is_ok()
}

/// What a connection's sinks and its queue share.
#[derive(Debug)]
struct Shared {
    /// The events waiting to be written, oldest first.
    entries: Mutex<VecDeque<Entry>>,
    /// Bytes charged to the connection: the events waiting and the one
    /// taken and not yet dropped.
    held: Arc<AtomicUsize>,
    /// Events waiting, counted against the queue's `events` as they are
    /// offered, before they are pushed.
    waiting: AtomicUsize,
    /// Sinks alive: the queue ends once they have all gone and it is empty.
    sinks: AtomicUsize,
    /// Set when the connection's end is dropped; offers are refused from
    /// then on.
    closed: AtomicBool,
    /// Wakes the connection's end when an event is queued or the last sink
    /// goes.
    ready: Notify,
}

impl Shared {
    /// The oldest waiting event, for the connection to write.
    fn pop_oldest(&self) -> Option<Entry> {
        let entry = self.entries.lock().pop_front()?;
        self.waiting.fetch_sub(1, Ordering::AcqRel);
        Some(entry)
    }

    /// Give up the newest waiting event, counting it dropped, and return its
    /// bytes, which leave this connection's budget but stay reserved in `total`
    /// for the caller, so no other offer takes the room; `None` when nothing
    /// waits.
    fn give_up_newest(&self, total: &QueueTotal, budget: usize) -> Option<usize> {
        let mut entry = self.entries.lock().pop_back()?;
        self.waiting.fetch_sub(1, Ordering::AcqRel);
        entry.dropped.fetch_add(1, Ordering::Relaxed);
        total.count_drop(budget);
        entry.charge.total = None;
        Some(entry.charge.bytes)
    }
}

/// One event waiting in a queue.
#[derive(Debug)]
struct Entry {
    head: Arc<str>,
    body: Arc<str>,
    /// The drop count of the event's subscription, for an event given up
    /// to make room.
    dropped: Arc<AtomicU64>,
    charge: Charge,
}

/// The bridge's end of a connection's event queue.
#[derive(Debug)]
pub struct EventSink {
    shared: Arc<Shared>,
    /// The most events the queue holds waiting.
    capacity: usize,
    /// The most bytes the connection holds.
    budget: usize,
    /// The bytes queued across the daemon's connections.
    total: Arc<QueueTotal>,
    total_budget: usize,
}

impl Clone for EventSink {
    fn clone(&self) -> Self {
        self.shared.sinks.fetch_add(1, Ordering::Relaxed);
        Self {
            shared: Arc::clone(&self.shared),
            capacity: self.capacity,
            budget: self.budget,
            total: Arc::clone(&self.total),
            total_budget: self.total_budget,
        }
    }
}

impl Drop for EventSink {
    fn drop(&mut self) {
        if self.shared.sinks.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.shared.ready.notify_one();
        }
    }
}

/// What became of an event offered to a queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offer {
    /// Queued for the connection to write.
    Queued,
    /// Dropped at one of the bounds.
    Dropped,
    /// The connection has gone.
    Closed,
}

impl EventSink {
    /// Whether the connection has gone.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::Acquire)
    }

    /// Offer one event, `head` then `body` (shared with the send's other
    /// subscriptions). `dropped` is its subscription's drop count, which the
    /// event keeps in case it is given up later; the caller counts a refusal.
    pub fn offer(&self, head: &Arc<str>, body: &Arc<str>, dropped: &Arc<AtomicU64>) -> Offer {
        let shared = &self.shared;
        if shared.closed.load(Ordering::Acquire) {
            return Offer::Closed;
        }
        let bytes = head.len() + body.len();
        if !reserve(&shared.waiting, 1, self.capacity) {
            return Offer::Dropped;
        }
        if !reserve(&shared.held, bytes, self.budget) {
            shared.waiting.fetch_sub(1, Ordering::AcqRel);
            return Offer::Dropped;
        }
        if !self.reserve_total(bytes) {
            shared.held.fetch_sub(bytes, Ordering::AcqRel);
            shared.waiting.fetch_sub(1, Ordering::AcqRel);
            self.total.count_drop(self.total_budget);
            return Offer::Dropped;
        }
        let entry = Entry {
            head: Arc::clone(head),
            body: Arc::clone(body),
            dropped: Arc::clone(dropped),
            charge: Charge {
                held: Arc::clone(&shared.held),
                total: Some(Arc::clone(&self.total)),
                bytes,
            },
        };
        let mut entries = shared.entries.lock();
        if shared.closed.load(Ordering::Acquire) {
            drop(entries);
            // Its charge goes with it.
            drop(entry);
            shared.waiting.fetch_sub(1, Ordering::AcqRel);
            return Offer::Closed;
        }
        entries.push_back(entry);
        drop(entries);
        shared.ready.notify_one();
        Offer::Queued
    }

    /// Reserve `bytes` of the daemon-wide budget, making room by longest-queue
    /// drop when there is none; `false`, with nothing reserved, when no room
    /// can be had.
    fn reserve_total(&self, bytes: usize) -> bool {
        let (total, budget) = (&self.total, self.total_budget);
        // Bytes of the budget given up to this event so far.
        let mut made = 0usize;
        let mut fruitless = 0usize;
        loop {
            if made >= bytes {
                total.held.fetch_sub(made - bytes, Ordering::AcqRel);
                return true;
            }
            if reserve(&total.held, bytes - made, budget) {
                return true;
            }
            let Some(victim) = total.victim(&self.shared, budget) else {
                total.held.fetch_sub(made, Ordering::AcqRel);
                return false;
            };
            let mut gave = false;
            while victim.held.load(Ordering::Acquire) > self.shared.held.load(Ordering::Acquire) {
                let Some(freed) = victim.give_up_newest(total, budget) else {
                    break;
                };
                made += freed;
                gave = true;
                // Give up no more than the event needs: once what is free
                // covers the rest, take it.
                if made >= bytes {
                    break;
                }
                if reserve(&total.held, bytes - made, budget) {
                    return true;
                }
            }
            if !gave {
                fruitless += 1;
                if fruitless >= ROOM_ATTEMPTS {
                    total.held.fetch_sub(made, Ordering::AcqRel);
                    return false;
                }
            }
        }
    }
}

/// The connection's end of its event queue.
#[derive(Debug)]
pub(crate) struct EventQueue {
    shared: Arc<Shared>,
    total: Arc<QueueTotal>,
}

impl EventQueue {
    /// The next event, waiting for one; `None` once every sink is gone and
    /// the queue is empty.
    pub(crate) async fn recv(&mut self) -> Option<QueuedEvent> {
        loop {
            if let Some(event) = self.try_recv() {
                return Some(event);
            }
            if self.shared.sinks.load(Ordering::Acquire) == 0 {
                // No sink is left to offer anything, and an offer made
                // before the last one went has pushed its event by now.
                return self.try_recv();
            }
            self.shared.ready.notified().await;
        }
    }

    /// The next event if one is waiting.
    pub(crate) fn try_recv(&mut self) -> Option<QueuedEvent> {
        let entry = self.shared.pop_oldest()?;
        Some(QueuedEvent {
            head: entry.head,
            body: entry.body,
            _charge: entry.charge,
        })
    }

    /// Bytes of event JSON the queue holds against its budget: the events
    /// waiting and those taken from it and not yet dropped.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn held_bytes(&self) -> usize {
        self.shared.held.load(Ordering::Acquire)
    }
}

impl Drop for EventQueue {
    fn drop(&mut self) {
        // Offers see the queue closed from here, and nothing is pushed
        // after the events waiting are taken.
        let waiting = {
            let mut entries = self.shared.entries.lock();
            self.shared.closed.store(true, Ordering::Release);
            std::mem::take(&mut *entries)
        };
        self.shared
            .waiting
            .fetch_sub(waiting.len(), Ordering::AcqRel);
        // Their charges go with them.
        drop(waiting);
        let this = Arc::as_ptr(&self.shared);
        self.total
            .queues
            .lock()
            .retain(|queue| queue.strong_count() > 0 && !std::ptr::eq(queue.as_ptr(), this));
    }
}

/// One event on its way to one subscription, its bytes counted against both
/// budgets until it drops, once written.
#[derive(Debug)]
pub(crate) struct QueuedEvent {
    head: Arc<str>,
    body: Arc<str>,
    _charge: Charge,
}

impl QueuedEvent {
    /// The opening of the event's JSON, which names its subscription.
    #[must_use]
    pub(crate) fn head(&self) -> &str {
        &self.head
    }

    /// The rest of the event's JSON after [`QueuedEvent::head`], shared by
    /// every subscription the send reached.
    #[must_use]
    pub(crate) fn body(&self) -> &str {
        &self.body
    }

    /// The event's whole JSON, as a copy the budgets do not count.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn to_json(&self) -> String {
        let mut json = String::with_capacity(self.head.len() + self.body.len());
        json.push_str(&self.head);
        json.push_str(&self.body);
        json
    }

    /// The length of that JSON in bytes, what the event counts against its
    /// connection's budget.
    #[must_use]
    pub(crate) fn bytes(&self) -> usize {
        self.head.len() + self.body.len()
    }

    /// The subscription the event is for, as its head names it (JSON-escaped,
    /// as it is written); `None` for a health notice, which names none.
    #[must_use]
    pub(crate) fn subscription_id(&self) -> Option<&str> {
        self.head
            .strip_prefix(r#"{"op":"event","subscription_id":""#)?
            .strip_suffix(r#"","#)
    }
}

/// Bytes held against a connection's budget and the daemon's, given back
/// when dropped.
#[derive(Debug)]
struct Charge {
    held: Arc<AtomicUsize>,
    /// The daemon-wide total, or `None` once the bytes have passed there
    /// to another connection's event.
    total: Option<Arc<QueueTotal>>,
    bytes: usize,
}

impl Drop for Charge {
    fn drop(&mut self) {
        self.held.fetch_sub(self.bytes, Ordering::AcqRel);
        if let Some(total) = &self.total {
            total.held.fetch_sub(self.bytes, Ordering::AcqRel);
        }
    }
}

/// The opening of every event for the subscription `id`:
/// `{"op":"event","subscription_id":"<id>",`.
pub(crate) fn event_head(id: &str) -> Arc<str> {
    // Serialising a string cannot fail; an empty id would still be JSON.
    let id = serde_json::to_string(id).unwrap_or_else(|_| "\"\"".to_string());
    Arc::from(format!(r#"{{"op":"event","subscription_id":{id},"#))
}

/// An event's fields after its subscription id, in `ServerMessage::Event`'s
/// order, so that head and body together are that message's JSON.
#[derive(Debug, Serialize)]
pub(crate) struct EventFields<'a> {
    pub(crate) envelope_id: &'a str,
    pub(crate) channel: &'a str,
    pub(crate) type_id: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) type_name: Option<&'a str>,
    pub(crate) origin: &'a str,
    pub(crate) captured_at_unix_nanos: u64,
    pub(crate) payload: &'a str,
}

impl EventFields<'_> {
    /// The event after its subscription id, closing brace included, made once
    /// per send; `None` only if serialising failed, which it cannot here.
    pub(crate) fn body(&self) -> Option<Arc<str>> {
        let json = serde_json::to_string(self).ok()?;
        json.strip_prefix('{').map(Arc::from)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::protocol::ServerMessage;

    /// Offer an event of `body` to `sink`, counting a drop in `dropped`.
    fn offer_counted(sink: &EventSink, body: &str, dropped: &Arc<AtomicU64>) -> Offer {
        sink.offer(&event_head("sub-1"), &Arc::from(body), dropped)
    }

    fn event(sink: &EventSink, body: &str) -> Offer {
        offer_counted(sink, body, &Arc::default())
    }

    /// A body that makes an event of exactly `bytes` bytes.
    fn body_of(bytes: usize) -> String {
        "x".repeat(bytes - event_head("sub-1").len())
    }

    /// A queue of `events` events and `bytes` bytes on a daemon-wide total
    /// of its own with no budget to speak of.
    fn queue(events: usize, bytes: usize) -> (EventSink, EventQueue) {
        event_queue(events, bytes, Arc::default(), usize::MAX)
    }

    #[test]
    fn head_and_body_are_the_protocols_event_message() {
        for (channel, type_name, origin) in [
            ("jobs/new", None, "worker@3f9a0b1c"),
            (
                "a \"quoted\"\\ channel",
                Some("job.créé"),
                "tab\there@00000000",
            ),
        ] {
            let fields = EventFields {
                envelope_id: "9c1d",
                channel,
                type_id: 7,
                type_name,
                origin,
                captured_at_unix_nanos: 1_758_700_000_000_000_000,
                payload: "aGVsbG8=",
            };
            let (sink, mut queue) = queue(4, usize::MAX);
            let head = event_head("sub-hub-00000001");
            assert_eq!(
                sink.offer(&head, &fields.body().unwrap(), &Arc::default()),
                Offer::Queued
            );
            let event = queue.try_recv().unwrap();
            let json = event.to_json();
            assert_eq!(format!("{}{}", event.head(), event.body()), json);
            let message = ServerMessage::Event {
                subscription_id: "sub-hub-00000001".into(),
                envelope_id: "9c1d".into(),
                channel: channel.into(),
                type_id: 7,
                type_name: type_name.map(String::from),
                origin: origin.into(),
                captured_at_unix_nanos: 1_758_700_000_000_000_000,
                payload: "aGVsbG8=".into(),
            };
            assert_eq!(json, serde_json::to_string(&message).unwrap());
            assert_eq!(event.subscription_id(), Some("sub-hub-00000001"));
            assert_eq!(event.bytes(), json.len());
        }
    }

    /// An event names the subscription it is for, and a health notice, which
    /// shares the queue, names none.
    #[test]
    fn an_event_names_its_subscription_and_a_health_notice_none() {
        let (sink, mut queue) = queue(4, usize::MAX);
        let dropped = Arc::default();
        for head in [
            event_head("sub-a-0000000f"),
            Arc::from(r#"{"op":"health","#),
        ] {
            assert_eq!(
                sink.offer(&head, &Arc::from(r#""node_id":"n@00"}"#), &dropped),
                Offer::Queued
            );
        }
        assert_eq!(
            queue.try_recv().unwrap().subscription_id(),
            Some("sub-a-0000000f")
        );
        assert_eq!(queue.try_recv().unwrap().subscription_id(), None);
    }

    #[test]
    fn the_queue_holds_at_most_its_bytes_and_gives_them_back_once_an_event_is_dropped() {
        let body = body_of(100);
        let (sink, mut queue) = queue(1024, 250);
        assert_eq!(event(&sink, &body), Offer::Queued);
        assert_eq!(event(&sink, &body), Offer::Queued);
        assert_eq!(queue.held_bytes(), 200);
        assert_eq!(
            event(&sink, &body),
            Offer::Dropped,
            "a third would hold 300"
        );
        assert_eq!(queue.held_bytes(), 200, "a dropped event holds nothing");
        let taken = queue.try_recv().unwrap();
        assert_eq!(taken.bytes(), 100);
        assert_eq!(queue.held_bytes(), 200, "held while it is written");
        drop(taken);
        assert_eq!(queue.held_bytes(), 100);
        assert_eq!(event(&sink, &body), Offer::Queued);
    }

    #[test]
    fn the_queue_holds_at_most_its_events() {
        let (sink, mut queue) = queue(2, usize::MAX);
        assert_eq!(event(&sink, "{}"), Offer::Queued);
        assert_eq!(event(&sink, "{}"), Offer::Queued);
        assert_eq!(event(&sink, "{}"), Offer::Dropped);
        // The event being written takes no place among the waiting.
        let taken = queue.try_recv().unwrap();
        assert_eq!(event(&sink, "{}"), Offer::Queued);
        drop(taken);
    }

    #[test]
    fn the_queues_of_a_daemon_hold_at_most_its_total_between_them() {
        let body = body_of(100);
        let total = Arc::new(QueueTotal::default());
        // Each queue may hold a thousand bytes; together they may hold 250.
        let (first, mut first_queue) = event_queue(1024, 1000, Arc::clone(&total), 250);
        let (second, mut second_queue) = event_queue(1024, 1000, Arc::clone(&total), 250);
        assert_eq!(event(&first, &body), Offer::Queued);
        assert_eq!(event(&second, &body), Offer::Queued);
        assert_eq!(total.held_bytes(), 200);
        // Each would hold 200, more than its share of 125: only what is
        // free, and nothing is.
        assert_eq!(
            event(&first, &body),
            Offer::Dropped,
            "a third would hold 300"
        );
        assert_eq!(event(&second, &body), Offer::Dropped);
        assert_eq!(total.events_dropped(), 2);
        assert_eq!(
            first_queue.held_bytes(),
            100,
            "a refused event holds nothing"
        );
        assert_eq!(total.held_bytes(), 200);
        // An event written and dropped gives its bytes back to both budgets.
        drop(second_queue.try_recv().unwrap());
        assert_eq!((second_queue.held_bytes(), total.held_bytes()), (0, 100));
        assert_eq!(event(&first, &body), Offer::Queued);
        drop(first_queue.try_recv().unwrap());
        drop(first_queue.try_recv().unwrap());
        assert_eq!(total.held_bytes(), 0);
        assert_eq!(
            total.events_dropped(),
            2,
            "only drops at the total count there"
        );
    }

    #[test]
    fn a_queue_within_its_share_takes_room_from_the_one_holding_the_most() {
        let total = Arc::new(QueueTotal::default());
        let (slow, mut slow_queue) = event_queue(1024, 1000, Arc::clone(&total), 300);
        let (fast, mut fast_queue) = event_queue(1024, 1000, Arc::clone(&total), 300);
        let slow_dropped = Arc::new(AtomicU64::new(0));
        // The slow connection fills the whole budget while nobody else
        // holds anything: three events, the last one marked.
        assert_eq!(
            offer_counted(&slow, &body_of(100), &slow_dropped),
            Offer::Queued
        );
        assert_eq!(
            offer_counted(&slow, &body_of(100), &slow_dropped),
            Offer::Queued
        );
        let newest = format!("{}z", &body_of(99));
        assert_eq!(offer_counted(&slow, &newest, &slow_dropped), Offer::Queued);
        assert_eq!(total.held_bytes(), 300);

        // The fast one, within its share of 150 with the event, is not
        // refused: the slow one gives up its newest waiting event.
        let fast_dropped = Arc::new(AtomicU64::new(0));
        assert_eq!(
            offer_counted(&fast, &body_of(100), &fast_dropped),
            Offer::Queued
        );
        assert_eq!(slow_queue.held_bytes(), 200);
        assert_eq!(fast_queue.held_bytes(), 100);
        assert_eq!(total.held_bytes(), 300);
        assert_eq!(
            slow_dropped.load(Ordering::Relaxed),
            1,
            "counted for its subscription"
        );
        assert_eq!(fast_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(total.events_dropped(), 1, "and at the total");

        // It was the newest that went: the rest come out in order.
        let first = slow_queue.try_recv().unwrap();
        let second = slow_queue.try_recv().unwrap();
        assert!(!first.body().ends_with('z') && !second.body().ends_with('z'));
        assert!(slow_queue.try_recv().is_none());

        // Once the fast one has written its event, the next takes room the
        // same way, from the one that holds the most.
        drop(fast_queue.try_recv().unwrap());
        drop((first, second));
        assert_eq!(total.held_bytes(), 0);
    }

    #[test]
    fn a_queue_gives_up_no_more_than_the_arriving_event_needs() {
        let total = Arc::new(QueueTotal::default());
        let (slow, _slow_queue) = event_queue(1024, 1000, Arc::clone(&total), 350);
        let (fast, fast_queue) = event_queue(1024, 1000, Arc::clone(&total), 350);
        let dropped: Vec<Arc<AtomicU64>> = (0..6).map(|_| Arc::default()).collect();
        for counter in &dropped {
            assert_eq!(offer_counted(&slow, &body_of(50), counter), Offer::Queued);
        }
        // 300 of 350 bytes are held: an event of 100 needs 50 more, one of
        // the slow connection's events, and the rest is free already.
        assert_eq!(event(&fast, &body_of(100)), Offer::Queued);
        let lost: Vec<u64> = dropped.iter().map(|d| d.load(Ordering::Relaxed)).collect();
        assert_eq!(lost, [0, 0, 0, 0, 0, 1], "the newest, and only it");
        assert_eq!(total.events_dropped(), 1);
        assert_eq!((fast_queue.held_bytes(), total.held_bytes()), (100, 350));
    }

    #[test]
    fn the_earliest_opened_of_those_holding_the_most_gives_up_room() {
        let total = Arc::new(QueueTotal::default());
        let ends: Vec<(EventSink, EventQueue, Arc<AtomicU64>)> = (0..3)
            .map(|_| {
                let (sink, queue) = event_queue(1024, 1000, Arc::clone(&total), 300);
                (sink, queue, Arc::default())
            })
            .collect();
        // The first two hold as much; the third arrives.
        for (sink, _, counter) in &ends[..2] {
            assert_eq!(offer_counted(sink, &body_of(100), counter), Offer::Queued);
            assert_eq!(offer_counted(sink, &body_of(50), counter), Offer::Queued);
        }
        assert_eq!(event(&ends[2].0, &body_of(50),), Offer::Queued);
        let lost: Vec<u64> = ends
            .iter()
            .map(|(_, _, d)| d.load(Ordering::Relaxed))
            .collect();
        assert_eq!(lost, [1, 0, 0], "the first opened gives up its newest");
    }

    #[test]
    fn a_queue_over_its_share_gets_only_what_is_free() {
        let total = Arc::new(QueueTotal::default());
        let (a, a_queue) = event_queue(1024, 1000, Arc::clone(&total), 300);
        let (b, b_queue) = event_queue(1024, 1000, Arc::clone(&total), 300);
        for _ in 0..3 {
            assert_eq!(event(&a, &body_of(100)), Offer::Queued);
        }
        assert_eq!(event(&b, &body_of(100)), Offer::Queued, "within its share");
        // With a second event, the second queue would hold 200, more than
        // its share of 150: it is refused, and nothing is given up for it.
        assert_eq!(event(&b, &body_of(100)), Offer::Dropped);
        assert_eq!((a_queue.held_bytes(), b_queue.held_bytes()), (200, 100));
        // Nor does the first, which holds more than its share already.
        assert_eq!(event(&a, &body_of(100)), Offer::Dropped);
        assert_eq!(total.events_dropped(), 3);
    }

    #[test]
    fn the_event_being_written_is_never_given_up() {
        let total = Arc::new(QueueTotal::default());
        let (a, mut a_queue) = event_queue(1024, 1000, Arc::clone(&total), 300);
        let (b, _b_queue) = event_queue(1024, 1000, Arc::clone(&total), 300);
        assert_eq!(event(&a, &body_of(250)), Offer::Queued);
        let writing = a_queue.try_recv().unwrap();
        // The only bytes the first queue holds are being written: nothing
        // can be given up, and the event does not fit.
        assert_eq!(event(&b, &body_of(100)), Offer::Dropped);
        assert_eq!(a_queue.held_bytes(), 250);
        drop(writing);
        assert_eq!(event(&b, &body_of(100)), Offer::Queued);
    }

    #[test]
    fn an_event_larger_than_the_total_gives_up_nothing_of_anyone_else() {
        let total = Arc::new(QueueTotal::default());
        let (a, a_queue) = event_queue(1024, 1000, Arc::clone(&total), 300);
        let (b, _b_queue) = event_queue(1024, 1000, Arc::clone(&total), 300);
        assert_eq!(event(&a, &body_of(100)), Offer::Queued);
        assert_eq!(event(&a, &body_of(100)), Offer::Queued);
        assert_eq!(event(&b, &body_of(400)), Offer::Dropped);
        assert_eq!(a_queue.held_bytes(), 200, "nothing given up for it");
    }

    #[test]
    fn concurrent_offers_keep_the_total_within_its_budget_and_every_event_accounted_for() {
        use std::sync::atomic::AtomicBool;
        let budget = 64 * 1024;
        let total = Arc::new(QueueTotal::default());
        let queues: Vec<(EventSink, EventQueue, Arc<AtomicU64>)> = (0..8)
            .map(|_| {
                let (sink, queue) = event_queue(64, 16 * 1024, Arc::clone(&total), budget);
                (sink, queue, Arc::default())
            })
            .collect();
        let (sinks, mut ends): (Vec<_>, Vec<_>) = queues
            .into_iter()
            .map(|(sink, queue, dropped)| ((sink, dropped), queue))
            .unzip();
        let sinks = Arc::new(sinks);
        let offered: Arc<Vec<AtomicU64>> = Arc::new((0..8).map(|_| AtomicU64::new(0)).collect());
        let done = Arc::new(AtomicBool::new(false));
        // Half the queues are read as fast as events come; half never are.
        let readers: Vec<_> = ends
            .drain(..4)
            .map(|mut queue| {
                let done = Arc::clone(&done);
                std::thread::spawn(move || {
                    let mut taken = 0u64;
                    while !done.load(Ordering::Acquire) {
                        match queue.try_recv() {
                            Some(_) => taken += 1,
                            None => std::thread::yield_now(),
                        }
                    }
                    while queue.try_recv().is_some() {
                        taken += 1;
                    }
                    taken
                })
            })
            .collect();
        let writers: Vec<_> = (0..4u64)
            .map(|w| {
                let (sinks, offered) = (Arc::clone(&sinks), Arc::clone(&offered));
                std::thread::spawn(move || {
                    let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ (w + 1);
                    for _ in 0..5_000 {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        let q = (state % 8) as usize;
                        let size = [60usize, 300, 2_000, 9_000][(state >> 8) as usize % 4];
                        let (sink, dropped) = &sinks[q];
                        offered[q].fetch_add(1, Ordering::Relaxed);
                        if offer_counted(sink, &body_of(size), dropped) == Offer::Dropped {
                            dropped.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                })
            })
            .collect();
        while writers.iter().any(|w| !w.is_finished()) {
            assert!(total.held_bytes() <= budget, "{} held", total.held_bytes());
            std::thread::yield_now();
        }
        for writer in writers {
            writer.join().unwrap();
        }
        done.store(true, Ordering::Release);
        let mut taken: Vec<u64> = readers.into_iter().map(|r| r.join().unwrap()).collect();
        for mut queue in ends {
            let mut n = 0;
            while queue.try_recv().is_some() {
                n += 1;
            }
            taken.push(n);
        }
        assert_eq!(total.held_bytes(), 0, "every byte was given back");
        assert!(total.events_dropped() > 0, "the budget was contended");
        for q in 0..8 {
            assert_eq!(
                taken[q] + sinks[q].1.load(Ordering::Relaxed),
                offered[q].load(Ordering::Relaxed),
                "queue {q}: every event taken or counted as dropped"
            );
        }
        assert!(
            taken[..4].iter().sum::<u64>() > taken[4..].iter().sum::<u64>(),
            "the queues read keep up: {taken:?}"
        );
    }

    #[test]
    fn a_closed_queue_gives_its_bytes_back_and_leaves_the_total() {
        let total = Arc::new(QueueTotal::default());
        let (sink, queue) = event_queue(1024, 1000, Arc::clone(&total), 1000);
        assert_eq!(event(&sink, &body_of(100)), Offer::Queued);
        assert_eq!(total.queues.lock().len(), 1);
        drop(queue);
        assert_eq!(total.held_bytes(), 0);
        assert!(total.queues.lock().is_empty());
        assert!(sink.is_closed());
        assert_eq!(event(&sink, &body_of(100)), Offer::Closed);
    }

    #[tokio::test]
    async fn recv_waits_for_an_event_and_ends_once_every_sink_is_gone() {
        let (sink, mut queue) = queue(8, usize::MAX);
        let second = sink.clone();
        let offering = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert_eq!(event(&second, "{}"), Offer::Queued);
        });
        assert!(queue.recv().await.is_some(), "woken by the offer");
        offering.await.unwrap();
        assert_eq!(event(&sink, "{}"), Offer::Queued);
        drop(sink);
        assert!(queue.recv().await.is_some(), "what was queued comes first");
        assert!(queue.recv().await.is_none(), "then the end");
    }

    #[test]
    fn a_queue_asked_for_more_events_than_it_may_hold_is_capped() {
        let (sink, _receiver) = queue(usize::MAX, usize::MAX);
        for _ in 0..3 {
            assert_eq!(event(&sink, "{}"), Offer::Queued);
        }
        assert_eq!(sink.capacity, MAX_QUEUE_EVENTS);
    }

    #[test]
    fn a_budget_of_zero_drops_every_event_and_a_closed_queue_says_so() {
        let (sink, receiver) = queue(8, 0);
        assert_eq!(event(&sink, "{}"), Offer::Dropped);
        drop(receiver);
        assert!(sink.is_closed());
        assert_eq!(event(&sink, "{}"), Offer::Closed);
    }
}
