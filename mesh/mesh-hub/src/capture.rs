// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The basket's own thread. Every capture and every retention sweep runs
//! there, behind a queue bounded in captures and in bytes, so a SQLite write
//! never runs on the runtime's workers and a slow disk never holds up a send:
//! a capture that finds the queue full is dropped and counted, and the
//! envelope is still delivered.

use mesh_basket::{Basket, CaptureMeta, RetentionPolicy};
use pulse_canon::PulseEnvelope;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Captures the queue holds before it drops the next one.
pub(crate) const CAPTURE_QUEUE: usize = 1024;

/// Payload bytes the queue holds before it drops the next capture.
pub(crate) const CAPTURE_QUEUE_BYTES: usize = 64 << 20;

/// What the thread is asked to do.
enum Job {
    /// Insert one envelope, whose payload is `bytes` long.
    Capture {
        envelope: PulseEnvelope,
        meta: CaptureMeta,
        bytes: usize,
    },
    /// Answer once every job queued before this one is done.
    #[cfg(test)]
    Flush(SyncSender<()>),
}

/// The handle the bridge holds: dropping it drains the queue into the basket
/// and joins the thread.
pub(crate) struct Capture {
    jobs: Option<SyncSender<Job>>,
    thread: Option<JoinHandle<()>>,
    queued_bytes: Arc<AtomicUsize>,
    dropped: AtomicU64,
}

impl Capture {
    /// Start the thread that owns `basket`, inserting what it is offered and
    /// sweeping the basket with the default retention policy every
    /// `sweep_every`.
    ///
    /// # Errors
    ///
    /// The operating system's error when the thread cannot be started.
    pub(crate) fn start(basket: Basket, sweep_every: Duration) -> std::io::Result<Self> {
        let (jobs, queue) = mpsc::sync_channel(CAPTURE_QUEUE);
        let queued_bytes = Arc::new(AtomicUsize::new(0));
        let queued = Arc::clone(&queued_bytes);
        let thread = std::thread::Builder::new()
            .name("pms-basket".into())
            .spawn(move || run(&basket, &queue, &queued, sweep_every))?;
        Ok(Self {
            jobs: Some(jobs),
            thread: Some(thread),
            queued_bytes,
            dropped: AtomicU64::new(0),
        })
    }

    /// Queue `envelope` for the basket without waiting. With the queue full,
    /// in captures or in bytes, the capture is dropped and counted; the count
    /// is logged at the first drop and at each doubling.
    pub(crate) fn offer(&self, envelope: PulseEnvelope, meta: CaptureMeta) {
        let bytes = envelope.payload_len();
        let before = self.queued_bytes.fetch_add(bytes, Ordering::Relaxed);
        let queued = before.saturating_add(bytes) <= CAPTURE_QUEUE_BYTES
            && self.jobs.as_ref().is_some_and(|jobs| {
                jobs.try_send(Job::Capture {
                    envelope,
                    meta,
                    bytes,
                })
                .is_ok()
            });
        if !queued {
            self.queued_bytes.fetch_sub(bytes, Ordering::Relaxed);
            let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if dropped.is_power_of_two() {
                tracing::warn!(dropped, "basket capture queue full: captures dropped");
            }
        }
    }

    /// Captures dropped so far because the queue was full.
    #[cfg(test)]
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Wait until every capture queued so far is in the basket.
    #[cfg(test)]
    pub(crate) fn flush(&self) {
        let (done, wait) = mpsc::sync_channel(1);
        if let Some(jobs) = &self.jobs {
            if jobs.send(Job::Flush(done)).is_ok() {
                let _ = wait.recv();
            }
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        // With the sender gone the thread drains what is queued and returns.
        drop(self.jobs.take());
        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() {
                tracing::error!("the basket thread panicked");
            }
        }
    }
}

/// The thread: insert each capture in turn, and sweep whenever a sweep is due,
/// even while captures keep arriving. An interval too long to add to the
/// clock means no sweep.
fn run(basket: &Basket, queue: &Receiver<Job>, queued: &AtomicUsize, sweep_every: Duration) {
    let policy = RetentionPolicy::default();
    let due = || Instant::now().checked_add(sweep_every);
    let mut next_sweep = due();
    loop {
        if next_sweep.is_some_and(|at| Instant::now() >= at) {
            match basket.retention_sweep(&policy) {
                Ok(n) if n > 0 => tracing::debug!(deleted = n, "basket retention sweep"),
                Ok(_) => {}
                Err(e) => tracing::warn!(error = ?e, "basket retention sweep failed"),
            }
            next_sweep = due();
        }
        let job = match next_sweep {
            Some(at) => queue.recv_timeout(at.saturating_duration_since(Instant::now())),
            None => queue.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        match job {
            Ok(Job::Capture {
                envelope,
                meta,
                bytes,
            }) => {
                if let Err(e) = basket.insert(&envelope, meta) {
                    tracing::warn!(error = ?e, "basket insert failed (continuing)");
                }
                queued.fetch_sub(bytes, Ordering::Relaxed);
            }
            #[cfg(test)]
            Ok(Job::Flush(done)) => {
                let _ = done.send(());
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}
