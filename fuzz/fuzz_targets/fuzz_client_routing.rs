// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// Fuzz target: the Rust client's handling of one connection,
// `mesh_client::client::Router`: the driver the connection's task runs, with
// the far ends of its outbox and its dispatch queue in place of the
// transport's writer and the dispatch thread, and the command queue the
// callers hand their calls to. It parks each call's reply under its request
// id, takes a call only while the outbox has room, forgets or abandons the
// calls that time out when their doorbell rings, keeps at most a cap of
// requests nobody waits on, routes every message from the daemon (a reply
// to its call, late replies counted, an event to the dispatch queue) and
// decides how the connection's end is reported. It is the client's whole
// handling of server messages, driven here without a socket.
//
// The input is a run: the attach, then calls the client makes (send,
// subscribe, unsubscribe, detach), offered to the command queue, one at a
// time or in a burst, and those the full queue refuses either waiting for
// room or giving up at their deadlines; turns of the driver, each settling
// what the calls that rang the doorbell left behind and taking a call while
// the outbox has room; callers timing out, wherever their calls wait (for
// room, in the queue, or for their replies), which withdraw their requests
// unless the writer has taken them, close their reply channels, take a
// reply that raced the deadline and ring the doorbell; the writer taking
// frames, in any order with the timeouts and the turns, as the writer's
// task, the callers' threads and the driver interleave; messages from the
// daemon (acks and errors naming a waiting request, an answered, withdrawn
// or forgotten one, one never made, or none, with any fields; events for a
// subscription the client holds or another, with a payload in the
// protocol's base64 or not; health notices; challenges, which the run's
// attach, carrying no key, leaves unanswered; frames of text parsed as a
// `ServerMessage` the way the reader parses them); and the dispatch thread
// taking the queued events. The cap on requests nobody waits on is the
// input's, zero to eight, where a client keeps 4,096, so that a run reaches
// it.
//
// The oracle is a model of the client's documented rules (SAF-30, SAF-40,
// SAF-78), written without the code under test.
//
// Invariants:
// - the command queue holds at most `COMMAND_QUEUE` calls, in order; a call
//   offered to a full queue is refused, and its caller either waits for
//   room, which the driver's taking a call gives the oldest waiting caller
//   first, or gives up at its deadline with `QueueFull` naming its
//   operation, having sent nothing;
// - a turn of the driver sweeps exactly when a caller that timed out
//   without an answer rang the doorbell since the last turn, and then takes
//   the oldest queued call exactly when fewer than `OUTBOUND_QUEUE` requests
//   wait for the writer; releases do not count against the depth;
// - requests are numbered in order, `req-1` the attach; each queued call
//   and each release is written exactly once, in order, unless its caller
//   gave up before the writer took it: then it is never written, whether
//   or not a sweep came between, an unsubscribe excepted, which always is;
//   a call whose caller gave up before the driver took it is never queued
//   for the writer, an unsubscribe excepted;
// - a sweep forgets the calls whose requests were withdrawn, removing
//   their frames if the writer has not skipped them, and abandons the
//   calls whose callers gave up after the writer took their requests, and
//   unsubscribes;
// - at most the cap of requests nobody waits on, abandoned calls and
//   releases together, are kept, the oldest forgotten first; a reply naming
//   a forgotten one names no request the driver holds;
// - a call whose caller waits gets exactly one answer: the first ack or
//   error naming its request, as its kind of call reads it (the ack's
//   envelope id, `persisted` and `delivered` for a send, its subscription
//   id for a subscribe, its drop count or zero for an unsubscribe) or the
//   daemon's error, `AuthFailed` for the code `auth_failed` and `Daemon`
//   for every other; or, when none came, the connection's end; a caller
//   that times out takes a reply that raced the deadline; a call still in
//   the command queue is answered by nothing the driver does;
// - a reply to a call whose caller had given up is counted late and
//   answers nobody; a late subscribe ack registers nothing and queues an
//   unsubscribe of the subscription it names, whose own reply answers
//   nobody and is not late; a late detach ack still ends the connection
//   cleanly;
// - an ack or error naming no request the driver holds answers nothing;
//   such an error is the connection's end reason until another message
//   follows it;
// - a subscribe's ack registers the subscription it names, before any
//   event after it is routed;
// - an event is queued, in order, exactly when its payload is valid base64
//   and the queue has room: fewer events than its depth, and bytes for it
//   within the budget, an event counting its payload and its text fields
//   and holding them until the dispatch thread has run it; one with an
//   invalid payload is counted malformed and one without room dropped;
//   replies never wait for room;
// - the connection ends cleanly exactly when the daemon acknowledged a
//   detach and said nothing unanswered after it; otherwise every caller
//   the driver holds and still waiting gets the reason: the daemon's
//   parting error, or `Disconnected`.

#![no_main]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use libfuzzer_sys::arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use mesh_client::client::{Call, Router, Waiter, COMMAND_QUEUE, OUTBOUND_QUEUE};
use mesh_client::{DevError, MeshEvent, SendReceipt, SubscriptionId, TapFilter};
use mesh_port_protocol::{base64, AckFields, ClientMessage, ServerMessage};
use pulse_mesh_fuzz::take;
use serde_json::Value;

/// Most steps in one run.
const MAX_STEPS: usize = 384;

/// Most calls in one burst, and most turns of the driver in one step: more
/// than both queues hold, so a few steps fill them.
const MAX_BURST: usize = 80;

/// The largest cap on requests nobody waits on a run chooses.
const MAX_CAP: usize = 8;

/// A call's operation, as its request and its errors name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Attach,
    Send,
    Subscribe,
    Unsubscribe,
    Detach,
}

impl Op {
    fn name(self) -> &'static str {
        match self {
            Op::Attach => "attach",
            Op::Send => "send",
            Op::Subscribe => "subscribe",
            Op::Unsubscribe => "unsubscribe",
            Op::Detach => "detach",
        }
    }
}

/// A caller's end of its call, by kind.
enum Rx {
    Unit(Waiter<()>),
    Send(Waiter<SendReceipt>),
    Subscribe(Waiter<SubscriptionId>),
    Unsubscribe(Waiter<u64>),
}

/// An answer as text: `Ok(..)` or `Err(..)` with the value's Debug form.
fn text<T: std::fmt::Debug>(answer: Option<std::result::Result<T, DevError>>) -> Option<String> {
    answer.map(|answer| match answer {
        Ok(v) => format!("Ok({v:?})"),
        Err(e) => format!("Err({e:?})"),
    })
}

impl Rx {
    /// The answer that has come, as text; `None` when none has.
    fn peek(&mut self) -> Option<String> {
        match self {
            Rx::Unit(rx) => text(rx.try_answer()),
            Rx::Send(rx) => text(rx.try_answer()),
            Rx::Subscribe(rx) => text(rx.try_answer()),
            Rx::Unsubscribe(rx) => text(rx.try_answer()),
        }
    }

    /// The caller times out, as a call does at its deadline: it withdraws
    /// its request unless the writer has taken it, closes its channel, so
    /// the driver can no longer answer it, and rings the doorbell when no
    /// answer had come. Returns an answer that had come, as text.
    fn time_out(&mut self, router: &Router) -> Option<String> {
        match self {
            Rx::Unit(rx) => text(router.time_out(rx)),
            Rx::Send(rx) => text(router.time_out(rx)),
            Rx::Subscribe(rx) => text(router.time_out(rx)),
            Rx::Unsubscribe(rx) => text(router.time_out(rx)),
        }
    }
}

/// A request the driver holds, as the model sees it.
enum Held {
    /// A call: its operation, its caller's end, whether the caller gave up
    /// before any reply, and whether its request was withdrawn, which it is
    /// when its caller gave up before the writer took it (an unsubscribe's
    /// never is).
    Call {
        op: Op,
        rx: Rx,
        gone: bool,
        withdrawn: bool,
    },
    /// A call whose caller gave up, abandoned by a sweep.
    Abandoned(Op),
    /// The client's own unsubscribe releasing a subscription.
    Release,
}

impl Held {
    /// Whether nobody waits for its reply: what the cap counts.
    fn unwaited(&self) -> bool {
        matches!(self, Held::Abandoned(_) | Held::Release)
    }
}

/// A call in the command queue, as the model sees it.
struct Queued {
    op: Op,
    rx: Rx,
    /// The subscription an unsubscribe names.
    subscription: Option<String>,
    /// Whether its caller timed out while it waited here.
    gone: bool,
}

/// A caller waiting for room in the command queue, holding its call.
struct Waiting {
    call: Call,
    op: Op,
    rx: Rx,
    subscription: Option<String>,
}

/// A frame waiting for the writer, as the model sees it.
struct Frame {
    request: u64,
    op: &'static str,
    /// The subscription an unsubscribe names.
    subscription: Option<String>,
    /// Whether it counts against `OUTBOUND_QUEUE`: a caller's request.
    counted: bool,
    /// Whether its caller withdrew it: the writer skips it.
    withdrawn: bool,
}

/// The model of the client's rules.
struct Model {
    next_request: u64,
    held: BTreeMap<u64, Held>,
    outbox: VecDeque<Frame>,
    /// The command queue, oldest first.
    commands: VecDeque<Queued>,
    /// The callers waiting for room there, oldest first.
    waiting: VecDeque<Waiting>,
    /// A caller that timed out without an answer rang the doorbell since
    /// the driver's last turn.
    rang: bool,
    /// Most requests nobody waits on kept.
    cap: usize,
    /// Calls answered whose callers have not collected the answer yet.
    answered: Vec<(Rx, String)>,
    subscribed: BTreeSet<String>,
    queued: Vec<(String, Vec<u8>)>,
    depth: usize,
    /// The bytes the queue may hold, and those its events hold.
    budget: usize,
    queued_bytes: usize,
    late: u64,
    dropped: u64,
    malformed: u64,
    detached: bool,
    last_word: Option<(String, String)>,
    /// Numbers of requests the driver no longer holds.
    retired: Vec<u64>,
}

fuzz_target!(|data: &[u8]| {
    let _ = fuzz(data);
});

fn fuzz(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    let depth = u.int_in_range(0..=4usize)?;
    // Unbounded now and then; otherwise about what a few events hold.
    let budget = if u.ratio(1, 4)? {
        usize::MAX
    } else {
        u.int_in_range(0..=160usize)?
    };
    let cap = u.int_in_range(0..=MAX_CAP)?;
    let mut router = Router::with_max_abandoned(depth, budget, cap);
    let mut m = Model {
        next_request: 1,
        held: BTreeMap::new(),
        outbox: VecDeque::new(),
        commands: VecDeque::new(),
        waiting: VecDeque::new(),
        rang: false,
        cap,
        answered: Vec::new(),
        subscribed: BTreeSet::new(),
        queued: Vec::new(),
        depth: depth.max(1),
        budget,
        queued_bytes: 0,
        late: 0,
        dropped: 0,
        malformed: 0,
        detached: false,
        last_word: None,
        retired: Vec::new(),
    };

    let attach = router.attach("fuzz").expect("an attach serialises");
    m.queue(Op::Attach, Rx::Unit(attach), None);
    check(&mut router, &mut m, Outbox::All);

    for _ in 0..MAX_STEPS {
        if u.is_empty() {
            break;
        }
        // What the step may have done to the outbox, and so how much of it
        // to compare: the whole of it after a turn, whose sweep withdraws
        // from anywhere in it, and after a burst; the newest frame after
        // anything else that queues one (a late subscribe ack's release).
        let mut outbox = Outbox::Newest;
        match u.int_in_range(0..=17u8)? {
            0..=2 => {
                let wait = u.ratio(3, 4)?;
                call(&mut u, &mut router, &mut m, wait)?;
            }
            3 => {
                let wait = u.ratio(1, 2)?;
                for _ in 0..u.int_in_range(1..=MAX_BURST)? {
                    let (call, rx) = Call::send("burst", b"");
                    offer(
                        &mut router,
                        &mut m,
                        call,
                        Op::Send,
                        Rx::Send(rx),
                        None,
                        wait,
                    );
                }
                outbox = Outbox::All;
            }
            4 | 5 => time_out(&mut u, &router, &mut m)?,
            6 | 7 => {
                for _ in 0..u.int_in_range(1..=MAX_BURST)? {
                    turn(&mut router, &mut m);
                }
                outbox = Outbox::All;
            }
            8 | 9 => {
                let got = router.write_next();
                let want = m.write_next();
                match (got, want) {
                    (None, None) => {}
                    (Some(text), Some(frame)) => check_frame(&text, &frame),
                    (got, want) => panic!(
                        "the writer took {got:?} where the model has {:?}",
                        want.map(|f| f.request)
                    ),
                }
            }
            10 => {
                // The dispatch thread takes what is queued, and runs it.
                let got: Vec<(String, Vec<u8>)> = router
                    .take_events()
                    .into_iter()
                    .map(|event: MeshEvent| (event.subscription_id.0, event.payload))
                    .collect();
                assert_eq!(
                    got, m.queued,
                    "the events queued are not the valid events routed, in order"
                );
                m.queued.clear();
                m.queued_bytes = 0;
            }
            11 => {
                // Callers collect their answers.
                for (mut rx, want) in m.answered.drain(..) {
                    assert_eq!(rx.peek(), Some(want), "a caller found another answer");
                }
            }
            12 => {
                // A frame of text, parsed as the reader parses one.
                let text = u.arbitrary::<&str>()?;
                if let Ok(msg) = serde_json::from_str::<ServerMessage>(text) {
                    m.route(&msg);
                    router.route(msg);
                }
            }
            _ => {
                let msg = message(&mut u, &m)?;
                m.route(&msg);
                router.route(msg);
            }
        }
        check(&mut router, &mut m, outbox);
    }
    check(&mut router, &mut m, Outbox::All);

    // The connection ends.
    let ended = router.conclude();
    let reason = match (&m.last_word, m.detached) {
        (None, true) => {
            assert!(
                ended.is_ok(),
                "an acknowledged detach did not end cleanly: {ended:?}"
            );
            None
        }
        (Some((code, message)), _) => Some(daemon(code, message)),
        (None, false) => Some(format!("{:?}", DevError::Disconnected)),
    };
    for (mut rx, want) in m.answered.drain(..) {
        assert_eq!(rx.peek(), Some(want), "a caller found another answer");
    }
    if let Some(reason) = reason {
        assert_eq!(
            ended.as_ref().err().map(|e| format!("{e:?}")),
            Some(reason.clone()),
            "the end reason"
        );
        for (request, held) in &mut m.held {
            if let Held::Call { rx, gone, .. } = held {
                let got = rx.peek();
                if *gone {
                    assert_eq!(got, None, "req-{request} was answered after it gave up");
                } else {
                    assert_eq!(
                        got,
                        Some(format!("Err({reason})")),
                        "req-{request} was not told the end"
                    );
                }
            }
        }
    }
    // The driver answers nothing it never took.
    for queued in &mut m.commands {
        assert_eq!(queued.rx.peek(), None, "a call still queued was answered");
    }
    for waiting in &mut m.waiting {
        assert_eq!(waiting.rx.peek(), None, "a call never queued was answered");
    }
    Ok(())
}

impl Model {
    /// Queue a request under the next number, as the driver's `submit`
    /// does.
    fn queue(&mut self, op: Op, rx: Rx, subscription: Option<String>) -> u64 {
        let request = self.next_request;
        self.next_request += 1;
        self.held.insert(
            request,
            Held::Call {
                op,
                rx,
                gone: false,
                withdrawn: false,
            },
        );
        self.outbox.push_back(Frame {
            request,
            op: op.name(),
            subscription,
            counted: true,
            withdrawn: false,
        });
        request
    }

    /// Queue the client's own unsubscribe of `subscription`, which counts
    /// against the cap.
    fn release(&mut self, subscription: String) {
        let request = self.next_request;
        self.next_request += 1;
        self.held.insert(request, Held::Release);
        self.outbox.push_back(Frame {
            request,
            op: "unsubscribe",
            subscription: Some(subscription),
            counted: false,
            withdrawn: false,
        });
        self.forget_excess();
    }

    /// Requests waiting for the writer that count against the depth.
    fn requests(&self) -> usize {
        self.outbox.iter().filter(|f| f.counted).count()
    }

    /// The driver's sweep: forget the calls whose requests were withdrawn,
    /// removing their frames if the writer has not skipped them, abandon
    /// the rest of the calls whose callers gave up, and keep at most the
    /// cap of requests nobody waits on.
    fn sweep(&mut self) {
        let mut forgotten = Vec::new();
        for (&request, held) in &mut self.held {
            if let Held::Call {
                op,
                gone: true,
                withdrawn,
                ..
            } = held
            {
                if *withdrawn {
                    forgotten.push(request);
                } else {
                    let op = *op;
                    *held = Held::Abandoned(op);
                }
            }
        }
        for request in forgotten {
            self.held.remove(&request);
            self.retired.push(request);
            self.outbox.retain(|frame| frame.request != request);
        }
        self.forget_excess();
    }

    /// Forget the oldest requests nobody waits on while there are more than
    /// the cap. Their frames, if the writer has not taken them, stay.
    fn forget_excess(&mut self) {
        loop {
            let unwaited: Vec<u64> = self
                .held
                .iter()
                .filter(|(_, held)| held.unwaited())
                .map(|(&request, _)| request)
                .collect();
            if unwaited.len() <= self.cap {
                break;
            }
            self.held.remove(&unwaited[0]);
            self.retired.push(unwaited[0]);
        }
    }

    /// One turn of the driver: sweep if the doorbell rang, then take the
    /// oldest queued call while the outbox has room, dropping it when its
    /// caller gave up (an unsubscribe excepted), and give the room it
    /// leaves in the queue to the oldest caller waiting for it. Whether it
    /// took a call.
    fn turn(&mut self) -> Option<Option<Waiting>> {
        if std::mem::take(&mut self.rang) {
            self.sweep();
        }
        if self.requests() >= OUTBOUND_QUEUE {
            return None;
        }
        let queued = self.commands.pop_front()?;
        if !(queued.gone && queued.op != Op::Unsubscribe) {
            let request = self.queue(queued.op, queued.rx, queued.subscription);
            if queued.gone {
                if let Some(Held::Call { gone, .. }) = self.held.get_mut(&request) {
                    *gone = true;
                }
            }
        }
        Some(self.waiting.pop_front())
    }

    /// The frame the writer takes next: the oldest, withdrawn ones skipped
    /// and gone.
    fn write_next(&mut self) -> Option<Frame> {
        while let Some(frame) = self.outbox.pop_front() {
            if !frame.withdrawn {
                return Some(frame);
            }
        }
        None
    }

    /// Route one message as the client's rules say.
    fn route(&mut self, msg: &ServerMessage) {
        let request = |id: &Option<String>| -> Option<u64> {
            id.as_deref()?.strip_prefix("req-")?.parse().ok()
        };
        match msg {
            ServerMessage::Ack { id, fields } => {
                let taken = request(id).and_then(|r| self.held.remove(&r).map(|h| (r, h)));
                let mut detached = false;
                if let Some((r, held)) = taken {
                    self.retired.push(r);
                    match held {
                        Held::Release => {}
                        Held::Abandoned(op) => {
                            self.late += 1;
                            self.after_late(op, fields, &mut detached);
                        }
                        Held::Call {
                            op, rx, gone: true, ..
                        } => {
                            drop(rx);
                            self.late += 1;
                            self.after_late(op, fields, &mut detached);
                        }
                        Held::Call {
                            op,
                            rx,
                            gone: false,
                            ..
                        } => {
                            let answer = match op {
                                Op::Attach => "Ok(())".to_owned(),
                                // `SendReceipt` is non-exhaustive, so its
                                // Debug form stands for it.
                                Op::Send => format!(
                                    "Ok(SendReceipt {{ envelope_id: {:?}, persisted: {:?}, delivered: {:?} }})",
                                    fields.envelope_id.clone().unwrap_or_default(),
                                    fields.persisted,
                                    fields.delivered
                                ),
                                Op::Subscribe => {
                                    let sub = fields.subscription_id.clone().unwrap_or_default();
                                    self.subscribed.insert(sub.clone());
                                    format!("Ok({:?})", SubscriptionId(sub))
                                }
                                Op::Unsubscribe => {
                                    format!("Ok({})", fields.events_dropped.unwrap_or(0))
                                }
                                Op::Detach => {
                                    detached = true;
                                    "Ok(())".to_owned()
                                }
                            };
                            self.answered.push((rx, answer));
                        }
                    }
                }
                if detached {
                    self.detached = true;
                }
                self.last_word = None;
            }
            ServerMessage::Error { id, code, message } => {
                match request(id).and_then(|r| self.held.remove(&r).map(|h| (r, h))) {
                    Some((r, held)) => {
                        self.retired.push(r);
                        match held {
                            Held::Abandoned(_) | Held::Call { gone: true, .. } => self.late += 1,
                            Held::Release => {}
                            Held::Call { rx, .. } => self
                                .answered
                                .push((rx, format!("Err({})", daemon(code, message)))),
                        }
                        self.last_word = None;
                    }
                    None => self.last_word = Some((code.clone(), message.clone())),
                }
            }
            ServerMessage::Event {
                subscription_id,
                envelope_id,
                channel,
                type_name,
                origin,
                payload,
                ..
            } => {
                self.last_word = None;
                match base64::decode(payload) {
                    Err(_) => self.malformed += 1,
                    Ok(bytes) => {
                        let size = bytes.len()
                            + subscription_id.len()
                            + envelope_id.len()
                            + channel.len()
                            + type_name.as_ref().map_or(0, String::len)
                            + origin.len();
                        let room = self.queued.len() < self.depth
                            && self
                                .queued_bytes
                                .checked_add(size)
                                .is_some_and(|total| total <= self.budget);
                        if room {
                            self.queued.push((subscription_id.clone(), bytes));
                            self.queued_bytes += size;
                        } else {
                            self.dropped += 1;
                        }
                    }
                }
            }
            ServerMessage::Health { .. } => self.last_word = None,
            // The run's attach carries no key, so a challenge names no keyed
            // attach of the client's: it is left unanswered, for the
            // daemon's deadline to settle, and changes nothing else.
            ServerMessage::Challenge { .. } => self.last_word = None,
        }
    }

    /// What a late ack does beyond being counted: a subscribe's releases
    /// the subscription it names, and a detach's still ends the connection
    /// cleanly.
    fn after_late(&mut self, op: Op, fields: &AckFields, detached: &mut bool) {
        match op {
            Op::Subscribe => {
                if let Some(sub) = &fields.subscription_id {
                    self.release(sub.clone());
                }
            }
            Op::Detach => *detached = true,
            Op::Attach | Op::Send | Op::Unsubscribe => {}
        }
    }
}

/// One call the client makes, offered to the command queue; refused, its
/// caller waits for room, or, with `wait` false, gives up at its deadline.
fn call(u: &mut Unstructured<'_>, router: &mut Router, m: &mut Model, wait: bool) -> Result<()> {
    let (call, op, rx, subscription) = match u.int_in_range(0..=4u8)? {
        0 | 1 => {
            let (call, rx) = Call::send(&format!("c/{}", u.int_in_range(0..=3u8)?), take(u, 16)?);
            (call, Op::Send, Rx::Send(rx), None)
        }
        2 => {
            let filter = TapFilter {
                channel: Some(u.arbitrary::<&str>()?.to_owned()),
                ..TapFilter::default()
            };
            let (call, rx) = Call::subscribe(filter);
            (call, Op::Subscribe, Rx::Subscribe(rx), None)
        }
        3 => {
            let sub = if !m.subscribed.is_empty() && u.ratio(3, 4)? {
                let subs: Vec<&String> = m.subscribed.iter().collect();
                subs[u.choose_index(subs.len())?].clone()
            } else {
                u.arbitrary::<String>()?
            };
            let (call, rx) = Call::unsubscribe(SubscriptionId(sub.clone()));
            (call, Op::Unsubscribe, Rx::Unsubscribe(rx), Some(sub))
        }
        _ => {
            let (call, rx) = Call::detach();
            (call, Op::Detach, Rx::Unit(rx), None)
        }
    };
    offer(router, m, call, op, rx, subscription, wait);
    Ok(())
}

/// Offer a call to the command queue: it goes in exactly when fewer than
/// `COMMAND_QUEUE` calls wait there and no caller waits for room before it.
/// Refused, its caller waits for room, or gives up at its deadline with
/// `QueueFull`, having sent nothing.
fn offer(
    router: &mut Router,
    m: &mut Model,
    call: Call,
    op: Op,
    mut rx: Rx,
    subscription: Option<String>,
    wait: bool,
) {
    let room = m.commands.len() < COMMAND_QUEUE && m.waiting.is_empty();
    match router.offer(call) {
        None => {
            assert!(room, "the command queue took a call past its depth");
            m.commands.push_back(Queued {
                op,
                rx,
                subscription,
                gone: false,
            });
        }
        Some(call) => {
            assert!(!room, "the command queue refused a call it had room for");
            if wait {
                m.waiting.push_back(Waiting {
                    call,
                    op,
                    rx,
                    subscription,
                });
            } else {
                refused(call, op);
                assert_eq!(rx.peek(), None, "a call never queued was answered");
            }
        }
    }
}

/// A caller waiting for room gives up at its deadline: `QueueFull` naming
/// its operation, and nothing sent.
fn refused(call: Call, op: Op) {
    assert_eq!(
        format!("{:?}", call.refused()),
        format!("{:?}", DevError::QueueFull { op: op.name() }),
        "a call refused for want of room"
    );
}

/// One turn of the driver, and the room it leaves in the command queue
/// given to the oldest caller waiting for it.
fn turn(router: &mut Router, m: &mut Model) {
    let took = router.turn().expect("a request serialises");
    let want = m.turn();
    assert_eq!(
        took,
        want.is_some(),
        "the driver took a call where the model says {}",
        if want.is_some() {
            "it takes one"
        } else {
            "it takes none"
        }
    );
    if let Some(Some(Waiting {
        call,
        op,
        rx,
        subscription,
    })) = want
    {
        assert!(
            router.offer(call).is_none(),
            "a caller waiting for room found none"
        );
        m.commands.push_back(Queued {
            op,
            rx,
            subscription,
            gone: false,
        });
    }
}

/// A caller times out: one whose call waits for room gives up with
/// `QueueFull`; one already answered takes the answer that raced its
/// deadline, and leaves its request alone; any other gives up without an
/// answer and rings the doorbell, withdrawing its request if the writer has
/// not taken it (an unsubscribe's never is).
fn time_out(u: &mut Unstructured<'_>, router: &Router, m: &mut Model) -> Result<()> {
    match u.int_in_range(0..=3u8)? {
        0 if !m.waiting.is_empty() => {
            let i = u.choose_index(m.waiting.len())?;
            let Some(Waiting {
                call, op, mut rx, ..
            }) = m.waiting.remove(i)
            else {
                return Ok(());
            };
            refused(call, op);
            assert_eq!(rx.peek(), None, "a call never queued was answered");
        }
        1 if !m.answered.is_empty() => {
            let i = u.choose_index(m.answered.len())?;
            let (mut rx, want) = m.answered.swap_remove(i);
            assert_eq!(
                rx.time_out(router),
                Some(want),
                "a reply that raced the deadline was lost"
            );
        }
        2 if m.commands.iter().any(|queued| !queued.gone) => {
            let waiting: Vec<usize> = (0..m.commands.len())
                .filter(|&i| !m.commands[i].gone)
                .collect();
            let queued = &mut m.commands[waiting[u.choose_index(waiting.len())?]];
            assert_eq!(
                queued.rx.time_out(router),
                None,
                "a call still queued had an answer"
            );
            queued.gone = true;
            m.rang = true;
        }
        _ => {
            let waiting: Vec<u64> = m
                .held
                .iter()
                .filter(|(_, h)| matches!(h, Held::Call { gone: false, .. }))
                .map(|(&r, _)| r)
                .collect();
            if waiting.is_empty() {
                return Ok(());
            }
            let request = waiting[u.choose_index(waiting.len())?];
            let frame = m.outbox.iter_mut().find(|frame| frame.request == request);
            if let Some(Held::Call {
                op,
                rx,
                gone,
                withdrawn,
            }) = m.held.get_mut(&request)
            {
                assert_eq!(
                    rx.time_out(router),
                    None,
                    "req-{request} had an answer the model missed"
                );
                *gone = true;
                // The writer has not taken it while its frame waits.
                if let Some(frame) = frame.filter(|_| *op != Op::Unsubscribe) {
                    frame.withdrawn = true;
                    *withdrawn = true;
                }
            }
            m.rang = true;
        }
    }
    Ok(())
}

/// How much of the outbox a check compares.
#[derive(Clone, Copy)]
enum Outbox {
    /// Every frame.
    All,
    /// The number of frames, and the newest.
    Newest,
}

/// The state the driver shows after every step, against the model's.
fn check(router: &mut Router, m: &mut Model, outbox: Outbox) {
    let waiting = router.waiting();
    assert_eq!(
        waiting.len(),
        m.outbox.len(),
        "the outbox holds {} frames, the model {}",
        waiting.len(),
        m.outbox.len()
    );
    assert_eq!(
        router.has_room(),
        m.requests() < OUTBOUND_QUEUE,
        "room for another call"
    );
    assert_eq!(
        router.queued(),
        m.commands.len(),
        "the calls in the command queue"
    );
    match outbox {
        Outbox::All => {
            for (text, frame) in waiting.iter().zip(&m.outbox) {
                check_frame(text, frame);
            }
        }
        Outbox::Newest => {
            if let (Some(text), Some(frame)) = (waiting.last(), m.outbox.back()) {
                check_frame(text, frame);
            }
        }
    }
    assert_eq!(router.late_replies(), m.late, "the late replies");
    assert_eq!(router.events_dropped(), m.dropped, "the dropped events");
    assert_eq!(
        router.events_malformed(),
        m.malformed,
        "the malformed events"
    );
    let registered: BTreeSet<String> = router.subscriptions().into_iter().map(|s| s.0).collect();
    assert_eq!(registered, m.subscribed, "the subscriptions registered");
    for (request, held) in &mut m.held {
        if let Held::Call {
            rx, gone: false, ..
        } = held
        {
            assert_eq!(
                rx.peek(),
                None,
                "req-{request} was answered, though nothing named it"
            );
        }
    }
    for queued in &mut m.commands {
        assert_eq!(queued.rx.peek(), None, "a call still queued was answered");
    }
}

/// A frame the writer holds is the request the model queued: a client
/// message with the request's op and id, and for an unsubscribe the
/// subscription it names.
fn check_frame(text: &str, frame: &Frame) {
    let value: Value =
        serde_json::from_str(text).unwrap_or_else(|e| panic!("the client wrote {text}: {e}"));
    assert_eq!(value["op"], frame.op, "frame {text}");
    assert_eq!(
        value["id"].as_str(),
        Some(format!("req-{}", frame.request).as_str()),
        "frame {text}"
    );
    if frame.op == "unsubscribe" {
        assert_eq!(
            value["subscription_id"].as_str(),
            frame.subscription.as_deref(),
            "an unsubscribe of another subscription"
        );
    }
    let _: ClientMessage = serde_json::from_value(value)
        .unwrap_or_else(|e| panic!("the client wrote {text}, not a client message: {e}"));
}

/// The Debug form of the daemon's error.
fn daemon(code: &str, message: &str) -> String {
    if code == "auth_failed" {
        return format!(
            "{:?}",
            DevError::AuthFailed {
                message: message.to_owned(),
            }
        );
    }
    format!(
        "{:?}",
        DevError::Daemon {
            code: code.to_owned(),
            message: message.to_owned(),
        }
    )
}

/// A message from the daemon, mostly about the run's own requests and
/// subscriptions.
fn message(u: &mut Unstructured<'_>, m: &Model) -> Result<ServerMessage> {
    let held: Vec<u64> = m.held.keys().copied().collect();
    let id = match u.int_in_range(0..=9u8)? {
        0 => None,
        1 => Some(u.arbitrary::<String>()?),
        2 if !m.retired.is_empty() => Some(format!(
            "req-{}",
            m.retired[u.choose_index(m.retired.len())?]
        )),
        3 => Some(format!(
            "req-{}",
            m.next_request + u64::from(u.arbitrary::<u8>()?)
        )),
        // A number the client gave, written another way.
        4 if !held.is_empty() => Some(format!("req-0{}", held[u.choose_index(held.len())?])),
        _ if !held.is_empty() => Some(format!("req-{}", held[u.choose_index(held.len())?])),
        _ => None,
    };
    Ok(match u.int_in_range(0..=6u8)? {
        0 | 1 => ServerMessage::Ack {
            id,
            fields: AckFields {
                envelope_id: u.arbitrary()?,
                persisted: u.arbitrary()?,
                delivered: u.arbitrary()?,
                subscription_id: if u.ratio(3, 4)? {
                    Some(format!("sub-{}", u.int_in_range(0..=3u8)?))
                } else {
                    u.arbitrary()?
                },
                events_dropped: u.arbitrary()?,
                ..AckFields::default()
            },
        },
        2 => ServerMessage::Error {
            id,
            code: if u.ratio(1, 8)? {
                "auth_failed".to_owned()
            } else {
                u.arbitrary()?
            },
            message: u.arbitrary()?,
        },
        3 | 4 => {
            let subscription_id = if !m.subscribed.is_empty() && u.ratio(3, 4)? {
                let subs: Vec<&String> = m.subscribed.iter().collect();
                subs[u.choose_index(subs.len())?].clone()
            } else {
                u.arbitrary()?
            };
            let payload = if u.ratio(3, 4)? {
                base64::encode(take(u, 24)?)
            } else {
                u.arbitrary()?
            };
            ServerMessage::Event {
                subscription_id,
                envelope_id: u.arbitrary()?,
                channel: u.arbitrary()?,
                type_id: u.arbitrary()?,
                type_name: u.arbitrary()?,
                origin: u.arbitrary()?,
                captured_at_unix_nanos: u.arbitrary()?,
                payload,
            }
        }
        5 => ServerMessage::Health {
            node_id: u.arbitrary()?,
            state: u.arbitrary()?,
            since_unix_nanos: u.arbitrary()?,
        },
        _ => ServerMessage::Challenge {
            id,
            nonce: if u.arbitrary()? {
                base64::encode(take(u, 32)?)
            } else {
                u.arbitrary()?
            },
        },
    })
}
