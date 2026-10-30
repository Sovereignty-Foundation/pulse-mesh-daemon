// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! What a link does, and two ends of one joined in memory.

use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::Duration;

use pulse_canon::PulseEnvelope;

use crate::{CodecError, Control, QualifiedOrigin};

/// An envelope as a link carries it: with the qualified origin of the
/// client that sent it, the channel it was sent on, which the envelope does
/// not carry, and the node it is addressed to, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Forwarded {
    /// The client that sent it.
    pub origin: QualifiedOrigin,
    /// The node it is addressed to; `None` for a send to subscribers.
    pub dest: Option<QualifiedOrigin>,
    /// The channel it was sent on.
    pub channel: String,
    /// The envelope.
    pub envelope: PulseEnvelope,
}

impl Forwarded {
    /// `envelope`, sent by `origin` on `channel` to subscribers.
    #[must_use]
    pub fn new(
        origin: QualifiedOrigin,
        channel: impl Into<String>,
        envelope: PulseEnvelope,
    ) -> Self {
        Self {
            origin,
            dest: None,
            channel: channel.into(),
            envelope,
        }
    }

    /// The same envelope addressed to `dest`.
    #[must_use]
    pub fn addressed_to(mut self, dest: QualifiedOrigin) -> Self {
        self.dest = Some(dest);
        self
    }
}

/// What arrives on a link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkItem {
    /// A control message.
    Control(Control),
    /// An envelope a peer forwarded.
    Envelope(Forwarded),
}

/// One end of a link between two daemons: one session, authenticated by
/// the two daemons' keys, over which control messages and envelopes pass
/// both ways (ADR-0021, item 1). Delivery is what the transport gives: at
/// most once, in no promised order (item 8).
///
/// The daemon's links over sealed UDP (ADR-0018, in `mesh-hub`) share one
/// socket among every peer, and the daemon drives them directly rather
/// than through this trait, one link per peer; they carry the same
/// [`Control`] messages and refuse an envelope longer than a run of
/// fragments carries, as [`LinkError::EnvelopeTooLarge`] describes.
/// [`MemoryLink`] is a pair in memory for tests.
pub trait Link: Send {
    /// Send a control message.
    ///
    /// # Errors
    ///
    /// [`LinkError::Encode`] for a message that cannot be encoded, and
    /// [`LinkError::Closed`] once the link is closed.
    fn send_control(&mut self, message: &Control) -> Result<(), LinkError>;

    /// Send an envelope.
    ///
    /// # Errors
    ///
    /// [`LinkError::EnvelopeTooLarge`] for an envelope longer than the link
    /// carries, and [`LinkError::Closed`] once the link is closed.
    fn send_envelope(&mut self, forwarded: &Forwarded) -> Result<(), LinkError>;

    /// The next item from the peer, waiting up to `timeout` for one;
    /// `Ok(None)` when none arrived in that time.
    ///
    /// # Errors
    ///
    /// [`LinkError::Decode`] for a control message from the peer that is
    /// not one, which is dropped (the next call goes on with the next
    /// item), and [`LinkError::Closed`] once the link is closed.
    fn recv_timeout(&mut self, timeout: Duration) -> Result<Option<LinkItem>, LinkError>;
}

/// Why a link refused to send or to receive.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LinkError {
    /// The link is closed, here or at the peer.
    #[error("the link is closed")]
    Closed,
    /// A control message could not be encoded, as one past its cap cannot.
    #[error("a control message could not be encoded: {0}")]
    Encode(CodecError),
    /// The peer sent bytes that are not a control message.
    #[error("the peer sent a control message that is not one: {0}")]
    Decode(CodecError),
    /// The envelope is longer than the link carries.
    #[error("an envelope of {len} bytes is longer than the {max} bytes this link carries")]
    EnvelopeTooLarge {
        /// Its canonical length in bytes.
        len: usize,
        /// The most the link carries.
        max: usize,
    },
}

/// What passes between the two ends of a [`MemoryLink`].
#[derive(Debug)]
enum Frame {
    /// A control message's bytes, so that its encoding is exercised.
    Control(Vec<u8>),
    /// An envelope, as it is.
    Envelope(Forwarded),
}

/// One end of a link in memory ([`link_pair`]), for tests: lossless and in
/// order, of unbounded capacity. Control messages cross as their encoded
/// bytes and are decoded on arrival, envelopes as they are. Dropping one
/// end closes the link for the other.
#[derive(Debug)]
pub struct MemoryLink {
    outgoing: Sender<Frame>,
    incoming: Receiver<Frame>,
}

/// Two ends of a link in memory: what one sends, the other receives.
#[must_use]
pub fn link_pair() -> (MemoryLink, MemoryLink) {
    let (a_out, b_in) = mpsc::channel();
    let (b_out, a_in) = mpsc::channel();
    (
        MemoryLink {
            outgoing: a_out,
            incoming: a_in,
        },
        MemoryLink {
            outgoing: b_out,
            incoming: b_in,
        },
    )
}

impl Link for MemoryLink {
    fn send_control(&mut self, message: &Control) -> Result<(), LinkError> {
        let bytes = message.encode().map_err(LinkError::Encode)?;
        self.outgoing
            .send(Frame::Control(bytes))
            .map_err(|_| LinkError::Closed)
    }

    fn send_envelope(&mut self, forwarded: &Forwarded) -> Result<(), LinkError> {
        self.outgoing
            .send(Frame::Envelope(forwarded.clone()))
            .map_err(|_| LinkError::Closed)
    }

    fn recv_timeout(&mut self, timeout: Duration) -> Result<Option<LinkItem>, LinkError> {
        match self.incoming.recv_timeout(timeout) {
            Ok(Frame::Control(bytes)) => Control::decode(&bytes)
                .map(|message| Some(LinkItem::Control(message)))
                .map_err(LinkError::Decode),
            Ok(Frame::Envelope(forwarded)) => Ok(Some(LinkItem::Envelope(forwarded))),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err(LinkError::Closed),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::DaemonId;

    fn origin() -> QualifiedOrigin {
        QualifiedOrigin::new(DaemonId::from_bytes([1; 8]), "sender").unwrap()
    }

    #[test]
    fn what_one_end_sends_the_other_receives_in_order() {
        let (mut a, mut b) = link_pair();
        let envelope = PulseEnvelope::with_content(0, Some("jobs/new".into()), b"x".to_vec());
        let forwarded = Forwarded::new(origin(), "jobs/new", envelope);
        a.send_control(&Control::Heartbeat).unwrap();
        a.send_envelope(&forwarded).unwrap();
        b.send_control(&Control::Hello(vec![1])).unwrap();
        assert_eq!(
            b.recv_timeout(Duration::ZERO),
            Ok(Some(LinkItem::Control(Control::Heartbeat)))
        );
        assert_eq!(
            b.recv_timeout(Duration::ZERO),
            Ok(Some(LinkItem::Envelope(forwarded)))
        );
        assert_eq!(b.recv_timeout(Duration::ZERO), Ok(None));
        assert_eq!(
            a.recv_timeout(Duration::ZERO),
            Ok(Some(LinkItem::Control(Control::Hello(vec![1]))))
        );
    }

    #[test]
    fn bytes_that_are_no_message_are_refused_and_the_link_goes_on() {
        let (a, mut b) = link_pair();
        a.outgoing.send(Frame::Control(vec![1, 99])).unwrap();
        a.outgoing.send(Frame::Control(vec![1, 5])).unwrap();
        assert_eq!(
            b.recv_timeout(Duration::ZERO),
            Err(LinkError::Decode(CodecError::UnknownKind(99)))
        );
        assert_eq!(
            b.recv_timeout(Duration::ZERO),
            Ok(Some(LinkItem::Control(Control::Heartbeat)))
        );
    }

    #[test]
    fn dropping_one_end_closes_the_link() {
        let (mut a, b) = link_pair();
        drop(b);
        assert_eq!(a.send_control(&Control::Heartbeat), Err(LinkError::Closed));
        assert_eq!(a.recv_timeout(Duration::ZERO), Err(LinkError::Closed));
    }

    #[test]
    fn a_message_past_its_cap_is_refused_before_it_is_sent() {
        let (mut a, mut b) = link_pair();
        let hello = Control::Hello(vec![0; crate::MAX_HELLO_BYTES + 1]);
        assert!(matches!(a.send_control(&hello), Err(LinkError::Encode(_))));
        assert_eq!(b.recv_timeout(Duration::ZERO), Ok(None));
    }
}
