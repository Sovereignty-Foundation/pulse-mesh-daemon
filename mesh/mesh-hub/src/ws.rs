// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The WebSocket's frames, read and written by the daemon itself once
//! tungstenite has done the upgrade (RFC 6455, section 5), since tungstenite's
//! buffers keep their largest size for the life of a connection.
//!
//! - [`UpgradeStream`] lends tungstenite the socket for the upgrade, and no
//!   byte past the request.
//! - [`FrameReader`], sans-IO, assembles each message in one buffer no larger
//!   than its frames declare, refuses one over the cap at its header, and keeps
//!   nothing of a binary message.
//! - [`frame_header`] heads a frame the daemon writes from where its bytes are.
//!
//! Checked by the tests below and `tests/connection_memory.rs`.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The opcode of a frame that continues a fragmented message.
pub(crate) const CONTINUATION: u8 = 0x0;
/// The opcode of a text message's first frame.
pub(crate) const TEXT: u8 = 0x1;
/// The opcode of a binary message's first frame.
pub(crate) const BINARY: u8 = 0x2;
/// The opcode of a close frame.
pub(crate) const CLOSE: u8 = 0x8;
/// The opcode of a ping.
pub(crate) const PING: u8 = 0x9;
/// The opcode of a pong.
pub(crate) const PONG: u8 = 0xa;

/// The most payload a control frame (a close, a ping, a pong) may carry.
pub(crate) const MAX_CONTROL_PAYLOAD: usize = 125;

/// The longest header of a frame the daemon sends: two bytes, then eight of
/// length. A server's frames carry no mask.
pub(crate) const MAX_HEADER: usize = 10;

/// Bytes a [`FrameReader`] takes from the socket at a time, which is all it
/// holds between messages besides a control frame's payload.
pub(crate) const READ_CHUNK: usize = 8 * 1024;

/// Bytes an [`UpgradeStream`] reads from the socket at a time, and so the
/// most it can have read past the request when the upgrade is done.
pub(crate) const UPGRADE_CHUNK: usize = 4 * 1024;

/// The header of a final, unmasked frame of `opcode` carrying `len` bytes
/// of payload, as a server sends one, and how many of the returned bytes it
/// takes: two, then the length in the shortest form section 5.2 allows.
#[must_use]
pub(crate) fn frame_header(opcode: u8, len: usize) -> ([u8; MAX_HEADER], usize) {
    let mut header = [0u8; MAX_HEADER];
    header[0] = 0x80 | (opcode & 0x0f);
    let used = match (u8::try_from(len), u16::try_from(len)) {
        (Ok(short), _) if short < 126 => {
            header[1] = short;
            2
        }
        (_, Ok(medium)) => {
            header[1] = 126;
            header[2..4].copy_from_slice(&medium.to_be_bytes());
            4
        }
        _ => {
            header[1] = 127;
            // A `usize` fits in 64 bits on every target the daemon builds for.
            header[2..10].copy_from_slice(&(len as u64).to_be_bytes());
            10
        }
    };
    (header, used)
}

/// Whether a close frame may carry `code` (RFC 6455 section 7.4, and the IANA
/// registry since): 1000 to 1003, 1007 to 1014, and 3000 to 4999 for libraries
/// and applications.
#[must_use]
pub(crate) fn close_code_allowed(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
}

/// What a client's frames came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Incoming {
    /// A whole text message.
    Text(String),
    /// A ping, with the payload the pong that answers it carries.
    Ping(Vec<u8>),
    /// A pong.
    Pong,
    /// A close frame, with the status code the answering close carries: the
    /// client's own, `None` when it gave none, 1002 when its code is not one a
    /// close may carry or its payload is one byte, and 1007 when its reason is
    /// not UTF-8.
    Close(Option<u16>),
}

/// Why a [`FrameReader`] refused a client's frames. Either way the
/// connection ends: the stream has no boundary to start again from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadError {
    /// A message's frames declared more than the reader's cap: `len` bytes,
    /// the message's earlier frames and the one whose header took it over.
    /// Nothing of that frame was read.
    Oversized {
        /// The bytes declared.
        len: usize,
    },
    /// The frames broke RFC 6455, as the reason says.
    Protocol(&'static str),
}

/// A frame header as a client sends it.
#[derive(Debug, Clone, Copy)]
struct Header {
    fin: bool,
    /// The three reserved bits, which no extension the daemon agrees to
    /// sets.
    rsv: u8,
    opcode: u8,
    mask: Option<[u8; 4]>,
    len: u64,
}

/// The header at the front of `bytes`, and how many bytes it takes; `None`
/// until all of it has arrived.
fn parse_header(bytes: &[u8]) -> Option<(Header, usize)> {
    let (&first, rest) = bytes.split_first()?;
    let (&second, rest) = rest.split_first()?;
    let (len, rest) = match second & 0x7f {
        126 => {
            let (len, rest) = rest.split_first_chunk::<2>()?;
            (u64::from(u16::from_be_bytes(*len)), rest)
        }
        127 => {
            let (len, rest) = rest.split_first_chunk::<8>()?;
            (u64::from_be_bytes(*len), rest)
        }
        short => (u64::from(short), rest),
    };
    let (mask, rest) = if second & 0x80 == 0 {
        (None, rest)
    } else {
        let (mask, rest) = rest.split_first_chunk::<4>()?;
        (Some(*mask), rest)
    };
    let header = Header {
        fin: first & 0x80 != 0,
        rsv: first & 0x70,
        opcode: first & 0x0f,
        mask,
        len,
    };
    Some((header, bytes.len() - rest.len()))
}

/// Unmask `bytes`, which begin `offset` bytes into their frame's payload.
fn unmask(bytes: &mut [u8], mask: [u8; 4], offset: usize) {
    let mut key = mask;
    key.rotate_left(offset % 4);
    for (byte, key) in bytes.iter_mut().zip(key.iter().cycle()) {
        *byte ^= key;
    }
}

/// Make room for `more` bytes, doubling the capacity but never past `limit`,
/// what the message's frames have declared so far, so a header alone reserves
/// nothing.
fn make_room(buffer: &mut Vec<u8>, more: usize, limit: usize) {
    let needed = buffer.len() + more;
    if needed > buffer.capacity() {
        let target = buffer.capacity().saturating_mul(2).min(limit).max(needed);
        buffer.reserve_exact(target - buffer.len());
    }
}

/// A frame whose payload is being read.
#[derive(Debug)]
struct InFrame {
    opcode: u8,
    fin: bool,
    mask: [u8; 4],
    len: usize,
    read: usize,
}

/// The data message being assembled.
#[derive(Debug)]
struct InMessage {
    /// A text message's bytes so far. A binary message's are not kept.
    text: Option<Vec<u8>>,
    /// The payload its frames have declared so far, the one being read
    /// included.
    declared: usize,
}

/// The daemon's reader of a client's WebSocket frames: bytes in as they arrive,
/// whole messages, pings, pongs and the close out.
///
/// It enforces what section 5 asks of a server (masked frames, no reserved bit
/// or opcode, whole control frames of at most 125 bytes, continuations only
/// within a message, UTF-8 text), and holds at most the cap while a message
/// arrives, nothing of it after, and [`READ_CHUNK`] bytes between messages.
#[derive(Debug)]
pub(crate) struct FrameReader {
    /// Bytes read from the socket; those from `start` to `end` are not yet
    /// taken.
    input: Box<[u8]>,
    start: usize,
    end: usize,
    frame: Option<InFrame>,
    message: Option<InMessage>,
    /// The payload of the control frame being read.
    control: Vec<u8>,
    max_message: usize,
    /// The refusal, once the frames have been refused: every later call
    /// gives it again.
    failed: Option<ReadError>,
    /// A close frame has been handed back: nothing after it is read.
    closed: bool,
}

impl FrameReader {
    /// A reader of messages of at most `max_message` bytes of payload,
    /// which starts with `already`: bytes of the connection read before it
    /// existed, such as those that followed the upgrade request.
    #[must_use]
    pub(crate) fn new(max_message: usize, already: &[u8]) -> Self {
        let mut input = vec![0u8; READ_CHUNK.max(already.len())].into_boxed_slice();
        input[..already.len()].copy_from_slice(already);
        Self {
            input,
            start: 0,
            end: already.len(),
            frame: None,
            message: None,
            control: Vec::new(),
            max_message,
            failed: None,
            closed: false,
        }
    }

    /// Where the next bytes read from the socket go; report how many with
    /// [`FrameReader::filled`]. Call it only after [`FrameReader::pop`]
    /// returned `Ok(None)`, when at most a partial header is left, so that
    /// there is room.
    pub(crate) fn space(&mut self) -> &mut [u8] {
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        } else if self.end == self.input.len() {
            self.input.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        &mut self.input[self.end..]
    }

    /// Record that `n` bytes were read into [`FrameReader::space`].
    pub(crate) fn filled(&mut self, n: usize) {
        self.end = (self.end + n).min(self.input.len());
    }

    /// Bytes the reader holds besides its read buffer: the message being
    /// assembled and the control frame being read, as allocated.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn holding(&self) -> usize {
        let text = self
            .message
            .as_ref()
            .and_then(|m| m.text.as_ref())
            .map_or(0, Vec::capacity);
        text + self.control.capacity()
    }

    /// The next message, ping, pong or close the bytes so far complete, or
    /// `Ok(None)` until more arrive, and for good after a close.
    ///
    /// # Errors
    ///
    /// [`ReadError::Oversized`] at the header that takes a message past the
    /// cap, and [`ReadError::Protocol`] when the frames break RFC 6455; every
    /// later call returns the same error, and the connection must end.
    pub(crate) fn pop(&mut self) -> Result<Option<Incoming>, ReadError> {
        if let Some(failed) = self.failed {
            return Err(failed);
        }
        if self.closed {
            return Ok(None);
        }
        let next = self.advance();
        match &next {
            Err(failed) => self.failed = Some(*failed),
            Ok(Some(Incoming::Close(_))) => self.closed = true,
            Ok(_) => return next,
        }
        // Whatever was being assembled goes with the connection's end.
        self.frame = None;
        self.message = None;
        self.control = Vec::new();
        next
    }

    /// [`FrameReader::pop`], before a refusal is made final.
    fn advance(&mut self) -> Result<Option<Incoming>, ReadError> {
        loop {
            if self.frame.is_none() {
                let Some((header, used)) = parse_header(&self.input[self.start..self.end]) else {
                    return Ok(None);
                };
                self.start += used;
                self.frame = Some(self.begin(header)?);
            }
            if !self.take_payload() {
                return Ok(None);
            }
            if let Some(frame) = self.frame.take() {
                if let Some(incoming) = self.finish(&frame)? {
                    return Ok(Some(incoming));
                }
            }
        }
    }

    /// Check a frame's header against what came before it, and start its
    /// payload.
    fn begin(&mut self, header: Header) -> Result<InFrame, ReadError> {
        if header.rsv != 0 {
            return Err(ReadError::Protocol(
                "a frame set a reserved bit, and no extension was agreed",
            ));
        }
        let Some(mask) = header.mask else {
            return Err(ReadError::Protocol("a client's frame was not masked"));
        };
        if header.len > i64::MAX as u64 {
            return Err(ReadError::Protocol(
                "a frame's 64-bit length set its most significant bit",
            ));
        }
        match header.opcode {
            CONTINUATION | TEXT | BINARY => {
                let before = match (&self.message, header.opcode) {
                    (None, CONTINUATION) => {
                        return Err(ReadError::Protocol(
                            "a continuation frame came with no message to continue",
                        ));
                    }
                    (Some(_), TEXT | BINARY) => {
                        return Err(ReadError::Protocol(
                            "a message began before the one before it had ended",
                        ));
                    }
                    (Some(message), _) => message.declared,
                    (None, _) => 0,
                };
                // Nothing a header declares is read, or reserved, before the
                // message it belongs to is known to fit.
                let oversized = || ReadError::Oversized {
                    len: usize::try_from((before as u64).saturating_add(header.len))
                        .unwrap_or(usize::MAX),
                };
                let len = usize::try_from(header.len).map_err(|_| oversized())?;
                let declared = before
                    .checked_add(len)
                    .filter(|&declared| declared <= self.max_message)
                    .ok_or_else(oversized)?;
                let message = self.message.get_or_insert_with(|| InMessage {
                    text: (header.opcode == TEXT).then(Vec::new),
                    declared: 0,
                });
                message.declared = declared;
                Ok(InFrame {
                    opcode: header.opcode,
                    fin: header.fin,
                    mask,
                    len,
                    read: 0,
                })
            }
            CLOSE | PING | PONG => {
                if !header.fin {
                    return Err(ReadError::Protocol("a control frame was fragmented"));
                }
                if header.len > MAX_CONTROL_PAYLOAD as u64 {
                    return Err(ReadError::Protocol(
                        "a control frame carried more than 125 bytes",
                    ));
                }
                self.control.clear();
                Ok(InFrame {
                    opcode: header.opcode,
                    fin: true,
                    mask,
                    len: header.len as usize,
                    read: 0,
                })
            }
            _ => Err(ReadError::Protocol("a frame's opcode is a reserved one")),
        }
    }

    /// Take what has arrived of the current frame's payload; `true` once
    /// all of it has.
    fn take_payload(&mut self) -> bool {
        let Some(frame) = self.frame.as_mut() else {
            return true;
        };
        let n = (frame.len - frame.read).min(self.end - self.start);
        let bytes = &mut self.input[self.start..self.start + n];
        match frame.opcode {
            CONTINUATION | TEXT | BINARY => {
                // A binary message's bytes are passed over unread.
                if let Some(InMessage {
                    text: Some(text),
                    declared,
                }) = self.message.as_mut()
                {
                    unmask(bytes, frame.mask, frame.read);
                    make_room(text, n, *declared);
                    text.extend_from_slice(bytes);
                }
            }
            _ => {
                unmask(bytes, frame.mask, frame.read);
                self.control.extend_from_slice(bytes);
            }
        }
        frame.read += n;
        self.start += n;
        frame.read == frame.len
    }

    /// What a frame whose payload is all read comes to, if anything yet.
    fn finish(&mut self, frame: &InFrame) -> Result<Option<Incoming>, ReadError> {
        Ok(match frame.opcode {
            // A control frame's payload is let go with it.
            PING => Some(Incoming::Ping(std::mem::take(&mut self.control))),
            PONG => {
                self.control = Vec::new();
                Some(Incoming::Pong)
            }
            CLOSE => Some(Incoming::Close(close_answer(&std::mem::take(
                &mut self.control,
            )))),
            _ if !frame.fin => None,
            _ => match self.message.take().and_then(|message| message.text) {
                // A binary message: the protocol has none, and none of it
                // was kept.
                None => None,
                Some(text) => {
                    Some(Incoming::Text(String::from_utf8(text).map_err(|_| {
                        ReadError::Protocol("a text message was not UTF-8")
                    })?))
                }
            },
        })
    }
}

/// The status code the close answering a close frame whose payload is
/// `payload` carries; see [`Incoming::Close`].
fn close_answer(payload: &[u8]) -> Option<u16> {
    match payload {
        [] => None,
        [_] => Some(1002),
        [high, low, reason @ ..] => {
            let code = u16::from_be_bytes([*high, *low]);
            if !close_code_allowed(code) {
                Some(1002)
            } else if std::str::from_utf8(reason).is_err() {
                Some(1007)
            } else {
                Some(code)
            }
        }
    }
}

/// Where the lines of an upgrade request stand: whether the request line
/// has begun, and what the current line holds so far.
#[derive(Debug, Default)]
struct RequestLines {
    begun: bool,
    line: Line,
}

/// What a line of an upgrade request holds so far.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Line {
    #[default]
    Empty,
    /// A lone carriage return, which a line feed makes a blank line.
    Cr,
    Other,
}

impl RequestLines {
    /// Take the request's next byte: `true` when it ends the request, the
    /// line feed of the first blank line after the request line. A blank
    /// line before the request line does not, as httparse skips those.
    fn ends_with(&mut self, byte: u8) -> bool {
        match byte {
            b'\n' => {
                let blank = self.line != Line::Other;
                self.line = Line::Empty;
                if blank {
                    self.begun
                } else {
                    self.begun = true;
                    false
                }
            }
            b'\r' if self.line == Line::Empty => {
                self.line = Line::Cr;
                false
            }
            _ => {
                self.line = Line::Other;
                false
            }
        }
    }
}

/// A connection's socket lent to tungstenite for the upgrade alone: tungstenite
/// gets no byte past the end of the request (found as httparse finds it), so
/// [`UpgradeStream::take_parts`] gets back the socket and every byte read past
/// the request. Writes pass straight through.
#[derive(Debug)]
pub(crate) struct UpgradeStream<S> {
    stream: Option<S>,
    /// Bytes read from the socket, the first `given` of them handed to
    /// tungstenite.
    read: Vec<u8>,
    given: usize,
    /// Where in `read` the request ends, once its blank line has arrived.
    end: Option<usize>,
    lines: RequestLines,
}

impl<S> UpgradeStream<S> {
    /// Lend `stream` for an upgrade.
    pub(crate) fn new(stream: S) -> Self {
        Self {
            stream: Some(stream),
            read: Vec::new(),
            given: 0,
            end: None,
            lines: RequestLines::default(),
        }
    }

    /// Take the socket back after the upgrade, with the bytes read past the
    /// request, at most [`UPGRADE_CHUNK`]; `None` when taken already, or when
    /// the upgrade ended before the request did.
    pub(crate) fn take_parts(&mut self) -> Option<(S, Vec<u8>)> {
        let end = self.end.filter(|&end| end == self.given)?;
        let stream = self.stream.take()?;
        Some((stream, self.read.split_off(end)))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for UpgradeStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            let limit = this.end.unwrap_or(this.read.len());
            if this.given < limit {
                let n = (limit - this.given).min(buf.remaining());
                buf.put_slice(&this.read[this.given..this.given + n]);
                this.given += n;
                return Poll::Ready(Ok(()));
            }
            if this.end.is_some() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the upgrade asked for bytes past the end of its request",
                )));
            }
            let Some(stream) = this.stream.as_mut() else {
                return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
            };
            let mut chunk = [0u8; UPGRADE_CHUNK];
            let mut chunk = ReadBuf::new(&mut chunk);
            ready!(Pin::new(stream).poll_read(cx, &mut chunk))?;
            let got = chunk.filled();
            if got.is_empty() {
                // The client closed: the end of the stream, as tungstenite
                // would have seen it.
                return Poll::Ready(Ok(()));
            }
            let from = this.read.len();
            this.read.extend_from_slice(got);
            let lines = &mut this.lines;
            if let Some(at) = got.iter().position(|&byte| lines.ends_with(byte)) {
                this.end = Some(from + at + 1);
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for UpgradeStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut().stream.as_mut() {
            Some(stream) => Pin::new(stream).poll_write(cx, buf),
            None => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().stream.as_mut() {
            Some(stream) => Pin::new(stream).poll_flush(cx),
            None => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().stream.as_mut() {
            Some(stream) => Pin::new(stream).poll_shutdown(cx),
            None => Poll::Ready(Ok(())),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::{Data, OpCode};
    use tokio_tungstenite::tungstenite::protocol::frame::Frame;

    const MASK: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];

    /// A client's frame: `first` is the byte holding FIN, the reserved
    /// bits and the opcode; the payload is masked with [`MASK`].
    fn raw(first: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![first];
        let len = payload.len();
        if len < 126 {
            frame.push(0x80 | len as u8);
        } else if let Ok(len) = u16::try_from(len) {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&len.to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        frame.extend_from_slice(&MASK);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ MASK[i % 4]));
        frame
    }

    /// A final client frame of `opcode`.
    fn frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        raw(0x80 | opcode, payload)
    }

    /// Feed `bytes` to `reader` in pieces of `piece` bytes, collecting what
    /// it hands back, until the bytes run out or it refuses them.
    fn feed(
        reader: &mut FrameReader,
        bytes: &[u8],
        piece: usize,
    ) -> (Vec<Incoming>, Option<ReadError>) {
        let mut out = Vec::new();
        let mut rest = bytes;
        loop {
            loop {
                match reader.pop() {
                    Ok(Some(incoming)) => out.push(incoming),
                    Ok(None) => break,
                    Err(e) => return (out, Some(e)),
                }
            }
            if rest.is_empty() {
                return (out, None);
            }
            let space = reader.space();
            let n = piece.min(space.len()).min(rest.len());
            space[..n].copy_from_slice(&rest[..n]);
            reader.filled(n);
            rest = &rest[n..];
        }
    }

    fn text(s: &str) -> Incoming {
        Incoming::Text(s.to_string())
    }

    #[test]
    fn the_header_is_the_one_tungstenite_writes_for_a_final_frame() {
        for opcode in [TEXT, PONG] {
            for len in [0usize, 1, 125, 126, 127, 65_535, 65_536, 1 << 20] {
                if opcode == PONG && len > MAX_CONTROL_PAYLOAD {
                    continue;
                }
                let (header, used) = frame_header(opcode, len);
                let frame = if opcode == TEXT {
                    Frame::message(vec![b'x'; len], OpCode::Data(Data::Text), true)
                } else {
                    Frame::pong(vec![b'x'; len])
                };
                let mut expected = Vec::new();
                frame.format(&mut expected).unwrap();
                assert_eq!(&expected[..used], &header[..used], "{len} bytes");
                assert_eq!(expected.len(), used + len, "{len} bytes");
            }
        }
        assert_eq!(
            frame_header(TEXT, 5),
            ([0x81, 5, 0, 0, 0, 0, 0, 0, 0, 0], 2)
        );
        let (header, used) = frame_header(TEXT, 70_000);
        assert_eq!(&header[..used], &[0x81, 127, 0, 0, 0, 0, 0, 1, 0x11, 0x70]);
    }

    #[test]
    fn messages_come_out_whole_however_the_bytes_arrive() {
        let long = "é".repeat(40_000);
        let mut stream = frame(TEXT, b"{\"op\":\"health\"}");
        stream.extend(raw(TEXT, long.as_bytes().get(..30_001).unwrap()));
        stream.extend(frame(PING, b"are you there"));
        stream.extend(raw(CONTINUATION, &long.as_bytes()[30_001..50_000]));
        stream.extend(frame(PONG, b""));
        stream.extend(frame(CONTINUATION, &long.as_bytes()[50_000..]));
        stream.extend(frame(BINARY, &[0xff; 3000]));
        stream.extend(frame(TEXT, b""));
        stream.extend(frame(CLOSE, &1000u16.to_be_bytes()));
        let expected = vec![
            text("{\"op\":\"health\"}"),
            Incoming::Ping(b"are you there".to_vec()),
            Incoming::Pong,
            text(&long),
            text(""),
            Incoming::Close(Some(1000)),
        ];
        for piece in [1, 2, 3, 13, 1000, READ_CHUNK] {
            let mut reader = FrameReader::new(1 << 20, &[]);
            assert_eq!(
                feed(&mut reader, &stream, piece),
                (expected.clone(), None),
                "{piece}"
            );
            assert_eq!(reader.holding(), 0, "nothing held after the messages");
        }
    }

    #[test]
    fn nothing_after_a_close_frame_is_read() {
        let mut stream = raw(TEXT, b"unfinished");
        stream.extend(frame(CLOSE, &1001u16.to_be_bytes()));
        stream.extend(frame(TEXT, b"after"));
        let mut reader = FrameReader::new(1024, &[]);
        assert_eq!(
            feed(&mut reader, &stream, 7),
            (vec![Incoming::Close(Some(1001))], None)
        );
        assert_eq!(reader.pop(), Ok(None));
        assert_eq!(reader.holding(), 0, "the unfinished message went too");
    }

    #[test]
    fn bytes_read_before_the_reader_existed_come_first() {
        let mut stream = frame(TEXT, b"one");
        stream.extend(frame(TEXT, b"two"));
        let mut reader = FrameReader::new(1024, &stream[..7]);
        assert_eq!(
            feed(&mut reader, &stream[7..], 64),
            (vec![text("one"), text("two")], None)
        );
    }

    #[test]
    fn a_message_at_the_cap_is_taken_and_one_byte_more_is_refused_at_its_header() {
        let mut reader = FrameReader::new(1000, &[]);
        let at_cap = "x".repeat(1000);
        assert_eq!(
            feed(&mut reader, &frame(TEXT, at_cap.as_bytes()), 100),
            (vec![text(&at_cap)], None)
        );
        let mut reader = FrameReader::new(1000, &[]);
        let over = frame(TEXT, &[b'x'; 1001]);
        // Only the header is given: the refusal needs nothing of the payload.
        assert_eq!(
            feed(&mut reader, &over[..8], 8),
            (vec![], Some(ReadError::Oversized { len: 1001 }))
        );
        assert_eq!(reader.holding(), 0, "nothing reserved for it");
    }

    #[test]
    fn a_fragmented_message_is_capped_as_a_whole_at_the_header_that_passes_the_cap() {
        let mut reader = FrameReader::new(1000, &[]);
        let mut stream = raw(TEXT, &[b'a'; 600]);
        stream.extend(frame(PING, b""));
        let continuation = frame(CONTINUATION, &[b'b'; 401]);
        stream.extend_from_slice(&continuation[..8]);
        let (out, refused) = feed(&mut reader, &stream, 64);
        assert_eq!(out, vec![Incoming::Ping(vec![])]);
        assert_eq!(refused, Some(ReadError::Oversized { len: 1001 }));
        // Fragments that fit are taken, the whole message within the cap.
        let mut reader = FrameReader::new(1000, &[]);
        let mut stream = raw(TEXT, &[b'a'; 600]);
        stream.extend(frame(CONTINUATION, &[b'b'; 400]));
        let (out, refused) = feed(&mut reader, &stream, 64);
        assert_eq!(refused, None);
        assert_eq!(
            out,
            vec![text(&format!("{}{}", "a".repeat(600), "b".repeat(400)))]
        );
    }

    #[test]
    fn a_header_declaring_more_than_any_message_is_refused_without_overflow() {
        let header = |first: u8, len: u64| {
            let mut header = vec![first, 0x80 | 127];
            header.extend_from_slice(&len.to_be_bytes());
            header.extend_from_slice(&MASK);
            header
        };
        // A length that sets the most significant bit is not one.
        let mut reader = FrameReader::new(usize::MAX, &[]);
        let (_, refused) = feed(&mut reader, &header(0x81, u64::MAX), 64);
        assert!(
            matches!(refused, Some(ReadError::Protocol(why)) if why.contains("significant")),
            "{refused:?}"
        );
        // The largest length there is, after a fragment: the sum is
        // refused, not wrapped.
        let mut reader = FrameReader::new(1000, &[]);
        let mut stream = raw(TEXT, &[b'a'; 600]);
        stream.extend(header(0x80, i64::MAX as u64));
        let (_, refused) = feed(&mut reader, &stream, 64);
        let len = usize::try_from(600 + i64::MAX as u64).unwrap_or(usize::MAX);
        assert_eq!(refused, Some(ReadError::Oversized { len }));
    }

    #[test]
    fn a_messages_buffer_never_outgrows_what_its_frames_declare() {
        for len in [1usize, 4095, 4096, 4097, 100_000, 1 << 20] {
            let mut reader = FrameReader::new(1 << 20, &[]);
            let bytes = frame(TEXT, &vec![b'y'; len]);
            // All but the last byte: the message is being read.
            let (out, refused) = feed(&mut reader, &bytes[..bytes.len() - 1], READ_CHUNK);
            assert!(out.is_empty() && refused.is_none());
            assert!(
                reader.holding() <= len,
                "{} held for a message of {len} bytes",
                reader.holding()
            );
        }
        // Across fragments, the buffer stays within the message.
        let mut reader = FrameReader::new(1 << 20, &[]);
        let mut stream = raw(TEXT, &[b'a'; 70_000]);
        stream.extend(raw(CONTINUATION, &[b'b'; 300_000]));
        let (_, refused) = feed(&mut reader, &stream, READ_CHUNK);
        assert!(refused.is_none());
        assert!(reader.holding() <= 370_000, "{}", reader.holding());
    }

    #[test]
    fn frames_that_break_the_protocol_are_refused() {
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (
                {
                    let mut f = frame(TEXT, b"x");
                    f[1] &= 0x7f;
                    f.drain(2..6);
                    f
                },
                "not masked",
            ),
            (raw(0x80 | 0x40 | TEXT, b"x"), "reserved bit"),
            (frame(0x3, b"x"), "reserved one"),
            (frame(0xb, b""), "reserved one"),
            (frame(CONTINUATION, b"x"), "no message to continue"),
            (
                {
                    let mut f = raw(TEXT, b"x");
                    f.extend(frame(TEXT, b"y"));
                    f
                },
                "began before",
            ),
            (raw(PING, b""), "fragmented"),
            (frame(PING, &[0; 126]), "more than 125"),
            (frame(TEXT, &[0xc3, 0x28]), "not UTF-8"),
        ];
        for (bytes, says) in cases {
            let mut reader = FrameReader::new(1024, &[]);
            let (_, refused) = feed(&mut reader, &bytes, 3);
            match refused {
                Some(ReadError::Protocol(why)) => assert!(why.contains(says), "{why} / {says}"),
                other => panic!("{bytes:?}: {other:?}, expected a refusal naming {says}"),
            }
        }
        // A text message split inside a character is whole again at the end.
        let mut reader = FrameReader::new(1024, &[]);
        let mut split = raw(TEXT, &[0xc3]);
        split.extend(frame(CONTINUATION, &[0xa9]));
        assert_eq!(feed(&mut reader, &split, 1), (vec![text("é")], None));
    }

    #[test]
    fn a_close_is_answered_with_its_own_code_when_it_may_carry_it() {
        let cases: [(&[u8], Option<u16>); 7] = [
            (b"", None),
            (&[0x03], Some(1002)),
            (&[0x03, 0xe8], Some(1000)),
            (&[0x0f, 0xa0, b'o', b'k'], Some(4000)),
            (&[0x03, 0xed], Some(1002)),
            (&[0x03, 0xe8, 0xff], Some(1007)),
            (&[0x00, 0x00], Some(1002)),
        ];
        for (payload, answer) in cases {
            let mut reader = FrameReader::new(1024, &[]);
            assert_eq!(
                feed(&mut reader, &frame(CLOSE, payload), 5),
                (vec![Incoming::Close(answer)], None),
                "{payload:?}"
            );
        }
        for code in [1004, 1005, 1006, 1015, 1016, 999, 2999, 5000] {
            assert!(!close_code_allowed(code), "{code}");
        }
        for code in [1000, 1001, 1003, 1007, 1011, 1013, 1014, 3000, 4999] {
            assert!(close_code_allowed(code), "{code}");
        }
    }

    #[test]
    fn the_blank_line_that_ends_a_request_is_found_as_httparse_finds_it() {
        let cases: [(&[u8], Option<usize>); 6] = [
            (b"GET / HTTP/1.1\r\nHost: a\r\n\r\nrest", Some(27)),
            (b"GET / HTTP/1.1\nHost: a\n\nrest", Some(24)),
            (b"\r\n\nGET / HTTP/1.1\r\n\r\n", Some(21)),
            (b"GET / HTTP/1.1\r\nHost: a\r\n\r", None),
            (b"GET / HTTP/1.1\r\nX: \r\r\n", None),
            (b"GET / HTTP/1.1\r\n\n", Some(17)),
        ];
        for (request, end) in cases {
            let mut lines = RequestLines::default();
            let found = request
                .iter()
                .position(|&b| lines.ends_with(b))
                .map(|at| at + 1);
            assert_eq!(found, end, "{:?}", String::from_utf8_lossy(request));
            if let Some(end) = end {
                use tokio_tungstenite::tungstenite::handshake::machine::TryParse;
                use tokio_tungstenite::tungstenite::handshake::server::Request;
                let parsed = Request::try_parse(request).unwrap().map(|(size, _)| size);
                assert_eq!(parsed, Some(end), "tungstenite's parse agrees");
            }
        }
    }

    #[tokio::test]
    async fn an_upgrade_leaves_the_frames_that_follow_its_request_to_the_reader() {
        use futures_util::SinkExt;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // A client that sends its first frames with the request, in the
        // same write, as a client that does not wait for the response may.
        let client = tokio::spawn(async move {
            let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut bytes = format!(
                "GET / HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                 Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
            )
            .into_bytes();
            bytes.extend(frame(TEXT, b"first"));
            bytes.extend(frame(TEXT, b"second"));
            tcp.write_all(&bytes).await.unwrap();
            let mut response = [0u8; 1024];
            let n = tcp.read(&mut response).await.unwrap();
            assert!(response[..n].starts_with(b"HTTP/1.1 101"));
            tcp
        });
        let (stream, _) = listener.accept().await.unwrap();
        let mut upgraded = tokio_tungstenite::accept_async(UpgradeStream::new(stream))
            .await
            .unwrap();
        let (_tcp, already) = upgraded.get_mut().take_parts().unwrap();
        assert!(upgraded.get_mut().take_parts().is_none(), "taken once");
        assert!(upgraded
            .send(tokio_tungstenite::tungstenite::Message::Text("x".into()))
            .await
            .is_err());
        let mut reader = FrameReader::new(1024, &already);
        assert_eq!(
            feed(&mut reader, &[], 1),
            (vec![text("first"), text("second")], None)
        );
        drop(client.await.unwrap());
    }
}
