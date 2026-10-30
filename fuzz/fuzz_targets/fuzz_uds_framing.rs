// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// Fuzz target: `mesh_port_protocol::framing`, the Unix socket's length
// prefix, under arbitrary chunking.
//
// The input builds a byte stream: frames made with `encode_frame` from
// payloads in the input, bare prefixes declaring any length, and stray
// bytes. It then cuts the stream into pieces whose sizes it also chooses,
// empty pieces included, and pushes them into a `FrameDecoder` with a cap
// it chooses, popping after every push until the decoder has nothing more.
//
// Invariants:
// - every pop returns what a stateless reading of the stream so far says
//   is next: the next frame, nothing yet, or `Oversized` with the declared
//   length as soon as a prefix over the cap is complete; after
//   `Oversized`, every later pop returns it again;
// - `buffered()` is exactly the bytes pushed and not yet returned;
// - a stream of `encode_frame` frames within the cap comes out as exactly
//   those payloads, in order, leaving nothing behind;
// - the decoder holds only bytes that arrived: a pop that returns nothing
//   or `Oversized` allocates nothing, a pop that returns a frame allocates
//   no more than the frame, and a push never asks for more than the
//   amortised doubling of what the decoder holds (so a declared length is
//   never reserved, within the cap or over it).

#![no_main]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use libfuzzer_sys::arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use mesh_port_protocol::framing::{encode_frame, FrameDecoder, FrameError, PREFIX_LEN};

/// Most parts (frames, bare prefixes, stray bytes) in one stream.
const MAX_PARTS: usize = 24;
/// Longest payload drawn for a frame.
const MAX_PAYLOAD: usize = 600;
/// Most pushes before the rest of the stream goes in at once.
const MAX_PUSHES: usize = 4096;

/// The global allocator, counting what is asked of it so the target can
/// see what a push or a pop allocates.
struct Counting;

/// Bytes requested since the last [`measure`] began.
static REQUESTED: AtomicUsize = AtomicUsize::new(0);
/// The largest single request since the last [`measure`] began.
static LARGEST: AtomicUsize = AtomicUsize::new(0);

fn note(size: usize) {
    REQUESTED.fetch_add(size, Ordering::Relaxed);
    LARGEST.fetch_max(size, Ordering::Relaxed);
}

// SAFETY: every method passes its arguments unchanged to `System` and
// returns what `System` returns, so this allocator keeps `System`'s
// contract; the counting touches only atomics and never allocates.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract, which
        // is `System.alloc`'s.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        // SAFETY: as for `alloc`.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note(new_size);
        // SAFETY: `ptr` came from this allocator, so from `System`, with
        // `layout`; the caller upholds the rest of `realloc`'s contract.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from this allocator, so from `System`, with
        // `layout`.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// What `f` allocated: its result, the bytes it requested in all, and its
/// largest single request.
fn measure<T>(f: impl FnOnce() -> T) -> (T, usize, usize) {
    REQUESTED.store(0, Ordering::Relaxed);
    LARGEST.store(0, Ordering::Relaxed);
    let out = f();
    (
        out,
        REQUESTED.load(Ordering::Relaxed),
        LARGEST.load(Ordering::Relaxed),
    )
}

/// What `pop` must return when `pending` is the stream's bytes pushed and
/// not yet returned: read statelessly from the front.
fn expected(pending: &[u8], max: usize) -> std::result::Result<Option<Vec<u8>>, FrameError> {
    let Some((prefix, rest)) = pending.split_first_chunk::<PREFIX_LEN>() else {
        return Ok(None);
    };
    let len = u32::from_be_bytes(*prefix) as usize;
    if len > max {
        return Err(FrameError::Oversized { len, max });
    }
    Ok(rest.get(..len).map(<[u8]>::to_vec))
}

fuzz_target!(|data: &[u8]| {
    let _ = fuzz(data);
});

fn fuzz(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    // Caps from none at all to more than any prefix can declare, so that a
    // partial frame far larger than what arrived is common.
    let max = match u.int_in_range(0..=3u8)? {
        0 => u.int_in_range(0..=64)?,
        1 => u.int_in_range(0..=4096)?,
        2 => 16 << 20,
        _ => usize::MAX,
    };

    let mut stream = Vec::new();
    let mut payloads = Vec::new();
    let mut only_frames = true;
    for _ in 0..u.int_in_range(0..=MAX_PARTS)? {
        match u.int_in_range(0..=5u8)? {
            0..=3 => {
                let len = u.int_in_range(0..=MAX_PAYLOAD)?;
                let payload = u.bytes(len.min(u.len()))?;
                let frame = encode_frame(payload).expect("a short payload frames");
                assert_eq!(
                    frame[..PREFIX_LEN],
                    (payload.len() as u32).to_be_bytes(),
                    "the prefix"
                );
                assert_eq!(
                    &frame[PREFIX_LEN..],
                    payload,
                    "the payload after the prefix"
                );
                stream.extend_from_slice(&frame);
                payloads.push(payload.to_vec());
            }
            4 => {
                // A bare prefix declaring any length; whatever follows is
                // read as its payload.
                stream.extend_from_slice(&u.arbitrary::<u32>()?.to_be_bytes());
                only_frames = false;
            }
            _ => {
                let len = u.int_in_range(0..=16)?;
                stream.extend_from_slice(u.bytes(len.min(u.len()))?);
                only_frames = false;
            }
        }
    }

    let mut decoder = FrameDecoder::new(max);
    let (mut pushed, mut consumed) = (0, 0);
    let mut popped = Vec::new();
    let mut refused = None;
    let mut pushes = 0;
    while pushed < stream.len() || pushes == 0 {
        let left = stream.len() - pushed;
        let size = if u.is_empty() || pushes >= MAX_PUSHES {
            left
        } else {
            u.int_in_range(0..=left)?
        };
        let piece = &stream[pushed..pushed + size];
        let held = decoder.buffered();
        let ((), _, largest) = measure(|| decoder.push(piece));
        // Growing the buffer at most doubles what it must hold, which is the
        // bytes not yet returned, at most as many again returned but not yet
        // reclaimed, and the piece. `Vec`'s smallest allocation is 8 bytes.
        let bound = (4 * held + 2 * size).max(8);
        assert!(
            largest <= bound,
            "a push of {size} bytes onto {held} held asked for {largest} bytes"
        );
        pushed += size;
        pushes += 1;

        loop {
            let (got, total, largest) = measure(|| decoder.pop());
            let want = expected(&stream[consumed..pushed], max);
            assert_eq!(
                got, want,
                "pop disagrees with the stream after {pushed} bytes pushed"
            );
            match got {
                Ok(Some(frame)) => {
                    assert!(
                        total <= frame.len() && largest <= frame.len(),
                        "a pop of a {} byte frame allocated {total} bytes",
                        frame.len()
                    );
                    consumed += PREFIX_LEN + frame.len();
                    popped.push(frame);
                }
                Ok(None) => {
                    assert_eq!(
                        total, 0,
                        "a pop that returned nothing allocated {total} bytes"
                    );
                    break;
                }
                Err(err) => {
                    assert_eq!(total, 0, "a refusing pop allocated {total} bytes");
                    if let Some(first) = refused {
                        assert_eq!(err, first, "the refusal changed");
                    }
                    refused = Some(err);
                    break;
                }
            }
            assert_eq!(
                decoder.buffered(),
                pushed - consumed,
                "buffered() after a pop"
            );
        }
        assert_eq!(
            decoder.buffered(),
            pushed - consumed,
            "buffered() after a push"
        );
    }

    // A refusal is final: more bytes do not resynchronise the stream.
    if let Some(err) = refused {
        decoder.push(&[0; PREFIX_LEN]);
        assert_eq!(
            decoder.pop(),
            Err(err),
            "the stream resynchronised after a refusal"
        );
    }
    if only_frames && payloads.iter().all(|p| p.len() <= max) {
        assert_eq!(
            popped, payloads,
            "the frames came out changed or out of order"
        );
        assert_eq!(
            decoder.buffered(),
            0,
            "bytes left over after the last frame"
        );
    }
    Ok(())
}
