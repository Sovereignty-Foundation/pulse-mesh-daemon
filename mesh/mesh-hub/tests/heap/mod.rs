// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A counting global allocator for the tests that measure the daemon's
//! heap. A test file that includes this module makes it its binary's
//! allocator, so such a file holds one measuring test, run alone.
#![allow(dead_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Heap bytes allocated and not yet freed.
pub(crate) static LIVE: AtomicUsize = AtomicUsize::new(0);

/// The most `LIVE` has been since it was last reset.
pub(crate) static PEAK: AtomicUsize = AtomicUsize::new(0);

/// The system allocator, keeping `LIVE` and `PEAK`.
pub(crate) struct Counting;

impl Counting {
    fn grew(by: usize) {
        let live = LIVE.fetch_add(by, Ordering::Relaxed) + by;
        PEAK.fetch_max(live, Ordering::Relaxed);
    }

    fn shrank(by: usize) {
        LIVE.fetch_sub(by, Ordering::Relaxed);
    }
}

// SAFETY: every method passes its arguments unchanged to the system
// allocator and returns its result, so each keeps `GlobalAlloc`'s contract
// exactly as `System` does; the counting only updates atomics, which never
// allocate.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's guarantee for `alloc` (a layout of non-zero
        // size) is passed on to `System` unchanged.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            Self::grew(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as for `alloc`.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            Self::grew(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller guarantees that `ptr` came from this allocator,
        // which is `System`, with this `layout`.
        unsafe { System.dealloc(ptr, layout) };
        Self::shrank(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller guarantees that `ptr` came from this allocator,
        // which is `System`, with `layout`, and that `new_size` is valid for
        // `layout`'s alignment.
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            Self::shrank(layout.size());
            Self::grew(new_size);
        }
        new
    }
}

#[global_allocator]
static HEAP: Counting = Counting;
