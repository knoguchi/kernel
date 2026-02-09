//! Shared VirtIO library for Kenix user-space drivers
//!
//! Provides common VirtIO MMIO transport and virtqueue implementations
//! used by blkdev, netdev, fbdev, and kbdev servers.

#![no_std]

pub mod mmio;
pub mod virtqueue;

pub use mmio::VirtioMmio;
pub use virtqueue::{Virtqueue, VirtqDesc, desc_flags, MAX_QUEUE_SIZE};
