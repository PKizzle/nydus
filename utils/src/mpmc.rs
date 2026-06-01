// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Asynchronous Multi-Producer Multi-Consumer channel.
//!
//! This module provides an asynchronous multi-producer multi-consumer channel based on [event_listener::Event].

use std::collections::VecDeque;
use std::io::{Error, ErrorKind, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

use event_listener::Event;

/// An asynchronous multi-producer multi-consumer channel based on [event_listener::Event].
///
/// `event_listener` is runtime-agnostic, so the channel is driven from the
/// compio prefetch worker without a tokio runtime.
pub struct Channel<T> {
    closed: AtomicBool,
    notifier: Event,
    requests: Mutex<VecDeque<T>>,
}

impl<T> Default for Channel<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Channel<T> {
    /// Create a new instance of [`Channel`].
    pub fn new() -> Self {
        Channel {
            closed: AtomicBool::new(false),
            notifier: Event::new(),
            requests: Mutex::new(VecDeque::new()),
        }
    }

    /// Close the channel.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        // Wake every waiter so they observe the closed state.
        self.notifier.notify(usize::MAX);
    }

    /// Send a message to the channel.
    ///
    /// The message object will be returned on error, to ease the lifecycle management.
    pub fn send(&self, msg: T) -> std::result::Result<(), T> {
        if self.closed.load(Ordering::Acquire) {
            Err(msg)
        } else {
            self.requests.lock().unwrap().push_back(msg);
            self.notifier.notify(1);
            Ok(())
        }
    }

    /// Try to receive a message from the channel.
    pub fn try_recv(&self) -> Option<T> {
        self.requests.lock().unwrap().pop_front()
    }

    /// Receive message from the channel in asynchronous mode.
    pub async fn recv(&self) -> Result<T> {
        loop {
            // Register a listener BEFORE checking the queue, so a `send`/`close`
            // racing between the check and the await cannot be missed (the same
            // pattern `async-channel` uses over `event_listener`).
            let listener = self.notifier.listen();

            if let Some(msg) = self.try_recv() {
                return Ok(msg);
            }
            if self.closed.load(Ordering::Acquire) {
                return Err(Error::new(ErrorKind::BrokenPipe, "channel has been closed"));
            }

            // Wait for a `send`/`close` notification, then re-check the queue.
            listener.await;
        }
    }

    /// Flush all pending requests specified by the predicator.
    ///
    pub fn flush_pending_prefetch_requests<F>(&self, mut f: F)
    where
        F: FnMut(&T) -> bool,
    {
        self.requests.lock().unwrap().retain(|t| !f(t));
    }

    /// Lock the channel to block all queue operations.
    pub fn lock_channel(&self) -> MutexGuard<'_, VecDeque<T>> {
        self.requests.lock().unwrap()
    }

    /// Notify all waiters.
    pub fn notify_waiters(&self) {
        self.notifier.notify(usize::MAX);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_new_channel() {
        let channel = Channel::new();

        channel.send(1u32).unwrap();
        channel.send(2u32).unwrap();
        assert_eq!(channel.try_recv().unwrap(), 1);
        assert_eq!(channel.try_recv().unwrap(), 2);

        channel.close();
        channel.send(2u32).unwrap_err();
    }

    #[test]
    fn test_flush_channel() {
        let channel = Channel::new();

        channel.send(1u32).unwrap();
        channel.send(2u32).unwrap();
        channel.flush_pending_prefetch_requests(|_| true);
        assert!(channel.try_recv().is_none());

        channel.notify_waiters();
        let _guard = channel.lock_channel();
    }

    #[test]
    fn test_async_recv() {
        let channel = Arc::new(Channel::new());
        let channel2 = channel.clone();

        let t = std::thread::spawn(move || {
            channel2.send(1u32).unwrap();
        });

        // The channel is runtime-agnostic now; drive `recv` with a plain
        // `futures` executor instead of a tokio runtime.
        futures::executor::block_on(async {
            let msg = channel.recv().await.unwrap();
            assert_eq!(msg, 1);
        });

        t.join().unwrap();
    }

    #[test]
    fn test_default_channel_send_and_recv() {
        let channel = Channel::default();

        channel.send(0x1u32).unwrap();
        channel.send(0x2u32).unwrap();
        assert_eq!(channel.try_recv().unwrap(), 0x1);
        assert_eq!(channel.try_recv().unwrap(), 0x2);

        channel.close();
        channel.send(2u32).unwrap_err();
    }

    #[test]
    fn test_flush_keeps_matching() {
        let channel = Channel::new();
        channel.send(1u32).unwrap();
        channel.send(2u32).unwrap();
        channel.send(3u32).unwrap();
        // Flush odd numbers, keep even numbers
        channel.flush_pending_prefetch_requests(|&t| t % 2 == 1);
        assert_eq!(channel.try_recv().unwrap(), 2);
        assert!(channel.try_recv().is_none());
    }

    #[test]
    fn test_recv_closed_channel_returns_broken_pipe() {
        let channel = Arc::new(Channel::<u32>::new());
        channel.close();

        futures::executor::block_on(async {
            let result = channel.recv().await;
            assert!(result.is_err());
            assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
        });
    }
}
