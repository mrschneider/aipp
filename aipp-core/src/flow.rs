//! Backpressure: a slow peer must not freeze the broker.
//!
//! The broker serves every connection from its own thread, but a blocking
//! `write` on a stalled TCP peer parks that thread while it holds the
//! shared state lock. The fix is the standard one: a bounded queue plus a
//! dedicated writer thread per connection. When the queue is full the
//! sender is told, and the broker answers `ERR 509` instead of waiting.

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowError {
    /// the peer is not draining; the message was NOT queued
    Full {
        queued: usize,
    },
    Closed,
}

impl std::fmt::Display for FlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full { queued } => write!(f, "peer is not draining ({queued} queued)"),
            Self::Closed => write!(f, "connection closed"),
        }
    }
}

pub struct Outbox {
    tx: SyncSender<Vec<u8>>,
    capacity: usize,
    sent: Arc<AtomicU64>,
    refused: Arc<AtomicU64>,
}

impl Outbox {
    pub fn spawn<W: Write + Send + 'static>(mut writer: W, capacity: usize) -> Self {
        let capacity = capacity.max(1);
        let (tx, rx) = sync_channel::<Vec<u8>>(capacity);
        let sent = Arc::new(AtomicU64::new(0));
        let s = sent.clone();
        std::thread::spawn(move || {
            while let Ok(chunk) = rx.recv() {
                if writer.write_all(&chunk).is_err() || writer.flush().is_err() {
                    break;
                }
                s.fetch_add(1, Ordering::Relaxed);
            }
        });
        Self {
            tx,
            capacity,
            sent,
            refused: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn send(&self, bytes: Vec<u8>) -> Result<(), FlowError> {
        match self.tx.try_send(bytes) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                self.refused.fetch_add(1, Ordering::Relaxed);
                Err(FlowError::Full {
                    queued: self.capacity,
                })
            }
            Err(TrySendError::Disconnected(_)) => Err(FlowError::Closed),
        }
    }

    pub fn stats(&self) -> (u64, u64) {
        (
            self.sent.load(Ordering::Relaxed),
            self.refused.load(Ordering::Relaxed),
        )
    }
}

/// Receive-side credit: a producer of TLV frames may only send what the
/// consumer has granted, so a token stream cannot outrun its reader.
#[derive(Debug, Clone)]
pub struct CreditWindow {
    capacity: usize,
    used: usize,
}

impl CreditWindow {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            used: 0,
        }
    }

    pub fn take(&mut self, n: usize) -> bool {
        if self.used + n > self.capacity {
            return false;
        }
        self.used += n;
        true
    }

    pub fn release(&mut self, n: usize) {
        self.used = self.used.saturating_sub(n);
    }

    pub fn available(&self) -> usize {
        self.capacity.saturating_sub(self.used)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;
    use std::time::Duration;

    struct Sink(Arc<std::sync::Mutex<Vec<u8>>>);
    impl Write for Sink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_draining_peer_gets_everything_in_order() {
        let out = Arc::new(std::sync::Mutex::new(Vec::new()));
        let ob = Outbox::spawn(Sink(out.clone()), 8);
        for i in 0..5u8 {
            ob.send(vec![i]).unwrap();
        }
        for _ in 0..50 {
            if ob.stats().0 == 5 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(*out.lock().unwrap(), vec![0, 1, 2, 3, 4]);
        assert_eq!(ob.stats().1, 0, "no refusals for a draining peer");
    }

    #[test]
    fn a_stalled_peer_is_refused_not_awaited() {
        struct Stalled(std::sync::mpsc::Receiver<()>);
        impl Write for Stalled {
            fn write(&mut self, _b: &[u8]) -> std::io::Result<usize> {
                let _ = self.0.recv_timeout(Duration::from_millis(30));
                Ok(0)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let (tx, rx) = channel::<()>();
        let ob = Outbox::spawn(Stalled(rx), 1);
        let mut refused = 0;
        for _ in 0..10 {
            if ob.send(vec![1, 2, 3]).is_err() {
                refused += 1;
            }
        }
        assert!(refused > 0, "a stalled peer must produce refusals");
        drop(tx);
    }

    #[test]
    fn credit_is_granted_and_returned() {
        let mut w = CreditWindow::new(4);
        assert!(w.take(3));
        assert!(!w.take(2));
        assert_eq!(w.available(), 1);
        w.release(3);
        assert_eq!(w.available(), 4);
        assert!(w.take(4));
    }
}
