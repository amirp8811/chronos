//! Bounded queue/backpressure primitive for relay tests.

use chronos_core::{RelayErrorCode, RelayPacket};
use std::collections::VecDeque;
use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueError {
    Full(RelayErrorCode),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedRelayPacket {
    pub packet: RelayPacket,
    pub destination: SocketAddr,
}

pub struct BoundedRelayQueue {
    max_len: usize,
    queue: VecDeque<QueuedRelayPacket>,
}

impl BoundedRelayQueue {
    pub fn new(max_len: usize) -> Self {
        Self {
            max_len: max_len.max(1),
            queue: VecDeque::new(),
        }
    }
    pub fn push(&mut self, item: QueuedRelayPacket) -> Result<(), QueueError> {
        if self.queue.len() >= self.max_len {
            return Err(QueueError::Full(RelayErrorCode::QueueFull));
        }
        self.queue.push_back(item);
        Ok(())
    }
    pub fn pop(&mut self) -> Option<QueuedRelayPacket> {
        self.queue.pop_front()
    }
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.queue.len()
    }
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_queue_rejects_overflow() {
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let mut q = BoundedRelayQueue::new(1);
        assert!(q.is_empty());
        q.push(QueuedRelayPacket {
            packet: RelayPacket::data(1, 1, b"a".to_vec()).unwrap(),
            destination: addr,
        })
        .unwrap();
        assert_eq!(q.len(), 1);
        assert_eq!(
            q.push(QueuedRelayPacket {
                packet: RelayPacket::data(1, 2, b"b".to_vec()).unwrap(),
                destination: addr,
            }),
            Err(QueueError::Full(RelayErrorCode::QueueFull))
        );
        assert_eq!(q.pop().unwrap().packet.sequence, 1);
    }
}
