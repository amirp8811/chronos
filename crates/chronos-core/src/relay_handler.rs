//! Minimal validated relay handler.
//!
//! This turns the relay packet envelope into a small stateful relay decision
//! engine: shard packets are parsed, embedded secure cells are envelope-checked,
//! relay-level sequence replay is enforced per stream, and the caller receives a
//! forwarding decision plus an ACK packet. The handler does not decrypt shard
//! payloads.

use std::collections::HashMap;

use crate::relay_packet::{RelayPacket, RelayPacketError, RelayPacketType};
use crate::route_layer::{RouteLayerError, RouteReplayCache};
use crate::secure_cell::{ReplayError, ReplayWindow};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayHandlerError {
    Packet(RelayPacketError),
    Replay(ReplayError),
    UnsupportedType(RelayPacketType),
    Route(RouteLayerError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayDecision {
    ForwardShard {
        packet: RelayPacket,
        ack: RelayPacket,
    },
    ForwardRoute {
        packet: RelayPacket,
        ack: RelayPacket,
    },
    Respond(RelayPacket),
}

pub struct RelayPacketHandler {
    replay_window_size: usize,
    streams: HashMap<u64, ReplayWindow>,
    route_replay: RouteReplayCache,
}

impl RelayPacketHandler {
    pub fn new(replay_window_size: usize) -> Result<Self, ReplayError> {
        // Validate once up front; per-stream windows use the same size.
        ReplayWindow::new(replay_window_size)?;
        Ok(Self {
            replay_window_size,
            streams: HashMap::new(),
            route_replay: RouteReplayCache::new(),
        })
    }

    pub fn process(&mut self, packet: RelayPacket) -> Result<RelayDecision, RelayHandlerError> {
        match packet.packet_type {
            RelayPacketType::Shard => self.process_shard(packet),
            RelayPacketType::Route => self.process_route(packet),
            RelayPacketType::Hello
            | RelayPacketType::Ack
            | RelayPacketType::Error
            | RelayPacketType::Data => Err(RelayHandlerError::UnsupportedType(packet.packet_type)),
        }
    }

    fn process_shard(&mut self, packet: RelayPacket) -> Result<RelayDecision, RelayHandlerError> {
        // Validate that the payload is an intact secure shard cell. This checks
        // envelope/header structure but intentionally does not decrypt.
        packet.shard_cell().map_err(RelayHandlerError::Packet)?;

        let replay = self.streams.entry(packet.stream_id).or_insert(
            ReplayWindow::new(self.replay_window_size).map_err(RelayHandlerError::Replay)?,
        );
        replay
            .observe(packet.sequence)
            .map_err(RelayHandlerError::Replay)?;

        let ack = RelayPacket::ack(packet.stream_id, packet.sequence)?;
        Ok(RelayDecision::ForwardShard { packet, ack })
    }

    fn process_route(&mut self, packet: RelayPacket) -> Result<RelayDecision, RelayHandlerError> {
        let route_packet = packet.route_packet().map_err(RelayHandlerError::Packet)?;
        self.route_replay
            .observe(&route_packet)
            .map_err(RelayHandlerError::Route)?;
        let ack = RelayPacket::ack(packet.stream_id, packet.sequence)?;
        Ok(RelayDecision::ForwardRoute { packet, ack })
    }
}

impl Default for RelayPacketHandler {
    fn default() -> Self {
        Self::new(128).expect("default replay window is valid")
    }
}

impl From<RelayPacketError> for RelayHandlerError {
    fn from(value: RelayPacketError) -> Self {
        Self::Packet(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_cell::{SecureShardCell, derive_link_key};

    fn test_cell(seq: u64) -> SecureShardCell {
        let key = derive_link_key(&[0x31u8; 32], &[0x13u8; 16]).expect("key");
        SecureShardCell::encrypt(&key, [0x13; 16], seq, 0, b"relay handler cell").expect("cell")
    }

    #[test]
    fn handler_forwards_valid_shard_and_generates_ack() {
        let cell = test_cell(7);
        let packet = RelayPacket::shard(42, 7, &cell).expect("packet");
        let mut handler = RelayPacketHandler::new(16).expect("handler");

        let decision = handler.process(packet.clone()).expect("decision");
        match decision {
            RelayDecision::ForwardShard { packet: fwd, ack } => {
                assert_eq!(fwd, packet);
                assert_eq!(ack.packet_type, RelayPacketType::Ack);
                assert_eq!(ack.stream_id, 42);
                assert_eq!(ack.sequence, 7);
                assert_eq!(ack.payload, b"OK");
            }
            other => panic!("unexpected decision: {other:?}"),
        }
    }

    #[test]
    fn handler_rejects_duplicate_relay_sequence_per_stream() {
        let cell = test_cell(8);
        let packet = RelayPacket::shard(7, 8, &cell).expect("packet");
        let mut handler = RelayPacketHandler::new(16).expect("handler");
        handler.process(packet.clone()).expect("first packet");

        assert_eq!(
            handler.process(packet),
            Err(RelayHandlerError::Replay(ReplayError::Duplicate { seq: 8 }))
        );
    }

    #[test]
    fn handler_allows_same_sequence_on_different_streams() {
        let cell = test_cell(9);
        let packet_a = RelayPacket::shard(1, 9, &cell).expect("packet a");
        let packet_b = RelayPacket::shard(2, 9, &cell).expect("packet b");
        let mut handler = RelayPacketHandler::new(16).expect("handler");

        assert!(handler.process(packet_a).is_ok());
        assert!(handler.process(packet_b).is_ok());
    }

    #[test]
    fn handler_forwards_valid_route_packet() {
        use crate::route_layer::{RouteCommand, RouteHopSecret, build_layered_route_packet};
        let secrets = vec![RouteHopSecret([1u8; 32]), RouteHopSecret([2u8; 32])];
        let commands = vec![RouteCommand::forward(10), RouteCommand::deliver_local()];
        let route = build_layered_route_packet(901, &secrets, &commands, b"route").expect("route");
        let packet = RelayPacket::route(77, 88, &route).expect("packet");
        let mut handler = RelayPacketHandler::new(16).expect("handler");
        match handler.process(packet.clone()).expect("decision") {
            RelayDecision::ForwardRoute { packet: fwd, ack } => {
                assert_eq!(fwd, packet);
                assert_eq!(ack.packet_type, RelayPacketType::Ack);
                assert_eq!(ack.stream_id, 77);
                assert_eq!(ack.sequence, 88);
            }
            other => panic!("unexpected decision: {other:?}"),
        }
    }

    #[test]
    fn handler_rejects_duplicate_route_packet_id() {
        use crate::route_layer::{RouteCommand, RouteHopSecret, build_layered_route_packet};
        let secrets = vec![RouteHopSecret([3u8; 32]), RouteHopSecret([4u8; 32])];
        let commands = vec![RouteCommand::forward(10), RouteCommand::deliver_local()];
        let route = build_layered_route_packet(902, &secrets, &commands, b"route").expect("route");
        let packet_a = RelayPacket::route(77, 1, &route).expect("packet a");
        let packet_b = RelayPacket::route(77, 2, &route).expect("packet b");
        let mut handler = RelayPacketHandler::new(16).expect("handler");
        handler.process(packet_a).expect("first");
        assert_eq!(
            handler.process(packet_b),
            Err(RelayHandlerError::Route(RouteLayerError::Replay {
                packet_id: 902,
                hop_index: 0,
            }))
        );
    }

    #[test]
    fn handler_rejects_unsupported_packet_type() {
        let packet =
            RelayPacket::new(RelayPacketType::Hello, 0, 1, 1, b"hello".to_vec()).expect("hello");
        let mut handler = RelayPacketHandler::new(16).expect("handler");
        assert_eq!(
            handler.process(packet),
            Err(RelayHandlerError::UnsupportedType(RelayPacketType::Hello))
        );
    }
}
