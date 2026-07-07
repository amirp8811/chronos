//! Local secure UDP shard transport helpers for `chronos-lite`.
//!
//! This module contains the first concrete UDP datagram boundary for encrypted
//! CHRONOS shard cells. It intentionally handles only exact 1,200-byte app-cell
//! payloads; outer IP/UDP/QUIC overhead is represented elsewhere in the spec's
//! 1,280-byte wire budget.

use chronos_core::{
    APP_CELL_PAYLOAD_SIZE, RELAY_PACKET_MAX_BYTES, RelayDecision, RelayHandlerError, RelayPacket,
    RelayPacketError, RelayPacketHandler, SecureCellError, SecureShardCell,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecureUdpError {
    InvalidLength { got: usize, expected: usize },
    InvalidCell(SecureCellError),
}

/// Parse one UDP payload as an exact encrypted CHRONOS app cell.
pub fn parse_secure_app_datagram(buf: &[u8]) -> Result<SecureShardCell, SecureUdpError> {
    if buf.len() != APP_CELL_PAYLOAD_SIZE {
        return Err(SecureUdpError::InvalidLength {
            got: buf.len(),
            expected: APP_CELL_PAYLOAD_SIZE,
        });
    }

    let mut bytes = [0u8; APP_CELL_PAYLOAD_SIZE];
    bytes.copy_from_slice(buf);
    SecureShardCell::from_app_cell_bytes(&bytes).map_err(SecureUdpError::InvalidCell)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecureRelayUdpError {
    InvalidLength { got: usize, max: usize },
    InvalidPacket(RelayPacketError),
    Handler(RelayHandlerError),
}

/// Parse one UDP payload as a CHRONOS relay packet carrying an encrypted shard.
pub fn parse_secure_relay_datagram(buf: &[u8]) -> Result<RelayPacket, SecureRelayUdpError> {
    if buf.len() > RELAY_PACKET_MAX_BYTES {
        return Err(SecureRelayUdpError::InvalidLength {
            got: buf.len(),
            max: RELAY_PACKET_MAX_BYTES,
        });
    }
    let packet = RelayPacket::decode(buf).map_err(SecureRelayUdpError::InvalidPacket)?;
    // Enforce that relay payloads contain intact, typed CHRONOS payloads.
    match packet.packet_type {
        chronos_core::RelayPacketType::Shard => {
            packet
                .shard_cell()
                .map_err(SecureRelayUdpError::InvalidPacket)?;
        }
        chronos_core::RelayPacketType::Route => {
            packet
                .route_packet()
                .map_err(SecureRelayUdpError::InvalidPacket)?;
        }
        _ => {
            return Err(SecureRelayUdpError::InvalidPacket(
                chronos_core::RelayPacketError::UnknownType(packet.packet_type as u8),
            ));
        }
    }
    Ok(packet)
}

pub fn process_secure_relay_datagram(
    handler: &mut RelayPacketHandler,
    buf: &[u8],
) -> Result<RelayDecision, SecureRelayUdpError> {
    let packet = parse_secure_relay_datagram(buf)?;
    handler
        .process(packet)
        .map_err(SecureRelayUdpError::Handler)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chronos_core::{SecureShardBlockCodec, derive_link_key};
    use std::net::SocketAddr;
    use tokio::net::UdpSocket;

    fn test_key() -> [u8; 32] {
        derive_link_key(&[0x5Au8; 32], &[0xA5u8; 16]).expect("key")
    }

    async fn relay_exact_secure_shards(
        relay: UdpSocket,
        destination: SocketAddr,
        count: usize,
    ) -> usize {
        let mut handler = RelayPacketHandler::new(128).expect("handler");
        let mut forwarded = 0usize;
        let mut buf = [0u8; RELAY_PACKET_MAX_BYTES];
        for _ in 0..count {
            let (len, src) = relay.recv_from(&mut buf).await.expect("relay recv");
            let decision = process_secure_relay_datagram(&mut handler, &buf[..len])
                .expect("relay handler decision");
            match decision {
                RelayDecision::ForwardShard { packet, ack } => {
                    let out = packet.encode().expect("relay encode");
                    let sent = relay.send_to(&out, destination).await.expect("relay send");
                    assert_eq!(sent, out.len());

                    let ack_bytes = ack.encode().expect("ack encode");
                    let ack_sent = relay.send_to(&ack_bytes, src).await.expect("ack send");
                    assert_eq!(ack_sent, ack_bytes.len());
                    forwarded += 1;
                }
                RelayDecision::ForwardRoute { packet, ack } => {
                    let out = packet.encode().expect("relay route encode");
                    let sent = relay
                        .send_to(&out, destination)
                        .await
                        .expect("relay route send");
                    assert_eq!(sent, out.len());

                    let ack_bytes = ack.encode().expect("route ack encode");
                    let ack_sent = relay
                        .send_to(&ack_bytes, src)
                        .await
                        .expect("route ack send");
                    assert_eq!(ack_sent, ack_bytes.len());
                    forwarded += 1;
                }
                RelayDecision::Respond(response) => {
                    let response_bytes = response.encode().expect("response encode");
                    let sent = relay
                        .send_to(&response_bytes, src)
                        .await
                        .expect("response send");
                    assert_eq!(sent, response_bytes.len());
                }
            }
        }
        forwarded
    }

    #[tokio::test]
    async fn localhost_udp_transports_encrypted_erasure_shards() {
        let codec = SecureShardBlockCodec::new();
        let message = b"chronos-lite localhost secure UDP shard integration".repeat(64);
        let cells = codec
            .encode_message(&test_key(), [0x11; 16], 100, 50_000, &message)
            .expect("encode");

        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("receiver");
        let receiver_addr = receiver.local_addr().expect("receiver addr");
        let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender");

        for cell in cells.iter().take(10) {
            let bytes = cell.to_app_cell_bytes();
            let sent = sender
                .send_to(&bytes, receiver_addr)
                .await
                .expect("send shard");
            assert_eq!(sent, APP_CELL_PAYLOAD_SIZE);
        }

        let mut received_cells = Vec::with_capacity(10);
        let mut buf = [0u8; APP_CELL_PAYLOAD_SIZE];
        for _ in 0..10 {
            let (len, _) = receiver.recv_from(&mut buf).await.expect("recv shard");
            received_cells.push(parse_secure_app_datagram(&buf[..len]).expect("parse cell"));
        }

        let recovered = codec
            .decode_message(test_key(), &received_cells)
            .expect("decode received shards");
        assert_eq!(recovered, message);
    }

    #[tokio::test]
    async fn localhost_udp_relay_forwards_secure_shards_without_decrypting() {
        let codec = SecureShardBlockCodec::new();
        let message = b"sender to relay to receiver secure shard path".repeat(96);
        let cells = codec
            .encode_message(&test_key(), [0x22; 16], 101, 60_000, &message)
            .expect("encode");

        let relay = UdpSocket::bind("127.0.0.1:0").await.expect("relay");
        let relay_addr = relay.local_addr().expect("relay addr");
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("receiver");
        let receiver_addr = receiver.local_addr().expect("receiver addr");
        let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender");

        let relay_task = tokio::spawn(relay_exact_secure_shards(relay, receiver_addr, 10));

        for (offset, cell) in cells.iter().skip(3).take(10).enumerate() {
            let packet = RelayPacket::shard(9001, offset as u64, cell).expect("relay packet");
            let bytes = packet.encode().expect("encode relay packet");
            let sent = sender
                .send_to(&bytes, relay_addr)
                .await
                .expect("send to relay");
            assert_eq!(sent, bytes.len());
        }

        let mut ack_buf = [0u8; RELAY_PACKET_MAX_BYTES];
        for expected_seq in 0..10u64 {
            let (len, _) = sender.recv_from(&mut ack_buf).await.expect("recv ack");
            let ack = RelayPacket::decode(&ack_buf[..len]).expect("decode ack");
            assert_eq!(ack.stream_id, 9001);
            assert_eq!(ack.sequence, expected_seq);
            assert_eq!(ack.payload, b"OK");
        }
        assert_eq!(relay_task.await.expect("relay task"), 10);

        let mut received_cells = Vec::with_capacity(10);
        let mut buf = [0u8; RELAY_PACKET_MAX_BYTES];
        for _ in 0..10 {
            let (len, _) = receiver.recv_from(&mut buf).await.expect("recv forwarded");
            let packet = parse_secure_relay_datagram(&buf[..len]).expect("parse forwarded");
            assert_eq!(packet.stream_id, 9001);
            received_cells.push(packet.shard_cell().expect("forwarded shard cell"));
        }

        let recovered = codec
            .decode_message(test_key(), &received_cells)
            .expect("decode forwarded shards");
        assert_eq!(recovered, message);
    }

    #[test]
    fn parse_rejects_wrong_length_datagrams() {
        assert_eq!(
            parse_secure_app_datagram(&[0u8; 16]),
            Err(SecureUdpError::InvalidLength {
                got: 16,
                expected: APP_CELL_PAYLOAD_SIZE,
            })
        );
    }

    #[test]
    fn parse_rejects_oversized_relay_datagrams() {
        let oversized = vec![0u8; RELAY_PACKET_MAX_BYTES + 1];
        assert_eq!(
            parse_secure_relay_datagram(&oversized),
            Err(SecureRelayUdpError::InvalidLength {
                got: RELAY_PACKET_MAX_BYTES + 1,
                max: RELAY_PACKET_MAX_BYTES,
            })
        );
    }

    #[tokio::test]
    async fn localhost_udp_relay_forwards_route_packets_without_peeling() {
        use chronos_core::{RouteCommand, RouteHopSecret, build_layered_route_packet};

        let secrets = vec![RouteHopSecret([0xA1; 32]), RouteHopSecret([0xA2; 32])];
        let commands = vec![RouteCommand::forward(100), RouteCommand::deliver_local()];
        let route = build_layered_route_packet(12_345, &secrets, &commands, b"routed payload")
            .expect("route");

        let relay = UdpSocket::bind("127.0.0.1:0").await.expect("relay");
        let relay_addr = relay.local_addr().expect("relay addr");
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("receiver");
        let receiver_addr = receiver.local_addr().expect("receiver addr");
        let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender");

        let relay_task = tokio::spawn(relay_exact_secure_shards(relay, receiver_addr, 1));
        let packet = RelayPacket::route(4242, 1, &route).expect("route relay packet");
        let bytes = packet.encode().expect("encode");
        sender
            .send_to(&bytes, relay_addr)
            .await
            .expect("send route");

        let mut ack_buf = [0u8; RELAY_PACKET_MAX_BYTES];
        let (ack_len, _) = sender.recv_from(&mut ack_buf).await.expect("ack");
        let ack = RelayPacket::decode(&ack_buf[..ack_len]).expect("decode ack");
        assert_eq!(ack.stream_id, 4242);
        assert_eq!(ack.sequence, 1);
        assert_eq!(relay_task.await.expect("relay task"), 1);

        let mut recv_buf = [0u8; RELAY_PACKET_MAX_BYTES];
        let (recv_len, _) = receiver.recv_from(&mut recv_buf).await.expect("recv route");
        let forwarded =
            parse_secure_relay_datagram(&recv_buf[..recv_len]).expect("forwarded route");
        assert_eq!(forwarded.route_packet().expect("route payload"), route);
    }

    #[test]
    fn relay_datagram_processing_rejects_duplicate_sequence() {
        let codec = SecureShardBlockCodec::new();
        let cells = codec
            .encode_message(&test_key(), [0x44; 16], 102, 70_000, b"duplicate relay seq")
            .expect("encode");
        let packet = RelayPacket::shard(1234, 1, &cells[0]).expect("packet");
        let bytes = packet.encode().expect("encode");
        let mut handler = RelayPacketHandler::new(128).expect("handler");
        assert!(process_secure_relay_datagram(&mut handler, &bytes).is_ok());
        assert!(matches!(
            process_secure_relay_datagram(&mut handler, &bytes),
            Err(SecureRelayUdpError::Handler(_))
        ));
    }
}
