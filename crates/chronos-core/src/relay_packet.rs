//! Minimal CHRONOS relay packet envelope.
//!
//! The secure app cell is exactly 1,200 bytes. This relay envelope adds a
//! compact 28-byte outer header for local UDP relay tests, making shard packets
//! 1,228 bytes. That remains within the IPv6 minimum-MTU UDP payload budget
//! (1,280 - 40 IPv6 - 8 UDP = 1,232 bytes) for non-QUIC local transport.

use crate::framing::APP_CELL_PAYLOAD_SIZE;
use crate::route_layer::{LayeredRoutePacket, RouteLayerError};
use crate::secure_cell::{SecureCellError, SecureShardCell};

pub const RELAY_PACKET_MAGIC: [u8; 4] = *b"CRP7";
pub const RELAY_PACKET_VERSION: u8 = 1;
pub const RELAY_PACKET_HEADER_SIZE: usize = 28;
pub const RELAY_PACKET_MAX_PAYLOAD: usize = APP_CELL_PAYLOAD_SIZE;
pub const RELAY_PACKET_MAX_BYTES: usize = RELAY_PACKET_HEADER_SIZE + RELAY_PACKET_MAX_PAYLOAD;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayPacketType {
    Hello = 1,
    Shard = 2,
    Ack = 3,
    Error = 4,
    Route = 5,
    Data = 6,
}

impl TryFrom<u8> for RelayPacketType {
    type Error = RelayPacketError;

    fn try_from(value: u8) -> Result<Self, RelayPacketError> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Shard),
            3 => Ok(Self::Ack),
            4 => Ok(Self::Error),
            5 => Ok(Self::Route),
            6 => Ok(Self::Data),
            other => Err(RelayPacketError::UnknownType(other)),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayErrorCode {
    MalformedPacket = 1,
    Replay = 2,
    NoSession = 3,
    UnknownStream = 4,
    ExpiredRoute = 5,
    Unauthorized = 6,
    QueueFull = 7,
    UnsupportedVersion = 8,
    NoRoute = 9,
    Drop = 10,
    Internal = 255,
}

impl TryFrom<u8> for RelayErrorCode {
    type Error = RelayPacketError;

    fn try_from(value: u8) -> Result<Self, RelayPacketError> {
        match value {
            1 => Ok(Self::MalformedPacket),
            2 => Ok(Self::Replay),
            3 => Ok(Self::NoSession),
            4 => Ok(Self::UnknownStream),
            5 => Ok(Self::ExpiredRoute),
            6 => Ok(Self::Unauthorized),
            7 => Ok(Self::QueueFull),
            8 => Ok(Self::UnsupportedVersion),
            9 => Ok(Self::NoRoute),
            10 => Ok(Self::Drop),
            255 => Ok(Self::Internal),
            other => Err(RelayPacketError::UnknownErrorCode(other)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayPacketError {
    InvalidLength { got: usize, min: usize },
    PayloadTooLarge { got: usize, max: usize },
    InvalidMagic,
    UnsupportedVersion(u8),
    UnknownType(u8),
    UnknownErrorCode(u8),
    InvalidPayloadLength { declared: usize, available: usize },
    InvalidReservedBytes,
    InvalidShardPayloadLength { got: usize, expected: usize },
    InvalidShardCell(SecureCellError),
    InvalidRoutePacket(RouteLayerError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayPacket {
    pub packet_type: RelayPacketType,
    pub flags: u8,
    pub stream_id: u64,
    pub sequence: u64,
    pub payload: Vec<u8>,
}

impl RelayPacket {
    pub fn new(
        packet_type: RelayPacketType,
        flags: u8,
        stream_id: u64,
        sequence: u64,
        payload: Vec<u8>,
    ) -> Result<Self, RelayPacketError> {
        if payload.len() > RELAY_PACKET_MAX_PAYLOAD {
            return Err(RelayPacketError::PayloadTooLarge {
                got: payload.len(),
                max: RELAY_PACKET_MAX_PAYLOAD,
            });
        }
        Ok(Self {
            packet_type,
            flags,
            stream_id,
            sequence,
            payload,
        })
    }

    pub fn ack(stream_id: u64, sequence: u64) -> Result<Self, RelayPacketError> {
        Self::new(RelayPacketType::Ack, 0, stream_id, sequence, b"OK".to_vec())
    }

    pub fn data(stream_id: u64, sequence: u64, payload: Vec<u8>) -> Result<Self, RelayPacketError> {
        Self::new(RelayPacketType::Data, 0, stream_id, sequence, payload)
    }

    pub fn error_code(
        stream_id: u64,
        sequence: u64,
        code: RelayErrorCode,
    ) -> Result<Self, RelayPacketError> {
        Self::new(
            RelayPacketType::Error,
            0,
            stream_id,
            sequence,
            vec![code as u8],
        )
    }

    pub fn decode_error_code(&self) -> Result<RelayErrorCode, RelayPacketError> {
        if self.packet_type != RelayPacketType::Error {
            return Err(RelayPacketError::UnknownType(self.packet_type as u8));
        }
        if self.payload.len() != 1 {
            return Err(RelayPacketError::InvalidPayloadLength {
                declared: 1,
                available: self.payload.len(),
            });
        }
        RelayErrorCode::try_from(self.payload[0])
    }

    pub fn error(stream_id: u64, sequence: u64, code: &[u8]) -> Result<Self, RelayPacketError> {
        Self::new(
            RelayPacketType::Error,
            0,
            stream_id,
            sequence,
            code.to_vec(),
        )
    }

    pub fn shard(
        stream_id: u64,
        sequence: u64,
        cell: &SecureShardCell,
    ) -> Result<Self, RelayPacketError> {
        Self::new(
            RelayPacketType::Shard,
            0,
            stream_id,
            sequence,
            cell.to_app_cell_bytes().to_vec(),
        )
    }

    pub fn route(
        stream_id: u64,
        sequence: u64,
        route_packet: &LayeredRoutePacket,
    ) -> Result<Self, RelayPacketError> {
        let mut payload = route_packet
            .encode()
            .map_err(RelayPacketError::InvalidRoutePacket)?;
        if payload.len() > RELAY_PACKET_MAX_PAYLOAD {
            return Err(RelayPacketError::PayloadTooLarge {
                got: payload.len(),
                max: RELAY_PACKET_MAX_PAYLOAD,
            });
        }
        payload.resize(RELAY_PACKET_MAX_PAYLOAD, 0);
        Self::new(RelayPacketType::Route, 0, stream_id, sequence, payload)
    }

    pub fn route_packet(&self) -> Result<LayeredRoutePacket, RelayPacketError> {
        if self.packet_type != RelayPacketType::Route {
            return Err(RelayPacketError::UnknownType(self.packet_type as u8));
        }
        let header_len = crate::route_layer::ROUTE_PACKET_HEADER_SIZE;
        if self.payload.len() < header_len {
            return Err(RelayPacketError::InvalidRoutePacket(
                RouteLayerError::InvalidLength {
                    declared: header_len,
                    available: self.payload.len(),
                },
            ));
        }
        let declared = u16::from_be_bytes([self.payload[6], self.payload[7]]) as usize;
        let total = header_len + declared;
        if total > self.payload.len() {
            return Err(RelayPacketError::InvalidRoutePacket(
                RouteLayerError::InvalidLength {
                    declared: total,
                    available: self.payload.len(),
                },
            ));
        }
        LayeredRoutePacket::decode(&self.payload[..total])
            .map_err(RelayPacketError::InvalidRoutePacket)
    }

    pub fn shard_cell(&self) -> Result<SecureShardCell, RelayPacketError> {
        if self.packet_type != RelayPacketType::Shard {
            return Err(RelayPacketError::UnknownType(self.packet_type as u8));
        }
        if self.payload.len() != APP_CELL_PAYLOAD_SIZE {
            return Err(RelayPacketError::InvalidShardPayloadLength {
                got: self.payload.len(),
                expected: APP_CELL_PAYLOAD_SIZE,
            });
        }
        let mut bytes = [0u8; APP_CELL_PAYLOAD_SIZE];
        bytes.copy_from_slice(&self.payload);
        SecureShardCell::from_app_cell_bytes(&bytes).map_err(RelayPacketError::InvalidShardCell)
    }

    pub fn encode(&self) -> Result<Vec<u8>, RelayPacketError> {
        if self.payload.len() > RELAY_PACKET_MAX_PAYLOAD {
            return Err(RelayPacketError::PayloadTooLarge {
                got: self.payload.len(),
                max: RELAY_PACKET_MAX_PAYLOAD,
            });
        }

        let mut out = Vec::with_capacity(RELAY_PACKET_HEADER_SIZE + self.payload.len());
        out.extend_from_slice(&RELAY_PACKET_MAGIC);
        out.push(RELAY_PACKET_VERSION);
        out.push(self.packet_type as u8);
        out.push(self.flags);
        out.push(0); // reserved
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&[0u8; 2]); // reserved/alignment
        out.extend_from_slice(&self.stream_id.to_be_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RelayPacketError> {
        if bytes.len() < RELAY_PACKET_HEADER_SIZE {
            return Err(RelayPacketError::InvalidLength {
                got: bytes.len(),
                min: RELAY_PACKET_HEADER_SIZE,
            });
        }
        if bytes[0..4] != RELAY_PACKET_MAGIC {
            return Err(RelayPacketError::InvalidMagic);
        }
        if bytes[4] != RELAY_PACKET_VERSION {
            return Err(RelayPacketError::UnsupportedVersion(bytes[4]));
        }
        let packet_type = RelayPacketType::try_from(bytes[5])?;
        let flags = bytes[6];
        if bytes[7] != 0 || bytes[10] != 0 || bytes[11] != 0 {
            return Err(RelayPacketError::InvalidReservedBytes);
        }

        let payload_len =
            u16::from_be_bytes(bytes[8..10].try_into().expect("fixed slice")) as usize;
        let available = bytes.len() - RELAY_PACKET_HEADER_SIZE;
        if payload_len != available {
            return Err(RelayPacketError::InvalidPayloadLength {
                declared: payload_len,
                available,
            });
        }
        if payload_len > RELAY_PACKET_MAX_PAYLOAD {
            return Err(RelayPacketError::PayloadTooLarge {
                got: payload_len,
                max: RELAY_PACKET_MAX_PAYLOAD,
            });
        }

        let stream_id = u64::from_be_bytes(bytes[12..20].try_into().expect("fixed slice"));
        let sequence = u64::from_be_bytes(bytes[20..28].try_into().expect("fixed slice"));
        let payload = bytes[RELAY_PACKET_HEADER_SIZE..].to_vec();
        Ok(Self {
            packet_type,
            flags,
            stream_id,
            sequence,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_cell::{SecureShardCell, derive_link_key};

    fn cell() -> SecureShardCell {
        let key = derive_link_key(&[0x77u8; 32], &[0x88u8; 16]).expect("key");
        SecureShardCell::encrypt(&key, [0x88; 16], 12, 0, b"relay packet shard").expect("cell")
    }

    #[test]
    fn relay_packet_round_trips_shard_cell() {
        let cell = cell();
        let packet = RelayPacket::shard(55, 66, &cell).expect("packet");
        let encoded = packet.encode().expect("encode");
        assert_eq!(encoded.len(), RELAY_PACKET_MAX_BYTES);

        let decoded = RelayPacket::decode(&encoded).expect("decode");
        assert_eq!(decoded.stream_id, 55);
        assert_eq!(decoded.sequence, 66);
        assert_eq!(decoded.shard_cell().expect("cell"), cell);
    }

    #[test]
    fn relay_packet_round_trips_typed_error_code() {
        let packet = RelayPacket::error_code(99, 100, RelayErrorCode::NoRoute).expect("error");
        let encoded = packet.encode().expect("encode");
        let decoded = RelayPacket::decode(&encoded).expect("decode");
        assert_eq!(
            decoded.decode_error_code().expect("code"),
            RelayErrorCode::NoRoute
        );
    }

    #[test]
    fn relay_packet_matches_documented_minimal_vector() {
        let packet = RelayPacket::data(1, 2, vec![1, 2, 3]).expect("packet");
        let encoded = packet.encode().expect("encode");
        let hex = encoded
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(
            hex,
            "43525037010600000003000000000000000000010000000000000002010203"
        );
    }

    #[test]
    fn relay_packet_round_trips_data_packet() {
        let packet = RelayPacket::data(12, 34, b"delivered route payload".to_vec()).expect("data");
        let encoded = packet.encode().expect("encode");
        let decoded = RelayPacket::decode(&encoded).expect("decode");
        assert_eq!(decoded, packet);
        assert_eq!(decoded.packet_type, RelayPacketType::Data);
    }

    #[test]
    fn relay_route_packet_is_padded_to_constant_payload_size() {
        use crate::route_layer::{RouteCommand, RouteHopSecret, build_layered_route_packet};
        let secrets = vec![RouteHopSecret([1u8; 32])];
        let commands = vec![RouteCommand::deliver_local()];
        let route = build_layered_route_packet(78, &secrets, &commands, b"x").expect("route");
        let packet = RelayPacket::route(88, 100, &route).expect("relay route");
        assert_eq!(packet.payload.len(), RELAY_PACKET_MAX_PAYLOAD);
        assert_eq!(
            packet.encode().expect("encode").len(),
            RELAY_PACKET_MAX_BYTES
        );
        assert_eq!(packet.route_packet().expect("route packet"), route);
    }

    #[test]
    fn relay_packet_round_trips_route_packet() {
        use crate::route_layer::{RouteCommand, RouteHopSecret, build_layered_route_packet};
        let secrets = vec![RouteHopSecret([1u8; 32]), RouteHopSecret([2u8; 32])];
        let commands = vec![RouteCommand::forward(10), RouteCommand::deliver_local()];
        let route =
            build_layered_route_packet(77, &secrets, &commands, b"route payload").expect("route");
        let packet = RelayPacket::route(88, 99, &route).expect("relay route");
        let encoded = packet.encode().expect("encode");
        let decoded = RelayPacket::decode(&encoded).expect("decode");
        assert_eq!(decoded.packet_type, RelayPacketType::Route);
        assert_eq!(decoded.route_packet().expect("route packet"), route);
    }

    #[test]
    fn relay_packet_rejects_bad_magic() {
        let packet =
            RelayPacket::new(RelayPacketType::Hello, 0, 1, 2, b"hello".to_vec()).expect("packet");
        let mut encoded = packet.encode().expect("encode");
        encoded[0] = b'X';
        assert_eq!(
            RelayPacket::decode(&encoded),
            Err(RelayPacketError::InvalidMagic)
        );
    }

    #[test]
    fn relay_packet_rejects_payload_length_mismatch() {
        let packet =
            RelayPacket::new(RelayPacketType::Ack, 0, 1, 2, b"ok".to_vec()).expect("packet");
        let mut encoded = packet.encode().expect("encode");
        encoded[9] = 3;
        assert_eq!(
            RelayPacket::decode(&encoded),
            Err(RelayPacketError::InvalidPayloadLength {
                declared: 3,
                available: 2,
            })
        );
    }

    #[test]
    fn relay_packet_rejects_non_shard_cell_extraction() {
        let packet =
            RelayPacket::new(RelayPacketType::Hello, 0, 1, 2, b"hello".to_vec()).expect("packet");
        assert_eq!(
            packet.shard_cell(),
            Err(RelayPacketError::UnknownType(RelayPacketType::Hello as u8))
        );
    }
}
