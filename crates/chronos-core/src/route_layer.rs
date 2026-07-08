//! Authenticated layered route packet primitive.
//!
//! This module replaces the old SHA-256/XOR Sphinx simulation path with a
//! concrete, testable onion-route building block. It is not a complete academic
//! Sphinx implementation, but it now includes the core production semantics the
//! rest of the workspace can build on: per-hop AEAD, packet-id blinding, typed
//! route commands, single-use reply blocks, route replay state, and relay-packet
//! serialization.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use hkdf::Hkdf;
use sha2::Sha256;

pub const ROUTE_LAYER_MAGIC: [u8; 4] = *b"RTE7";
pub const ROUTE_LAYER_VERSION: u8 = 1;
pub const ROUTE_LAYER_HEADER_SIZE: usize = 32;
pub const ROUTE_LAYER_TAG_SIZE: usize = 16;
pub const ROUTE_LAYER_MAX_BODY: usize = 2048;
pub const ROUTE_PACKET_MAGIC: [u8; 4] = *b"RTP7";
pub const ROUTE_PACKET_HEADER_SIZE: usize = 16;
const ROUTE_LAYER_KEY_INFO: &[u8] = b"chronos-v7/route-layer-aead";
const ROUTE_BLINDING_INFO: &[u8] = b"chronos-v7/route-packet-id-blinding";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteLayerError {
    TooManyHops { got: usize, max: usize },
    EmptyRoute,
    BodyTooLarge { got: usize, max: usize },
    InvalidMagic,
    UnsupportedVersion(u8),
    HopIndexMismatch { expected: u8, got: u8 },
    InvalidLength { declared: usize, available: usize },
    InvalidReservedBytes,
    KeyDerivation,
    AuthenticationFailed,
    Replay { packet_id: u64, hop_index: u8 },
    ReplyBlockAlreadyUsed,
    DropCommand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteCommandKind {
    Forward,
    DeliverLocal,
    Drop,
    Reply,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteCommand {
    pub next_stream_id: u64,
    pub flags: u8,
}

impl RouteCommand {
    pub const KIND_MASK: u8 = 0x03;

    pub fn forward(next_stream_id: u64) -> Self {
        Self {
            next_stream_id,
            flags: 0,
        }
    }

    pub fn deliver_local() -> Self {
        Self {
            next_stream_id: 0,
            flags: 1,
        }
    }

    pub fn drop() -> Self {
        Self {
            next_stream_id: 0,
            flags: 2,
        }
    }

    pub fn reply(reply_stream_id: u64) -> Self {
        Self {
            next_stream_id: reply_stream_id,
            flags: 3,
        }
    }

    pub fn kind(self) -> RouteCommandKind {
        match self.flags & Self::KIND_MASK {
            0 => RouteCommandKind::Forward,
            1 => RouteCommandKind::DeliverLocal,
            2 => RouteCommandKind::Drop,
            _ => RouteCommandKind::Reply,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteHopSecret(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayeredRoutePacket {
    pub packet_id: u64,
    pub hop_index: u8,
    pub body: Vec<u8>,
}

impl LayeredRoutePacket {
    pub fn encode(&self) -> Result<Vec<u8>, RouteLayerError> {
        if self.body.len() > u16::MAX as usize || self.body.len() > ROUTE_LAYER_MAX_BODY {
            return Err(RouteLayerError::BodyTooLarge {
                got: self.body.len(),
                max: ROUTE_LAYER_MAX_BODY,
            });
        }
        let mut out = Vec::with_capacity(ROUTE_PACKET_HEADER_SIZE + self.body.len());
        out.extend_from_slice(&ROUTE_PACKET_MAGIC);
        out.push(ROUTE_LAYER_VERSION);
        out.push(self.hop_index);
        out.extend_from_slice(&(self.body.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.packet_id.to_be_bytes());
        out.extend_from_slice(&self.body);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RouteLayerError> {
        if bytes.len() < ROUTE_PACKET_HEADER_SIZE {
            return Err(RouteLayerError::InvalidLength {
                declared: ROUTE_PACKET_HEADER_SIZE,
                available: bytes.len(),
            });
        }
        if bytes[0..4] != ROUTE_PACKET_MAGIC {
            return Err(RouteLayerError::InvalidMagic);
        }
        if bytes[4] != ROUTE_LAYER_VERSION {
            return Err(RouteLayerError::UnsupportedVersion(bytes[4]));
        }
        let hop_index = bytes[5];
        let declared = u16::from_be_bytes(bytes[6..8].try_into().expect("fixed slice")) as usize;
        let available = bytes.len() - ROUTE_PACKET_HEADER_SIZE;
        if declared != available {
            return Err(RouteLayerError::InvalidLength {
                declared,
                available,
            });
        }
        let packet_id = u64::from_be_bytes(bytes[8..16].try_into().expect("fixed slice"));
        Ok(Self {
            packet_id,
            hop_index,
            body: bytes[ROUTE_PACKET_HEADER_SIZE..].to_vec(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeeledRouteLayer {
    pub command: RouteCommand,
    pub next_packet: Option<LayeredRoutePacket>,
    pub payload: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct RouteReplayCache {
    seen: HashMap<(u64, u8), Instant>,
    order: VecDeque<(u64, u8)>,
    max_entries: usize,
    ttl: Duration,
}

impl Default for RouteReplayCache {
    fn default() -> Self {
        Self::with_limits(4096, Duration::from_secs(300))
    }
}

impl RouteReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_limits(max_entries: usize, ttl: Duration) -> Self {
        Self {
            seen: HashMap::new(),
            order: VecDeque::new(),
            max_entries: max_entries.max(1),
            ttl,
        }
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    pub fn observe(&mut self, packet: &LayeredRoutePacket) -> Result<(), RouteLayerError> {
        self.prune_expired();
        let key = (packet.packet_id, packet.hop_index);
        if self.seen.contains_key(&key) {
            return Err(RouteLayerError::Replay {
                packet_id: packet.packet_id,
                hop_index: packet.hop_index,
            });
        }
        self.seen.insert(key, Instant::now());
        self.order.push_back(key);
        self.enforce_capacity();
        Ok(())
    }

    fn prune_expired(&mut self) {
        let now = Instant::now();
        while let Some(&key) = self.order.front() {
            let expired = self
                .seen
                .get(&key)
                .map(|seen_at| now.duration_since(*seen_at) >= self.ttl)
                .unwrap_or(true);
            if expired {
                self.order.pop_front();
                self.seen.remove(&key);
            } else {
                break;
            }
        }
    }

    fn enforce_capacity(&mut self) {
        while self.seen.len() > self.max_entries {
            if let Some(key) = self.order.pop_front() {
                self.seen.remove(&key);
            } else {
                break;
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RouteLayerProcessor {
    replay: RouteReplayCache,
}

impl RouteLayerProcessor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_replay_limits(max_entries: usize, ttl: Duration) -> Self {
        Self {
            replay: RouteReplayCache::with_limits(max_entries, ttl),
        }
    }

    pub fn peel_once(
        &mut self,
        packet: &LayeredRoutePacket,
        expected_hop_index: u8,
        hop_secret: &RouteHopSecret,
    ) -> Result<PeeledRouteLayer, RouteLayerError> {
        self.replay.observe(packet)?;
        peel_route_layer(packet, expected_hop_index, hop_secret)
    }
}

#[derive(Debug, Clone)]
pub struct SingleUseReplyBlock {
    packet_id: u64,
    hop_secrets: Vec<RouteHopSecret>,
    commands: Vec<RouteCommand>,
    used: bool,
}

impl SingleUseReplyBlock {
    pub fn new(
        packet_id: u64,
        hop_secrets: Vec<RouteHopSecret>,
        commands: Vec<RouteCommand>,
    ) -> Self {
        Self {
            packet_id,
            hop_secrets,
            commands,
            used: false,
        }
    }

    pub fn seal_reply(&mut self, payload: &[u8]) -> Result<LayeredRoutePacket, RouteLayerError> {
        if self.used {
            return Err(RouteLayerError::ReplyBlockAlreadyUsed);
        }
        self.used = true;
        build_layered_route_packet(self.packet_id, &self.hop_secrets, &self.commands, payload)
    }
}

/// Build a route packet by wrapping `payload` in one authenticated layer per hop.
/// `commands[i]` is revealed only to hop `i` when it peels its layer.
pub fn build_layered_route_packet(
    packet_id: u64,
    hop_secrets: &[RouteHopSecret],
    commands: &[RouteCommand],
    payload: &[u8],
) -> Result<LayeredRoutePacket, RouteLayerError> {
    if hop_secrets.is_empty() {
        return Err(RouteLayerError::EmptyRoute);
    }
    if hop_secrets.len() != commands.len() {
        return Err(RouteLayerError::TooManyHops {
            got: commands.len(),
            max: hop_secrets.len(),
        });
    }
    if hop_secrets.len() > u8::MAX as usize {
        return Err(RouteLayerError::TooManyHops {
            got: hop_secrets.len(),
            max: u8::MAX as usize,
        });
    }
    if payload.len() > ROUTE_LAYER_MAX_BODY {
        return Err(RouteLayerError::BodyTooLarge {
            got: payload.len(),
            max: ROUTE_LAYER_MAX_BODY,
        });
    }

    let mut packet_ids = Vec::with_capacity(hop_secrets.len());
    let mut current_id = packet_id;
    for (hop, secret) in hop_secrets.iter().enumerate() {
        packet_ids.push(current_id);
        current_id = blind_next_packet_id(current_id, hop as u8, secret)?;
    }

    let mut inner = payload.to_vec();
    for hop in (0..hop_secrets.len()).rev() {
        inner = encrypt_layer(
            packet_ids[hop],
            hop as u8,
            &hop_secrets[hop],
            commands[hop],
            &inner,
        )?;
    }

    Ok(LayeredRoutePacket {
        packet_id,
        hop_index: 0,
        body: inner,
    })
}

/// Peel the current hop layer. The caller supplies the expected hop index to
/// prevent accidental out-of-order processing in tests and local relay code.
pub fn peel_route_layer(
    packet: &LayeredRoutePacket,
    expected_hop_index: u8,
    hop_secret: &RouteHopSecret,
) -> Result<PeeledRouteLayer, RouteLayerError> {
    if packet.hop_index != expected_hop_index {
        return Err(RouteLayerError::HopIndexMismatch {
            expected: expected_hop_index,
            got: packet.hop_index,
        });
    }

    let decrypted = decrypt_layer(packet.packet_id, packet.hop_index, hop_secret, &packet.body)?;
    if decrypted.len() < 18 {
        return Err(RouteLayerError::InvalidLength {
            declared: 18,
            available: decrypted.len(),
        });
    }

    let next_stream_id = u64::from_be_bytes(decrypted[0..8].try_into().expect("fixed slice"));
    let flags = decrypted[8];
    if decrypted[9..16].iter().any(|&b| b != 0) {
        return Err(RouteLayerError::InvalidReservedBytes);
    }
    let inner_len = u16::from_be_bytes(decrypted[16..18].try_into().expect("fixed slice")) as usize;
    let available = decrypted.len() - 18;
    if inner_len != available {
        return Err(RouteLayerError::InvalidLength {
            declared: inner_len,
            available,
        });
    }
    let inner = decrypted[18..].to_vec();
    let command = RouteCommand {
        next_stream_id,
        flags,
    };

    match command.kind() {
        RouteCommandKind::DeliverLocal | RouteCommandKind::Reply => Ok(PeeledRouteLayer {
            command,
            next_packet: None,
            payload: Some(inner),
        }),
        RouteCommandKind::Drop => Err(RouteLayerError::DropCommand),
        RouteCommandKind::Forward => Ok(PeeledRouteLayer {
            command,
            next_packet: Some(LayeredRoutePacket {
                packet_id: blind_next_packet_id(packet.packet_id, packet.hop_index, hop_secret)?,
                hop_index: packet.hop_index.saturating_add(1),
                body: inner,
            }),
            payload: None,
        }),
    }
}

fn encrypt_layer(
    packet_id: u64,
    hop_index: u8,
    hop_secret: &RouteHopSecret,
    command: RouteCommand,
    inner: &[u8],
) -> Result<Vec<u8>, RouteLayerError> {
    if inner.len() > u16::MAX as usize || inner.len() > ROUTE_LAYER_MAX_BODY {
        return Err(RouteLayerError::BodyTooLarge {
            got: inner.len(),
            max: ROUTE_LAYER_MAX_BODY,
        });
    }

    let mut plaintext = Vec::with_capacity(18 + inner.len());
    plaintext.extend_from_slice(&command.next_stream_id.to_be_bytes());
    plaintext.push(command.flags);
    plaintext.extend_from_slice(&[0u8; 7]);
    plaintext.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    plaintext.extend_from_slice(inner);

    let key = derive_route_layer_key(packet_id, hop_index, hop_secret)?;
    let nonce = route_layer_nonce(packet_id, hop_index);
    let aad = route_layer_aad(packet_id, hop_index, plaintext.len());
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, &mut plaintext)
        .map_err(|_| RouteLayerError::AuthenticationFailed)?;

    let mut out =
        Vec::with_capacity(ROUTE_LAYER_HEADER_SIZE + plaintext.len() + ROUTE_LAYER_TAG_SIZE);
    out.extend_from_slice(&ROUTE_LAYER_MAGIC);
    out.push(ROUTE_LAYER_VERSION);
    out.push(hop_index);
    out.extend_from_slice(&(plaintext.len() as u16).to_be_bytes());
    out.extend_from_slice(&packet_id.to_be_bytes());
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&plaintext);
    out.extend_from_slice(&tag);
    Ok(out)
}

fn decrypt_layer(
    packet_id: u64,
    hop_index: u8,
    hop_secret: &RouteHopSecret,
    body: &[u8],
) -> Result<Vec<u8>, RouteLayerError> {
    if body.len() < ROUTE_LAYER_HEADER_SIZE + ROUTE_LAYER_TAG_SIZE {
        return Err(RouteLayerError::InvalidLength {
            declared: ROUTE_LAYER_HEADER_SIZE + ROUTE_LAYER_TAG_SIZE,
            available: body.len(),
        });
    }
    if body[0..4] != ROUTE_LAYER_MAGIC {
        return Err(RouteLayerError::InvalidMagic);
    }
    if body[4] != ROUTE_LAYER_VERSION {
        return Err(RouteLayerError::UnsupportedVersion(body[4]));
    }
    if body[5] != hop_index {
        return Err(RouteLayerError::HopIndexMismatch {
            expected: hop_index,
            got: body[5],
        });
    }
    let declared = u16::from_be_bytes(body[6..8].try_into().expect("fixed slice")) as usize;
    let encoded_packet_id = u64::from_be_bytes(body[8..16].try_into().expect("fixed slice"));
    if encoded_packet_id != packet_id || body[16..32].iter().any(|&b| b != 0) {
        return Err(RouteLayerError::InvalidReservedBytes);
    }
    let available = body.len() - ROUTE_LAYER_HEADER_SIZE - ROUTE_LAYER_TAG_SIZE;
    if declared != available {
        return Err(RouteLayerError::InvalidLength {
            declared,
            available,
        });
    }

    let mut ciphertext = body[ROUTE_LAYER_HEADER_SIZE..ROUTE_LAYER_HEADER_SIZE + declared].to_vec();
    let tag = &body[ROUTE_LAYER_HEADER_SIZE + declared..];
    let key = derive_route_layer_key(packet_id, hop_index, hop_secret)?;
    let nonce = route_layer_nonce(packet_id, hop_index);
    let aad = route_layer_aad(packet_id, hop_index, declared);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&nonce),
            &aad,
            &mut ciphertext,
            Tag::from_slice(tag),
        )
        .map_err(|_| RouteLayerError::AuthenticationFailed)?;
    Ok(ciphertext)
}

fn blind_next_packet_id(
    packet_id: u64,
    hop_index: u8,
    hop_secret: &RouteHopSecret,
) -> Result<u64, RouteLayerError> {
    let hk = Hkdf::<Sha256>::new(Some(&hop_secret.0), &packet_id.to_be_bytes());
    let mut out = [0u8; 8];
    hk.expand(&[ROUTE_BLINDING_INFO, &[hop_index]].concat(), &mut out)
        .map_err(|_| RouteLayerError::KeyDerivation)?;
    Ok(u64::from_be_bytes(out))
}

fn derive_route_layer_key(
    packet_id: u64,
    hop_index: u8,
    hop_secret: &RouteHopSecret,
) -> Result<[u8; 32], RouteLayerError> {
    let mut salt = [0u8; 16];
    salt[0..8].copy_from_slice(&packet_id.to_be_bytes());
    salt[8] = hop_index;
    let hk = Hkdf::<Sha256>::new(Some(&salt), &hop_secret.0);
    let mut out = [0u8; 32];
    hk.expand(ROUTE_LAYER_KEY_INFO, &mut out)
        .map_err(|_| RouteLayerError::KeyDerivation)?;
    Ok(out)
}

fn route_layer_nonce(packet_id: u64, hop_index: u8) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(&packet_id.to_be_bytes());
    nonce[11] = hop_index;
    nonce
}

fn route_layer_aad(packet_id: u64, hop_index: u8, body_len: usize) -> [u8; 16] {
    let mut aad = [0u8; 16];
    aad[0..4].copy_from_slice(&ROUTE_LAYER_MAGIC);
    aad[4] = ROUTE_LAYER_VERSION;
    aad[5] = hop_index;
    aad[6..8].copy_from_slice(&(body_len as u16).to_be_bytes());
    aad[8..16].copy_from_slice(&packet_id.to_be_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets() -> Vec<RouteHopSecret> {
        vec![
            RouteHopSecret([1u8; 32]),
            RouteHopSecret([2u8; 32]),
            RouteHopSecret([3u8; 32]),
        ]
    }

    fn commands() -> Vec<RouteCommand> {
        vec![
            RouteCommand::forward(10),
            RouteCommand::forward(20),
            RouteCommand::deliver_local(),
        ]
    }

    #[test]
    fn layered_route_peels_in_order_to_payload_with_blinded_packet_ids() {
        let packet = build_layered_route_packet(99, &secrets(), &commands(), b"terminal payload")
            .expect("build");
        let first = peel_route_layer(&packet, 0, &secrets()[0]).expect("hop 0");
        assert_eq!(first.command.next_stream_id, 10);
        assert!(first.payload.is_none());

        let second_packet = first.next_packet.expect("next packet");
        assert_ne!(second_packet.packet_id, packet.packet_id);
        let second = peel_route_layer(&second_packet, 1, &secrets()[1]).expect("hop 1");
        assert_eq!(second.command.next_stream_id, 20);

        let third_packet = second.next_packet.expect("next packet");
        assert_ne!(third_packet.packet_id, second_packet.packet_id);
        let third = peel_route_layer(&third_packet, 2, &secrets()[2]).expect("hop 2");
        assert_eq!(third.command.kind(), RouteCommandKind::DeliverLocal);
        assert_eq!(third.payload.expect("payload"), b"terminal payload");
    }

    #[test]
    fn route_packet_serializes_for_relay_payloads() {
        let packet =
            build_layered_route_packet(199, &secrets(), &commands(), b"payload").expect("build");
        let encoded = packet.encode().expect("encode");
        let decoded = LayeredRoutePacket::decode(&encoded).expect("decode");
        assert_eq!(decoded, packet);
    }

    #[test]
    fn route_processor_rejects_replay() {
        let packet =
            build_layered_route_packet(299, &secrets(), &commands(), b"payload").expect("build");
        let mut processor = RouteLayerProcessor::new();
        processor
            .peel_once(&packet, 0, &secrets()[0])
            .expect("first peel");
        assert_eq!(
            processor.peel_once(&packet, 0, &secrets()[0]),
            Err(RouteLayerError::Replay {
                packet_id: packet.packet_id,
                hop_index: packet.hop_index,
            })
        );
    }

    #[test]
    fn route_replay_cache_expires_entries() {
        let packet =
            build_layered_route_packet(300, &secrets(), &commands(), b"payload").expect("build");
        let mut cache = RouteReplayCache::with_limits(16, Duration::from_secs(0));
        cache.observe(&packet).expect("first observe");
        assert_eq!(cache.len(), 1);
        cache
            .observe(&packet)
            .expect("expired replay is accepted again");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn route_replay_cache_evicts_oldest_when_bounded() {
        let mut cache = RouteReplayCache::with_limits(2, Duration::from_secs(3600));
        let p1 = build_layered_route_packet(301, &secrets(), &commands(), b"one").expect("p1");
        let p2 = build_layered_route_packet(302, &secrets(), &commands(), b"two").expect("p2");
        let p3 = build_layered_route_packet(303, &secrets(), &commands(), b"three").expect("p3");
        cache.observe(&p1).expect("p1");
        cache.observe(&p2).expect("p2");
        cache.observe(&p3).expect("p3 evicts p1");
        assert_eq!(cache.len(), 2);
        cache
            .observe(&p1)
            .expect("p1 was evicted and is accepted again");
    }

    #[test]
    fn single_use_reply_block_seals_once() {
        let mut surb = SingleUseReplyBlock::new(399, secrets(), commands());
        let packet = surb.seal_reply(b"reply payload").expect("first use");
        let first = peel_route_layer(&packet, 0, &secrets()[0]).expect("hop 0");
        assert!(first.next_packet.is_some());
        assert_eq!(
            surb.seal_reply(b"second"),
            Err(RouteLayerError::ReplyBlockAlreadyUsed)
        );
    }

    #[test]
    fn route_command_drop_is_enforced() {
        let cmds = vec![RouteCommand::drop()];
        let secs = vec![RouteHopSecret([9u8; 32])];
        let packet = build_layered_route_packet(499, &secs, &cmds, b"drop me").expect("build");
        assert_eq!(
            peel_route_layer(&packet, 0, &secs[0]),
            Err(RouteLayerError::DropCommand)
        );
    }

    #[test]
    fn layered_route_rejects_tampering() {
        let mut packet =
            build_layered_route_packet(100, &secrets(), &commands(), b"payload").expect("build");
        let last = packet.body.len() - 1;
        packet.body[last] ^= 0x80;
        assert_eq!(
            peel_route_layer(&packet, 0, &secrets()[0]),
            Err(RouteLayerError::AuthenticationFailed)
        );
    }

    #[test]
    fn layered_route_rejects_wrong_hop_secret() {
        let packet =
            build_layered_route_packet(101, &secrets(), &commands(), b"payload").expect("build");
        assert_eq!(
            peel_route_layer(&packet, 0, &secrets()[1]),
            Err(RouteLayerError::AuthenticationFailed)
        );
    }

    #[test]
    fn layered_route_rejects_out_of_order_peel() {
        let packet =
            build_layered_route_packet(102, &secrets(), &commands(), b"payload").expect("build");
        assert_eq!(
            peel_route_layer(&packet, 1, &secrets()[0]),
            Err(RouteLayerError::HopIndexMismatch {
                expected: 1,
                got: 0,
            })
        );
    }
}
