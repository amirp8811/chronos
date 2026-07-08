//! Async UDP relay service for `chronosd`.
//!
//! This is the first real relay loop in the daemon. It uses the core CRP7 relay
//! packet parser and stateful handler, then forwards validated shard/route
//! packets according to a static stream-id route table. It is intentionally a
//! normal Tokio UDP implementation; io_uring/AF_XDP can replace the socket layer
//! later without changing the packet semantics.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use crate::queue::{BoundedRelayQueue, QueueError, QueuedRelayPacket};

use chronos_core::{
    HandshakePacket, HandshakePacketType, HandshakePublicKeys, NodeKeyMaterial, PowAdmissionCache,
    PowChallenge, RELAY_PACKET_MAX_BYTES, RelayDecision, RelayErrorCode, RelayHandlerError,
    RelayPacket, RelayPacketError, RelayPacketHandler, RouteCommandKind, RouteHopSecret,
    RouteLayerError, RouteLayerProcessor, ServerHandshakeState, server_accept_handshake,
};
use tokio::net::UdpSocket;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpRelayError {
    Io(String),
    Packet(RelayPacketError),
    Handler(RelayHandlerError),
    Route(RouteLayerError),
    Handshake(String),
    NoRoute { stream_id: u64 },
    NoSession { stream_id: u64 },
    QueueFull,
    InvalidRouteSpec(String),
}

impl fmt::Display for UdpRelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for UdpRelayError {}

impl From<std::io::Error> for UdpRelayError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

#[derive(Debug, Clone, Default)]
pub struct StaticRouteTable {
    routes: HashMap<u64, SocketAddr>,
}

impl StaticRouteTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_spec(spec: &str) -> Self {
        let mut table = Self::new();
        for entry in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if let Ok((stream_id, addr)) = parse_route_entry(entry) {
                table.insert(stream_id, addr);
            }
        }
        table
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn insert(&mut self, stream_id: u64, addr: SocketAddr) {
        self.routes.insert(stream_id, addr);
    }

    pub fn get(&self, stream_id: u64) -> Option<SocketAddr> {
        self.routes.get(&stream_id).copied()
    }

    #[cfg(test)]
    pub fn save_to_file(&self, path: impl AsRef<std::path::Path>) -> Result<(), UdpRelayError> {
        let mut body = String::new();
        for (stream, addr) in &self.routes {
            body.push_str(&format!("{}={}\n", stream, addr));
        }
        std::fs::write(path, body).map_err(UdpRelayError::from)
    }

    #[cfg(test)]
    pub fn load_from_file(path: impl AsRef<std::path::Path>) -> Result<Self, UdpRelayError> {
        let body = std::fs::read_to_string(path).map_err(UdpRelayError::from)?;
        Ok(Self::from_spec(&body.replace('\n', ",")))
    }

    /// Parse static routes from an environment variable containing entries like:
    /// `100=127.0.0.1:5001,200=127.0.0.1:5002`.
    pub fn from_env(var_name: &str) -> Self {
        let mut table = Self::new();
        if let Ok(spec) = std::env::var(var_name) {
            for entry in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                if let Ok((stream_id, addr)) = parse_route_entry(entry) {
                    table.insert(stream_id, addr);
                }
            }
        }
        table
    }
}

fn parse_route_entry(entry: &str) -> Result<(u64, SocketAddr), UdpRelayError> {
    let (stream, addr) = entry
        .split_once('=')
        .ok_or_else(|| UdpRelayError::InvalidRouteSpec(entry.to_string()))?;
    let stream_id = stream
        .parse::<u64>()
        .map_err(|_| UdpRelayError::InvalidRouteSpec(entry.to_string()))?;
    let addr = addr
        .parse::<SocketAddr>()
        .map_err(|_| UdpRelayError::InvalidRouteSpec(entry.to_string()))?;
    Ok((stream_id, addr))
}

fn parse_route_secret_hex(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (idx, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(hex.as_bytes()[idx * 2])?;
        let lo = hex_nibble(hex.as_bytes()[idx * 2 + 1])?;
        *byte = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UdpRelayMetrics {
    pub packets_received: u64,
    pub packets_forwarded: u64,
    pub acks_sent: u64,
    pub errors_sent: u64,
    pub no_route_errors: u64,
    pub queue_full_errors: u64,
    pub route_packets_peeled: u64,
    pub data_packets_delivered: u64,
}

pub struct ChronosUdpRelay {
    socket: UdpSocket,
    handler: RelayPacketHandler,
    routes: StaticRouteTable,
    route_secrets: HashMap<u64, RouteHopSecret>,
    route_processors: HashMap<u64, RouteLayerProcessor>,
    route_replay_max_entries: usize,
    route_replay_ttl: std::time::Duration,
    node_keys: Option<NodeKeyMaterial>,
    server_hello: Option<HandshakePacket>,
    pending_handshakes: HashMap<SocketAddr, (HandshakePacket, NodeKeyMaterial)>,
    next_session_stream_id: u64,
    sessions: HashMap<SocketAddr, ServerHandshakeState>,
    session_streams: HashSet<u64>,
    enforce_sessions: bool,
    pow_challenge: Option<PowChallenge>,
    pow_admitted: std::collections::HashSet<SocketAddr>,
    pow_cache: PowAdmissionCache,
    outbound_queue: BoundedRelayQueue,
    metrics: Arc<Mutex<UdpRelayMetrics>>,
    tdm_slot_width: std::time::Duration,
    sent_tdm_slots: u64,
}

impl ChronosUdpRelay {
    #[cfg(test)]
    pub async fn bind(bind_addr: &str, routes: StaticRouteTable) -> Result<Self, UdpRelayError> {
        Self::bind_with_replay_config(bind_addr, routes, 4096, std::time::Duration::from_secs(300))
            .await
    }

    #[cfg(test)]
    pub async fn bind_with_replay_config(
        bind_addr: &str,
        routes: StaticRouteTable,
        route_replay_max_entries: usize,
        route_replay_ttl: std::time::Duration,
    ) -> Result<Self, UdpRelayError> {
        Self::bind_with_runtime_config(
            bind_addr,
            routes,
            route_replay_max_entries,
            route_replay_ttl,
            1024,
        )
        .await
    }

    pub async fn bind_with_runtime_config(
        bind_addr: &str,
        routes: StaticRouteTable,
        route_replay_max_entries: usize,
        route_replay_ttl: std::time::Duration,
        outbound_queue_max: usize,
    ) -> Result<Self, UdpRelayError> {
        Ok(Self {
            socket: UdpSocket::bind(bind_addr).await?,
            handler: RelayPacketHandler::new(128)
                .map_err(|e| UdpRelayError::Handler(RelayHandlerError::Replay(e)))?,
            routes,
            route_secrets: HashMap::new(),
            route_processors: HashMap::new(),
            route_replay_max_entries,
            route_replay_ttl,
            node_keys: None,
            server_hello: None,
            pending_handshakes: HashMap::new(),
            next_session_stream_id: 10_000,
            sessions: HashMap::new(),
            session_streams: HashSet::new(),
            enforce_sessions: false,
            pow_challenge: None,
            pow_admitted: std::collections::HashSet::new(),
            pow_cache: PowAdmissionCache::new(4096, std::time::Duration::from_secs(300)),
            outbound_queue: BoundedRelayQueue::new(outbound_queue_max),
            metrics: Arc::new(Mutex::new(UdpRelayMetrics::default())),
            tdm_slot_width: std::time::Duration::ZERO,
            sent_tdm_slots: 0,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, UdpRelayError> {
        self.socket.local_addr().map_err(UdpRelayError::from)
    }

    pub fn enable_handshake(&mut self, node_keys: NodeKeyMaterial) -> Result<(), UdpRelayError> {
        let server_hello = HandshakePublicKeys::from_node_keys(&node_keys)
            .to_server_hello_packet()
            .map_err(|e| UdpRelayError::Handshake(format!("server hello: {e:?}")))?;
        self.node_keys = Some(node_keys);
        self.server_hello = Some(server_hello);
        Ok(())
    }

    pub fn enable_pow_admission(&mut self, challenge: PowChallenge) {
        self.pow_challenge = Some(challenge);
    }

    pub fn set_session_enforcement(&mut self, enforce: bool) {
        self.enforce_sessions = enforce;
    }

    #[cfg(test)]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn metrics_handle(&self) -> Arc<Mutex<UdpRelayMetrics>> {
        Arc::clone(&self.metrics)
    }

    #[cfg(test)]
    pub fn metrics(&self) -> UdpRelayMetrics {
        *self.metrics.lock().expect("metrics lock")
    }

    pub fn enable_tdm_pacing(&mut self, slot_width: std::time::Duration) {
        self.tdm_slot_width = slot_width;
    }

    #[cfg(test)]
    pub fn sent_tdm_slots(&self) -> u64 {
        self.sent_tdm_slots
    }

    pub fn insert_route_secret(&mut self, stream_id: u64, secret: RouteHopSecret) {
        self.route_secrets.insert(stream_id, secret);
    }

    pub fn apply_route_secrets_from_env(&mut self, var_name: &str) -> Result<usize, UdpRelayError> {
        let spec = std::env::var(var_name).unwrap_or_default();
        self.apply_route_secrets_spec(&spec)
    }

    pub fn apply_route_secrets_spec(&mut self, spec: &str) -> Result<usize, UdpRelayError> {
        let mut inserted = 0usize;
        for entry in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let (stream, hex_secret) = entry
                .split_once('=')
                .ok_or_else(|| UdpRelayError::InvalidRouteSpec(entry.to_string()))?;
            let stream_id = stream
                .parse::<u64>()
                .map_err(|_| UdpRelayError::InvalidRouteSpec(entry.to_string()))?;
            let secret = parse_route_secret_hex(hex_secret)
                .ok_or_else(|| UdpRelayError::InvalidRouteSpec(entry.to_string()))?;
            self.insert_route_secret(stream_id, RouteHopSecret(secret));
            inserted += 1;
        }
        Ok(inserted)
    }

    pub async fn run_forever(&mut self) -> Result<(), UdpRelayError> {
        loop {
            let _ = self.relay_one().await?;
        }
    }

    pub async fn relay_one(&mut self) -> Result<RelayPacket, UdpRelayError> {
        let mut buf = [0u8; RELAY_PACKET_MAX_BYTES];
        let (len, src) = self.socket.recv_from(&mut buf).await?;
        self.increment_metrics(|m| m.packets_received = m.packets_received.saturating_add(1));
        if let Ok(handshake) = HandshakePacket::decode(&buf[..len]) {
            return self.handle_handshake_packet(handshake, src).await;
        }

        let packet = RelayPacket::decode(&buf[..len]).map_err(UdpRelayError::Packet)?;
        let decision = self
            .handler
            .process(packet)
            .map_err(UdpRelayError::Handler)?;

        match decision {
            RelayDecision::ForwardShard { packet, ack } => {
                self.forward_packet_and_ack(packet, ack, src).await
            }
            RelayDecision::ForwardRoute { packet, ack } => {
                self.process_route_packet_and_ack(packet, ack, src).await
            }
            RelayDecision::Respond(packet) => {
                self.send_packet(&packet, src).await?;
                Ok(packet)
            }
        }
    }

    async fn handle_handshake_packet(
        &mut self,
        packet: HandshakePacket,
        source: SocketAddr,
    ) -> Result<RelayPacket, UdpRelayError> {
        let Some(server_hello) = self.server_hello.clone() else {
            return Err(UdpRelayError::Handshake("handshake disabled".to_string()));
        };
        match packet.packet_type {
            HandshakePacketType::ServerHello if packet.payload.is_empty() => {
                let response = if let Some(challenge) = &self.pow_challenge {
                    let source_challenge = PowChallenge::new_stateless(
                        challenge.relay_id,
                        challenge.unix_window,
                        challenge.difficulty_zero_bits,
                        source.to_string().as_bytes(),
                        b"chronosd-local-pow-secret",
                    );
                    HandshakePacket::pow_challenge(&source_challenge).map_err(|e| {
                        UdpRelayError::Handshake(format!("encode pow challenge: {e:?}"))
                    })?
                } else {
                    let eph = NodeKeyMaterial::generate()
                        .map_err(|e| UdpRelayError::Handshake(format!("ephemeral keys: {e:?}")))?;
                    let eph_hello = HandshakePublicKeys::from_node_keys(&eph)
                        .to_server_hello_packet()
                        .map_err(|e| UdpRelayError::Handshake(format!("ephemeral hello: {e:?}")))?;
                    self.pending_handshakes
                        .insert(source, (eph_hello.clone(), eph));
                    eph_hello
                };
                let bytes = response
                    .encode()
                    .map_err(|e| UdpRelayError::Handshake(format!("encode hello: {e:?}")))?;
                self.socket.send_to(&bytes, source).await?;
                RelayPacket::ack(0, 0).map_err(UdpRelayError::Packet)
            }
            HandshakePacketType::PowSolution => {
                let Some(challenge) = &self.pow_challenge else {
                    return Err(UdpRelayError::Handshake("pow not required".to_string()));
                };
                let source_challenge = PowChallenge::new_stateless(
                    challenge.relay_id,
                    challenge.unix_window,
                    challenge.difficulty_zero_bits,
                    source.to_string().as_bytes(),
                    b"chronosd-local-pow-secret",
                );
                self.pow_cache
                    .verify_and_insert(&source_challenge, &packet.payload)
                    .map_err(|e| UdpRelayError::Handshake(format!("pow verify: {e:?}")))?;
                self.pow_admitted.insert(source);
                let eph = NodeKeyMaterial::generate()
                    .map_err(|e| UdpRelayError::Handshake(format!("ephemeral keys: {e:?}")))?;
                let eph_hello = HandshakePublicKeys::from_node_keys(&eph)
                    .to_server_hello_packet()
                    .map_err(|e| UdpRelayError::Handshake(format!("ephemeral hello: {e:?}")))?;
                self.pending_handshakes
                    .insert(source, (eph_hello.clone(), eph));
                let bytes = eph_hello
                    .encode()
                    .map_err(|e| UdpRelayError::Handshake(format!("encode hello: {e:?}")))?;
                self.socket.send_to(&bytes, source).await?;
                RelayPacket::ack(0, 0).map_err(UdpRelayError::Packet)
            }
            HandshakePacketType::ClientKeyShare => {
                if self.pow_challenge.is_some() && !self.pow_admitted.contains(&source) {
                    return Err(UdpRelayError::Handshake(
                        "pow admission required".to_string(),
                    ));
                }
                let (hello_for_client, keys_for_client) =
                    self.pending_handshakes.remove(&source).unwrap_or_else(|| {
                        (
                            server_hello.clone(),
                            self.node_keys
                                .clone()
                                .expect("node keys enabled for handshake"),
                        )
                    });
                let (confirm, state) =
                    server_accept_handshake(&hello_for_client, &packet, &keys_for_client).map_err(
                        |e| UdpRelayError::Handshake(format!("accept handshake: {e:?}")),
                    )?;
                let stream_id = self.next_session_stream_id;
                self.next_session_stream_id = self.next_session_stream_id.saturating_add(1);
                self.insert_route_secret(stream_id, state.route_secret.clone());
                self.session_streams.insert(stream_id);
                self.sessions.insert(source, state);
                let bytes = confirm
                    .encode()
                    .map_err(|e| UdpRelayError::Handshake(format!("encode confirm: {e:?}")))?;
                self.socket.send_to(&bytes, source).await?;
                RelayPacket::ack(stream_id, 0).map_err(UdpRelayError::Packet)
            }
            other => Err(UdpRelayError::Handshake(format!(
                "unsupported handshake packet: {other:?}"
            ))),
        }
    }

    async fn forward_packet_and_ack(
        &mut self,
        packet: RelayPacket,
        ack: RelayPacket,
        source: SocketAddr,
    ) -> Result<RelayPacket, UdpRelayError> {
        let destination = match self.routes.get(packet.stream_id) {
            Some(destination) => destination,
            None => {
                let error = RelayPacket::error_code(
                    packet.stream_id,
                    packet.sequence,
                    RelayErrorCode::NoRoute,
                )
                .map_err(UdpRelayError::Packet)?;
                self.send_packet(&error, source).await?;
                self.increment_metrics(|m| m.errors_sent = m.errors_sent.saturating_add(1));
                self.increment_metrics(|m| m.no_route_errors = m.no_route_errors.saturating_add(1));
                return Err(UdpRelayError::NoRoute {
                    stream_id: packet.stream_id,
                });
            }
        };
        if let Err(QueueError::Full(_)) = self.enqueue_packet(packet.clone(), destination) {
            return self
                .send_queue_full(source, packet.stream_id, packet.sequence)
                .await;
        }
        if let Err(QueueError::Full(_)) = self.enqueue_packet(ack.clone(), source) {
            return self
                .send_queue_full(source, ack.stream_id, ack.sequence)
                .await;
        }
        self.flush_outbound_queue().await?;
        Ok(ack)
    }

    async fn process_route_packet_and_ack(
        &mut self,
        packet: RelayPacket,
        ack: RelayPacket,
        source: SocketAddr,
    ) -> Result<RelayPacket, UdpRelayError> {
        if self.enforce_sessions && !self.session_streams.contains(&packet.stream_id) {
            let error = RelayPacket::error_code(
                packet.stream_id,
                packet.sequence,
                RelayErrorCode::NoSession,
            )
            .map_err(UdpRelayError::Packet)?;
            self.send_packet(&error, source).await?;
            self.increment_metrics(|m| m.errors_sent = m.errors_sent.saturating_add(1));
            return Err(UdpRelayError::NoSession {
                stream_id: packet.stream_id,
            });
        }
        let Some(secret) = self.route_secrets.get(&packet.stream_id).cloned() else {
            return self.forward_packet_and_ack(packet, ack, source).await;
        };

        let route_packet = packet.route_packet().map_err(UdpRelayError::Packet)?;
        let processor = self
            .route_processors
            .entry(packet.stream_id)
            .or_insert_with(|| {
                RouteLayerProcessor::with_replay_limits(
                    self.route_replay_max_entries,
                    self.route_replay_ttl,
                )
            });
        let peeled = processor
            .peel_once(&route_packet, route_packet.hop_index, &secret)
            .map_err(UdpRelayError::Route)?;
        self.increment_metrics(|m| {
            m.route_packets_peeled = m.route_packets_peeled.saturating_add(1)
        });

        let outbound = match peeled.command.kind() {
            RouteCommandKind::Forward => {
                let next = peeled.next_packet.ok_or(UdpRelayError::Route(
                    RouteLayerError::InvalidLength {
                        declared: 1,
                        available: 0,
                    },
                ))?;
                RelayPacket::route(peeled.command.next_stream_id, packet.sequence, &next)
                    .map_err(UdpRelayError::Packet)?
            }
            RouteCommandKind::DeliverLocal | RouteCommandKind::Reply => {
                let payload =
                    peeled
                        .payload
                        .ok_or(UdpRelayError::Route(RouteLayerError::InvalidLength {
                            declared: 1,
                            available: 0,
                        }))?;
                let stream_id = if peeled.command.kind() == RouteCommandKind::Reply {
                    peeled.command.next_stream_id
                } else {
                    packet.stream_id
                };
                RelayPacket::data(stream_id, packet.sequence, payload)
                    .map_err(UdpRelayError::Packet)?
            }
            RouteCommandKind::Drop => {
                let error = RelayPacket::error_code(
                    packet.stream_id,
                    packet.sequence,
                    RelayErrorCode::Drop,
                )
                .map_err(UdpRelayError::Packet)?;
                self.send_packet(&error, source).await?;
                self.increment_metrics(|m| m.errors_sent = m.errors_sent.saturating_add(1));
                return Err(UdpRelayError::Route(RouteLayerError::DropCommand));
            }
        };

        self.forward_packet_and_ack(outbound, ack, source).await
    }

    fn enqueue_packet(
        &mut self,
        packet: RelayPacket,
        destination: SocketAddr,
    ) -> Result<(), QueueError> {
        self.outbound_queue.push(QueuedRelayPacket {
            packet,
            destination,
        })
    }

    async fn flush_outbound_queue(&mut self) -> Result<(), UdpRelayError> {
        while let Some(item) = self.outbound_queue.pop() {
            let is_ack = item.packet.packet_type == chronos_core::RelayPacketType::Ack;
            self.send_packet(&item.packet, item.destination).await?;
            if is_ack {
                self.increment_metrics(|m| m.acks_sent = m.acks_sent.saturating_add(1));
            } else {
                self.increment_metrics(|m| {
                    m.packets_forwarded = m.packets_forwarded.saturating_add(1)
                });
            }
        }
        Ok(())
    }

    async fn send_queue_full(
        &mut self,
        destination: SocketAddr,
        stream_id: u64,
        sequence: u64,
    ) -> Result<RelayPacket, UdpRelayError> {
        let error = RelayPacket::error_code(stream_id, sequence, RelayErrorCode::QueueFull)
            .map_err(UdpRelayError::Packet)?;
        self.send_packet(&error, destination).await?;
        self.increment_metrics(|m| m.errors_sent = m.errors_sent.saturating_add(1));
        self.increment_metrics(|m| m.queue_full_errors = m.queue_full_errors.saturating_add(1));
        Err(UdpRelayError::QueueFull)
    }

    fn increment_metrics(&self, update: impl FnOnce(&mut UdpRelayMetrics)) {
        let mut metrics = self.metrics.lock().expect("metrics lock");
        update(&mut metrics);
    }

    async fn send_packet(
        &mut self,
        packet: &RelayPacket,
        destination: SocketAddr,
    ) -> Result<(), UdpRelayError> {
        if !self.tdm_slot_width.is_zero() {
            tokio::time::sleep(self.tdm_slot_width).await;
        }
        self.sent_tdm_slots = self.sent_tdm_slots.saturating_add(1);
        let bytes = packet.encode().map_err(UdpRelayError::Packet)?;
        self.socket.send_to(&bytes, destination).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chronos_core::{
        RelayPacketType, RouteCommand, RouteHopSecret, SecureShardBlockCodec,
        build_layered_route_packet, derive_link_key,
    };

    fn key() -> [u8; 32] {
        derive_link_key(&[0x91u8; 32], &[0x19u8; 16]).expect("key")
    }

    #[test]
    fn parses_static_route_entries() {
        let (stream, addr) = parse_route_entry("42=127.0.0.1:9999").expect("route");
        assert_eq!(stream, 42);
        assert_eq!(addr, "127.0.0.1:9999".parse::<SocketAddr>().expect("addr"));
        assert!(parse_route_entry("bad-route").is_err());
    }

    #[tokio::test]
    async fn udp_relay_forwards_shard_packet_and_acks_sender() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("receiver");
        let receiver_addr = receiver.local_addr().expect("receiver addr");
        let mut routes = StaticRouteTable::new();
        routes.insert(77, receiver_addr);
        let mut relay = ChronosUdpRelay::bind("127.0.0.1:0", routes)
            .await
            .expect("relay");
        let relay_addr = relay.local_addr().expect("relay addr");
        let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender");

        let codec = SecureShardBlockCodec::new();
        let cells = codec
            .encode_message(&key(), [0x19; 16], 1, 10, b"chronosd relay shard")
            .expect("encode");
        let packet = RelayPacket::shard(77, 1, &cells[0]).expect("packet");
        let bytes = packet.encode().expect("encode");
        sender.send_to(&bytes, relay_addr).await.expect("send");

        let relay_task = tokio::spawn(async move { relay.relay_one().await });
        let mut recv_buf = [0u8; RELAY_PACKET_MAX_BYTES];
        let (recv_len, _) = receiver.recv_from(&mut recv_buf).await.expect("recv");
        let forwarded = RelayPacket::decode(&recv_buf[..recv_len]).expect("forwarded");
        assert_eq!(forwarded, packet);

        let mut ack_buf = [0u8; RELAY_PACKET_MAX_BYTES];
        let (ack_len, _) = sender.recv_from(&mut ack_buf).await.expect("ack");
        let ack = RelayPacket::decode(&ack_buf[..ack_len]).expect("ack decode");
        assert_eq!(ack.packet_type, RelayPacketType::Ack);
        assert_eq!(ack.stream_id, 77);
        assert_eq!(ack.sequence, 1);
        assert_eq!(relay_task.await.expect("join").expect("relay result"), ack);
    }

    #[tokio::test]
    async fn udp_relay_returns_no_route_error_to_sender() {
        let routes = StaticRouteTable::new();
        let mut relay = ChronosUdpRelay::bind("127.0.0.1:0", routes)
            .await
            .expect("relay");
        let relay_addr = relay.local_addr().expect("relay addr");
        let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender");

        let codec = SecureShardBlockCodec::new();
        let cells = codec
            .encode_message(&key(), [0x19; 16], 3, 30, b"no route shard")
            .expect("encode");
        let packet = RelayPacket::shard(999, 3, &cells[0]).expect("packet");
        let bytes = packet.encode().expect("encode");
        sender.send_to(&bytes, relay_addr).await.expect("send");

        let relay_task = tokio::spawn(async move { relay.relay_one().await });
        let mut err_buf = [0u8; RELAY_PACKET_MAX_BYTES];
        let (err_len, _) = sender.recv_from(&mut err_buf).await.expect("error packet");
        let err = RelayPacket::decode(&err_buf[..err_len]).expect("decode error");
        assert_eq!(err.packet_type, RelayPacketType::Error);
        assert_eq!(err.stream_id, 999);
        assert_eq!(err.sequence, 3);
        assert_eq!(
            err.decode_error_code().expect("error code"),
            RelayErrorCode::NoRoute
        );
        assert_eq!(
            relay_task.await.expect("join"),
            Err(UdpRelayError::NoRoute { stream_id: 999 })
        );
    }

    #[tokio::test]
    async fn two_udp_relays_forward_shard_across_two_hops() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("receiver");
        let receiver_addr = receiver.local_addr().expect("receiver addr");

        let mut relay2_routes = StaticRouteTable::new();
        relay2_routes.insert(500, receiver_addr);
        let mut relay2 = ChronosUdpRelay::bind("127.0.0.1:0", relay2_routes)
            .await
            .expect("relay2");
        let relay2_addr = relay2.local_addr().expect("relay2 addr");

        let mut relay1_routes = StaticRouteTable::new();
        relay1_routes.insert(500, relay2_addr);
        let mut relay1 = ChronosUdpRelay::bind("127.0.0.1:0", relay1_routes)
            .await
            .expect("relay1");
        let relay1_addr = relay1.local_addr().expect("relay1 addr");

        let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender");
        let codec = SecureShardBlockCodec::new();
        let cells = codec
            .encode_message(&key(), [0x29; 16], 4, 40, b"two hop shard relay")
            .expect("encode");
        let packet = RelayPacket::shard(500, 4, &cells[0]).expect("packet");
        let bytes = packet.encode().expect("encode");

        let relay2_task = tokio::spawn(async move { relay2.relay_one().await });
        let relay1_task = tokio::spawn(async move { relay1.relay_one().await });
        sender.send_to(&bytes, relay1_addr).await.expect("send");

        let mut recv_buf = [0u8; RELAY_PACKET_MAX_BYTES];
        let (recv_len, _) = receiver.recv_from(&mut recv_buf).await.expect("recv");
        let forwarded = RelayPacket::decode(&recv_buf[..recv_len]).expect("forwarded");
        assert_eq!(forwarded, packet);

        let mut ack_buf = [0u8; RELAY_PACKET_MAX_BYTES];
        let (ack_len, _) = sender.recv_from(&mut ack_buf).await.expect("ack");
        let ack = RelayPacket::decode(&ack_buf[..ack_len]).expect("ack decode");
        assert_eq!(ack.packet_type, RelayPacketType::Ack);
        assert_eq!(ack.stream_id, 500);
        assert_eq!(ack.sequence, 4);

        assert_eq!(
            relay1_task.await.expect("relay1 join").expect("relay1"),
            ack
        );
        let relay2_ack = relay2_task.await.expect("relay2 join").expect("relay2");
        assert_eq!(relay2_ack.packet_type, RelayPacketType::Ack);
        assert_eq!(relay2_ack.stream_id, 500);
        assert_eq!(relay2_ack.sequence, 4);
    }

    #[tokio::test]
    async fn relay_rejects_route_without_session_when_enforced() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("receiver");
        let receiver_addr = receiver.local_addr().expect("receiver addr");
        let mut routes = StaticRouteTable::new();
        routes.insert(1, receiver_addr);
        let mut relay = ChronosUdpRelay::bind("127.0.0.1:0", routes)
            .await
            .expect("relay");
        relay.set_session_enforcement(true);
        let relay_addr = relay.local_addr().expect("relay addr");
        let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender");
        let route = chronos_core::build_layered_route_packet(
            42,
            &[RouteHopSecret([1; 32])],
            &[RouteCommand::deliver_local()],
            b"no session",
        )
        .expect("route");
        let packet = RelayPacket::route(1, 1, &route).expect("packet");
        sender
            .send_to(&packet.encode().unwrap(), relay_addr)
            .await
            .unwrap();
        assert_eq!(
            relay.relay_one().await,
            Err(UdpRelayError::NoSession { stream_id: 1 })
        );
        let mut buf = [0u8; RELAY_PACKET_MAX_BYTES];
        let (len, _) = sender.recv_from(&mut buf).await.expect("error");
        let err = RelayPacket::decode(&buf[..len]).expect("decode");
        assert_eq!(err.decode_error_code().unwrap(), RelayErrorCode::NoSession);
    }

    #[test]
    fn static_route_table_persists_to_disk() {
        let path = std::env::temp_dir().join(format!("chronos-routes-{}.txt", std::process::id()));
        let mut routes = StaticRouteTable::new();
        routes.insert(5, "127.0.0.1:55".parse().unwrap());
        routes.save_to_file(&path).unwrap();
        let loaded = StaticRouteTable::load_from_file(&path).unwrap();
        assert_eq!(loaded.get(5).unwrap(), "127.0.0.1:55".parse().unwrap());
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn security_rejects_replayed_pow_solution_from_same_source() {
        use chronos_core::{
            HandshakePacketType, NodeKeyMaterial, PowChallenge, solve_pow_for_tests,
        };
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("receiver");
        let mut routes = StaticRouteTable::new();
        routes.insert(10_000, receiver.local_addr().expect("receiver addr"));
        let mut relay = ChronosUdpRelay::bind("127.0.0.1:0", routes)
            .await
            .expect("relay");
        relay
            .enable_handshake(NodeKeyMaterial::generate().expect("keys"))
            .expect("enable");
        let challenge_template = PowChallenge {
            relay_id: [4; 16],
            unix_window: 1,
            difficulty_zero_bits: 8,
            token: [0; 32],
        };
        relay.enable_pow_admission(challenge_template.clone());
        let relay_addr = relay.local_addr().expect("relay addr");
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");

        let hello_request = HandshakePacket::new(HandshakePacketType::ServerHello, Vec::new())
            .expect("hello request");
        client
            .send_to(&hello_request.encode().expect("encode"), relay_addr)
            .await
            .expect("send hello request");
        relay.relay_one().await.expect("challenge response");
        let mut buf = [0u8; 4096];
        let (len, _) = client.recv_from(&mut buf).await.expect("receive challenge");
        let challenge = HandshakePacket::decode(&buf[..len])
            .expect("decode challenge")
            .decode_pow_challenge()
            .expect("pow challenge");
        let nonce = solve_pow_for_tests(&challenge, 100_000).expect("solve pow");
        let solution = HandshakePacket::pow_solution(nonce).expect("solution");
        let solution_bytes = solution.encode().expect("encode solution");

        client
            .send_to(&solution_bytes, relay_addr)
            .await
            .expect("send first solution");
        relay.relay_one().await.expect("first solution accepted");
        let (_hello_len, _) = client
            .recv_from(&mut buf)
            .await
            .expect("receive server hello");

        client
            .send_to(&solution_bytes, relay_addr)
            .await
            .expect("replay solution");
        assert!(
            relay.relay_one().await.is_err(),
            "replayed PowSolution from same source was accepted; PoW nonces must be single-use"
        );
    }

    #[tokio::test]
    async fn live_chs7_handshake_requires_pow_when_enabled() {
        use chronos_core::{
            HandshakePacketType, NodeKeyMaterial, PowChallenge, X25519NodeSecret,
            client_begin_handshake, client_verify_server_confirm, solve_pow_for_tests,
        };
        let mut routes = StaticRouteTable::new();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("receiver");
        routes.insert(10_000, receiver.local_addr().expect("receiver addr"));
        let mut relay = ChronosUdpRelay::bind("127.0.0.1:0", routes)
            .await
            .expect("relay");
        relay
            .enable_handshake(NodeKeyMaterial::generate().expect("keys"))
            .expect("enable");
        let challenge_template = PowChallenge {
            relay_id: [3; 16],
            unix_window: 1,
            difficulty_zero_bits: 8,
            token: [0; 32],
        };
        relay.enable_pow_admission(challenge_template.clone());
        let relay_addr = relay.local_addr().expect("addr");
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
        let expected_challenge = PowChallenge::new_stateless(
            challenge_template.relay_id,
            challenge_template.unix_window,
            challenge_template.difficulty_zero_bits,
            client
                .local_addr()
                .expect("client addr")
                .to_string()
                .as_bytes(),
            b"chronosd-local-pow-secret",
        );

        let hello_request =
            HandshakePacket::new(HandshakePacketType::ServerHello, Vec::new()).expect("req");
        client
            .send_to(&hello_request.encode().unwrap(), relay_addr)
            .await
            .unwrap();
        relay.relay_one().await.expect("challenge");
        let mut buf = [0u8; 4096];
        let (len, _) = client.recv_from(&mut buf).await.expect("recv challenge");
        let challenge_packet = HandshakePacket::decode(&buf[..len]).expect("decode challenge");
        assert_eq!(
            challenge_packet.decode_pow_challenge().expect("pow"),
            expected_challenge
        );

        let nonce = solve_pow_for_tests(&expected_challenge, 100_000).expect("solve");
        let solution = HandshakePacket::pow_solution(nonce).expect("solution");
        client
            .send_to(&solution.encode().unwrap(), relay_addr)
            .await
            .unwrap();
        relay.relay_one().await.expect("hello after pow");
        let (hlen, _) = client.recv_from(&mut buf).await.expect("hello");
        let server_hello = HandshakePacket::decode(&buf[..hlen]).expect("decode hello");

        let (client_share, client_state) =
            client_begin_handshake(&server_hello, &X25519NodeSecret::from_bytes([0xBC; 32]))
                .expect("begin");
        client
            .send_to(&client_share.encode().unwrap(), relay_addr)
            .await
            .unwrap();
        relay.relay_one().await.expect("accept share");
        let (clen, _) = client.recv_from(&mut buf).await.expect("confirm");
        let confirm = HandshakePacket::decode(&buf[..clen]).expect("decode confirm");
        client_verify_server_confirm(&client_state, &confirm).expect("confirm");
    }

    #[tokio::test]
    async fn live_chs7_handshake_installs_route_secret_for_delivery() {
        use chronos_core::{
            HandshakePacketType, HandshakePublicKeys, X25519NodeSecret, client_begin_handshake,
            client_verify_server_confirm,
        };

        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("receiver");
        let receiver_addr = receiver.local_addr().expect("receiver addr");
        let mut routes = StaticRouteTable::new();
        routes.insert(10_000, receiver_addr);
        let mut relay = ChronosUdpRelay::bind("127.0.0.1:0", routes)
            .await
            .expect("relay");
        let server_keys = NodeKeyMaterial::generate().expect("server keys");
        relay
            .enable_handshake(server_keys)
            .expect("enable handshake");
        let relay_addr = relay.local_addr().expect("relay addr");
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");

        let hello_request = HandshakePacket::new(HandshakePacketType::ServerHello, Vec::new())
            .expect("hello request");
        client
            .send_to(&hello_request.encode().expect("encode request"), relay_addr)
            .await
            .expect("send request");
        relay.relay_one().await.expect("serve hello");
        let mut hbuf = [0u8; 4096];
        let (hlen, _) = client.recv_from(&mut hbuf).await.expect("hello");
        let server_hello = HandshakePacket::decode(&hbuf[..hlen]).expect("decode hello");
        let parsed =
            HandshakePublicKeys::from_server_hello_packet(&server_hello).expect("parse hello keys");
        assert_ne!(parsed.x25519_public.0, [0u8; 32]);

        let client_x = X25519NodeSecret::from_bytes([0xAB; 32]);
        let (client_share, client_state) =
            client_begin_handshake(&server_hello, &client_x).expect("client share");
        client
            .send_to(&client_share.encode().expect("encode share"), relay_addr)
            .await
            .expect("send share");
        let relay_result = relay.relay_one().await.expect("accept share");
        assert_eq!(relay_result.stream_id, 10_000);
        assert_eq!(relay.session_count(), 1);
        let (clen, _) = client.recv_from(&mut hbuf).await.expect("confirm");
        let confirm = HandshakePacket::decode(&hbuf[..clen]).expect("decode confirm");
        client_verify_server_confirm(&client_state, &confirm).expect("verify confirm");

        let route = chronos_core::build_layered_route_packet(
            90_000,
            &[client_state.route_secret],
            &[RouteCommand::deliver_local()],
            b"post-handshake route payload",
        )
        .expect("route");
        let packet = RelayPacket::route(10_000, 1, &route).expect("route packet");
        client
            .send_to(&packet.encode().expect("encode route"), relay_addr)
            .await
            .expect("send route");
        relay.relay_one().await.expect("process route");

        let mut rbuf = [0u8; RELAY_PACKET_MAX_BYTES];
        let (rlen, _) = receiver.recv_from(&mut rbuf).await.expect("delivered");
        let delivered = RelayPacket::decode(&rbuf[..rlen]).expect("decode delivered");
        assert_eq!(delivered.packet_type, RelayPacketType::Data);
        assert_eq!(delivered.payload, b"post-handshake route payload");
    }

    #[tokio::test]
    async fn three_udp_relays_peel_route_layers_to_local_delivery() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("receiver");
        let receiver_addr = receiver.local_addr().expect("receiver addr");

        let secret1 = RouteHopSecret([0xD1; 32]);
        let secret2 = RouteHopSecret([0xD2; 32]);
        let secret3 = RouteHopSecret([0xD3; 32]);
        let route = build_layered_route_packet(
            8000,
            &[secret1.clone(), secret2.clone(), secret3.clone()],
            &[
                RouteCommand::forward(20),
                RouteCommand::forward(30),
                RouteCommand::deliver_local(),
            ],
            b"three-hop delivered payload",
        )
        .expect("route");

        let mut relay3_routes = StaticRouteTable::new();
        relay3_routes.insert(30, receiver_addr);
        let mut relay3 = ChronosUdpRelay::bind("127.0.0.1:0", relay3_routes)
            .await
            .expect("relay3");
        relay3.insert_route_secret(30, secret3);
        let relay3_addr = relay3.local_addr().expect("relay3 addr");

        let mut relay2_routes = StaticRouteTable::new();
        relay2_routes.insert(30, relay3_addr);
        let mut relay2 = ChronosUdpRelay::bind("127.0.0.1:0", relay2_routes)
            .await
            .expect("relay2");
        relay2.insert_route_secret(20, secret2);
        let relay2_addr = relay2.local_addr().expect("relay2 addr");

        let mut relay1_routes = StaticRouteTable::new();
        relay1_routes.insert(20, relay2_addr);
        let mut relay1 = ChronosUdpRelay::bind("127.0.0.1:0", relay1_routes)
            .await
            .expect("relay1");
        relay1.insert_route_secret(10, secret1);
        let relay1_addr = relay1.local_addr().expect("relay1 addr");

        let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender");
        let packet = RelayPacket::route(10, 123, &route).expect("packet");
        let bytes = packet.encode().expect("encode");

        let relay3_task = tokio::spawn(async move { relay3.relay_one().await });
        let relay2_task = tokio::spawn(async move { relay2.relay_one().await });
        let relay1_task = tokio::spawn(async move { relay1.relay_one().await });
        sender.send_to(&bytes, relay1_addr).await.expect("send");

        let mut recv_buf = [0u8; RELAY_PACKET_MAX_BYTES];
        let (recv_len, _) = receiver.recv_from(&mut recv_buf).await.expect("deliver");
        let delivered = RelayPacket::decode(&recv_buf[..recv_len]).expect("decode delivered");
        assert_eq!(delivered.packet_type, RelayPacketType::Data);
        assert_eq!(delivered.stream_id, 30);
        assert_eq!(delivered.sequence, 123);
        assert_eq!(delivered.payload, b"three-hop delivered payload");

        let mut ack_buf = [0u8; RELAY_PACKET_MAX_BYTES];
        let (ack_len, _) = sender.recv_from(&mut ack_buf).await.expect("ack");
        let ack = RelayPacket::decode(&ack_buf[..ack_len]).expect("decode ack");
        assert_eq!(ack.packet_type, RelayPacketType::Ack);
        assert_eq!(ack.stream_id, 10);
        assert_eq!(ack.sequence, 123);

        assert_eq!(
            relay1_task.await.expect("relay1").expect("relay1 result"),
            ack
        );
        assert_eq!(
            relay2_task
                .await
                .expect("relay2")
                .expect("relay2 result")
                .packet_type,
            RelayPacketType::Ack
        );
        assert_eq!(
            relay3_task
                .await
                .expect("relay3")
                .expect("relay3 result")
                .packet_type,
            RelayPacketType::Ack
        );
    }

    #[tokio::test]
    async fn udp_relay_returns_queue_full_when_outbound_queue_is_saturated() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("receiver");
        let receiver_addr = receiver.local_addr().expect("receiver addr");
        let mut routes = StaticRouteTable::new();
        routes.insert(77, receiver_addr);
        let mut relay = ChronosUdpRelay::bind_with_runtime_config(
            "127.0.0.1:0",
            routes,
            4096,
            std::time::Duration::from_secs(300),
            1,
        )
        .await
        .expect("relay");
        let relay_addr = relay.local_addr().expect("relay addr");
        let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender");
        let codec = SecureShardBlockCodec::new();
        let cells = codec
            .encode_message(&key(), [0x49; 16], 6, 60, b"queue full shard")
            .expect("encode");
        let packet = RelayPacket::shard(77, 6, &cells[0]).expect("packet");
        sender
            .send_to(&packet.encode().expect("encode"), relay_addr)
            .await
            .expect("send");
        assert_eq!(relay.relay_one().await, Err(UdpRelayError::QueueFull));
        let mut err_buf = [0u8; RELAY_PACKET_MAX_BYTES];
        let (err_len, _) = sender
            .recv_from(&mut err_buf)
            .await
            .expect("queue full error");
        let err = RelayPacket::decode(&err_buf[..err_len]).expect("decode error");
        assert_eq!(
            err.decode_error_code().expect("error code"),
            RelayErrorCode::QueueFull
        );
        assert_eq!(relay.metrics().queue_full_errors, 1);
    }

    #[tokio::test]
    async fn udp_relay_tdm_pacing_counts_send_slots() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("receiver");
        let receiver_addr = receiver.local_addr().expect("receiver addr");
        let mut routes = StaticRouteTable::new();
        routes.insert(77, receiver_addr);
        let mut relay = ChronosUdpRelay::bind("127.0.0.1:0", routes)
            .await
            .expect("relay");
        relay.enable_tdm_pacing(std::time::Duration::from_millis(1));
        let relay_addr = relay.local_addr().expect("relay addr");
        let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender");
        let codec = SecureShardBlockCodec::new();
        let cells = codec
            .encode_message(&key(), [0x59; 16], 7, 70, b"tdm shard")
            .expect("encode");
        let packet = RelayPacket::shard(77, 7, &cells[0]).expect("packet");
        sender
            .send_to(&packet.encode().expect("encode"), relay_addr)
            .await
            .expect("send");
        let _ = relay.relay_one().await.expect("relay one");
        // one forwarded packet + one ACK were paced through the live send path
        assert_eq!(relay.sent_tdm_slots(), 2);
    }

    #[tokio::test]
    async fn udp_relay_metrics_count_forward_and_ack() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("receiver");
        let receiver_addr = receiver.local_addr().expect("receiver addr");
        let mut routes = StaticRouteTable::new();
        routes.insert(77, receiver_addr);
        let mut relay = ChronosUdpRelay::bind("127.0.0.1:0", routes)
            .await
            .expect("relay");
        let relay_addr = relay.local_addr().expect("relay addr");
        let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender");
        let codec = SecureShardBlockCodec::new();
        let cells = codec
            .encode_message(&key(), [0x39; 16], 5, 50, b"metrics shard")
            .expect("encode");
        let packet = RelayPacket::shard(77, 5, &cells[0]).expect("packet");
        sender
            .send_to(&packet.encode().expect("encode"), relay_addr)
            .await
            .expect("send");
        let _ = relay.relay_one().await.expect("relay one");
        let metrics = relay.metrics();
        assert_eq!(metrics.packets_received, 1);
        assert_eq!(metrics.packets_forwarded, 1);
        assert_eq!(metrics.acks_sent, 1);
    }

    #[tokio::test]
    async fn udp_relay_forwards_route_packet_and_acks_sender() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("receiver");
        let receiver_addr = receiver.local_addr().expect("receiver addr");
        let mut routes = StaticRouteTable::new();
        routes.insert(88, receiver_addr);
        let mut relay = ChronosUdpRelay::bind("127.0.0.1:0", routes)
            .await
            .expect("relay");
        let relay_addr = relay.local_addr().expect("relay addr");
        let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender");

        let secrets = vec![RouteHopSecret([0xA1; 32]), RouteHopSecret([0xA2; 32])];
        let commands = vec![RouteCommand::forward(1), RouteCommand::deliver_local()];
        let route =
            build_layered_route_packet(55, &secrets, &commands, b"route payload").expect("route");
        let packet = RelayPacket::route(88, 2, &route).expect("packet");
        let bytes = packet.encode().expect("encode");
        sender.send_to(&bytes, relay_addr).await.expect("send");

        let relay_task = tokio::spawn(async move { relay.relay_one().await });
        let mut recv_buf = [0u8; RELAY_PACKET_MAX_BYTES];
        let (recv_len, _) = receiver.recv_from(&mut recv_buf).await.expect("recv");
        let forwarded = RelayPacket::decode(&recv_buf[..recv_len]).expect("forwarded");
        assert_eq!(forwarded, packet);

        let mut ack_buf = [0u8; RELAY_PACKET_MAX_BYTES];
        let (ack_len, _) = sender.recv_from(&mut ack_buf).await.expect("ack");
        let ack = RelayPacket::decode(&ack_buf[..ack_len]).expect("ack decode");
        assert_eq!(ack.packet_type, RelayPacketType::Ack);
        assert_eq!(ack.stream_id, 88);
        assert_eq!(ack.sequence, 2);
        assert_eq!(relay_task.await.expect("join").expect("relay result"), ack);
    }
}
