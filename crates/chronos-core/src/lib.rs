#![deny(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod clock;
pub mod fountain;
pub mod framing;
pub mod gf28;
pub mod handshake;
pub mod mix_policy;
pub mod secure_cell;
pub mod shard_stream;

#[cfg(feature = "simulation")]
pub mod sphinx_sim;

#[cfg(feature = "std")]
pub mod hybrid_route;
#[cfg(feature = "std")]
pub mod relay_packet;
#[cfg(feature = "std")]
pub mod tdm;

#[cfg(feature = "std")]
pub mod anonymity_metrics;
#[cfg(feature = "std")]
pub mod handshake_protocol;
#[cfg(feature = "std")]
pub mod key_store;
#[cfg(feature = "std")]
pub mod pow;
#[cfg(feature = "std")]
pub mod pow_admission;
#[cfg(feature = "std")]
pub mod ratchet;
#[cfg(feature = "std")]
pub mod relay_handler;
#[cfg(feature = "std")]
pub mod route_layer;
#[cfg(feature = "std")]
pub mod session;
#[cfg(feature = "std")]
pub mod traffic_analysis;

#[cfg(feature = "std")]
pub use clock::StdClock;
pub use clock::{Clock, ManualClock};

pub use fountain::{
    FountainConfig, FountainDecoder, FountainEncodeReport, FountainSymbol,
    encode_payload_with_repair, fountain_encode, join_payload, progressive_recovery_count,
    split_payload, try_decode_payload,
};

pub use framing::{
    APP_CELL_PAYLOAD_SIZE, SIMD_SCRATCHPAD_SIZE, UmemFrameDescriptor, WIRE_DATAGRAM_SIZE,
};

pub use gf28::{
    PRIMITIVE_POLYNOMIAL_MASK_0X1D, ReedSolomon16_10, align_simd_symbol_slice, gf_inv_0x1d,
    gf_mul_0x1d,
};

pub use handshake::{LinkSharedSecret, X25519NodePublic, X25519NodeSecret};

#[cfg(feature = "std")]
pub use hybrid_route::{
    HybridRouteEncapsulation, HybridRouteError, MlKem768Ciphertext, MlKem768RouteKeypair,
    encapsulate_route_secret,
};

pub use mix_policy::{
    AdaptiveMixConfig, AdaptiveMixDecision, AdaptiveMixer, MixProfile, MixTelemetry,
};

#[cfg(feature = "std")]
pub use relay_packet::{
    RELAY_PACKET_HEADER_SIZE, RELAY_PACKET_MAGIC, RELAY_PACKET_MAX_BYTES, RELAY_PACKET_MAX_PAYLOAD,
    RELAY_PACKET_VERSION, RelayErrorCode, RelayPacket, RelayPacketError, RelayPacketType,
};

pub use secure_cell::{
    ReceiveCellError, ReplayError, ReplayWindow, SECURE_CELL_AAD_SIZE, SECURE_CELL_CIPHERTEXT_SIZE,
    SECURE_CELL_HEADER_SIZE, SECURE_CELL_MAGIC, SECURE_CELL_RESERVED_SIZE, SECURE_CELL_TAG_SIZE,
    SECURE_CELL_VERSION, SecureCellError, SecureCellReceiver, SecureCellSender, SecureShardCell,
    derive_link_key,
};

pub use shard_stream::{
    SHARD_STREAM_FLAG_PARITY, SHARD_STREAM_HEADER_SIZE, SHARD_STREAM_K, SHARD_STREAM_MAGIC,
    SHARD_STREAM_MAX_SYMBOL_BYTES, SHARD_STREAM_N, SecureShardBlockCodec, SecureShardBlockEncoder,
    ShardStreamError,
};

#[cfg(feature = "simulation")]
pub use sphinx_sim::{SimulationOnionCell, SimulationOnionError, SphinxSimulationProcessor};

#[cfg(feature = "std")]
pub use tdm::{TdmCellKind, TdmScheduler, TdmSlot};

#[cfg(feature = "std")]
pub use anonymity_metrics::{
    FecCompareRow, FlowTimingPair, LatencyCdf, MixExperimentReport, bandwidth_multiplier,
    compare_fec_overhead, interval_histogram, kl_divergence, latencies_us, latency_cdf,
    length_histogram, mutual_information_timing, percentile, shannon_entropy,
    simulate_adaptive_mix, sweep_mix_k_latency_csv,
};

#[cfg(feature = "std")]
pub use handshake_protocol::{
    CLIENT_KEY_SHARE_PAYLOAD_BYTES, ClientHandshakeState, ED25519_PUBLIC_KEY_BYTES,
    ED25519_SIGNATURE_BYTES, HANDSHAKE_MAGIC, HANDSHAKE_SUITE_MLKEM768_X25519_CHACHA20POLY1305,
    HANDSHAKE_VERSION, HandshakeError, HandshakePacket, HandshakePacketType, HandshakePublicKeys,
    KEY_CONFIRM_SIZE, MLKEM768_CIPHERTEXT_BYTES, MLKEM768_PUBLIC_KEY_BYTES,
    SERVER_HELLO_PAYLOAD_BYTES, ServerHandshakeState, client_begin_handshake_for_identity,
    client_verify_server_confirm, server_accept_handshake,
};

#[cfg(feature = "std")]
pub use key_store::{
    ED25519_IDENTITY_FILE, KeyStoreError, MLKEM768_SEED_FILE, NodeKeyMaterial, X25519_KEY_FILE,
};

#[cfg(feature = "std")]
pub use pow::{PoWVerificationEngine, SramCuckooBloomFilter};

#[cfg(feature = "std")]
pub use pow_admission::{PowAdmissionCache, PowAdmissionError, PowChallenge, solve_pow_for_tests};

#[cfg(feature = "std")]
pub use ratchet::SessionKeyRatchet;

#[cfg(feature = "std")]
pub use relay_handler::{RelayDecision, RelayHandlerError, RelayPacketHandler};

#[cfg(feature = "std")]
pub use route_layer::{
    LayeredRoutePacket, PeeledRouteLayer, ROUTE_LAYER_HEADER_SIZE, ROUTE_LAYER_MAGIC,
    ROUTE_LAYER_MAX_BODY, ROUTE_LAYER_TAG_SIZE, ROUTE_LAYER_VERSION, ROUTE_PACKET_HEADER_SIZE,
    ROUTE_PACKET_MAGIC, RouteCommand, RouteCommandKind, RouteHopSecret, RouteLayerError,
    RouteLayerProcessor, RouteReplayCache, SingleUseReplyBlock, build_layered_route_packet,
    peel_route_layer,
};

#[cfg(feature = "std")]
pub use session::{CircuitSession, SessionError, SessionManager, SessionState};

#[cfg(feature = "std")]
pub use traffic_analysis::{
    PacketObservation, TrafficClassifierScore, TrafficShapeReport, analyze_observations,
    heuristic_classifier_score, observations_from_csv, observations_to_csv,
    synthesize_constant_rate_trace,
};
