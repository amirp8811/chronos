#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod clock;
pub mod fountain;
pub mod framing;
pub mod gf28;
pub mod handshake;
pub mod hybrid_route;
pub mod mix_policy;
pub mod relay_packet;
pub mod secure_cell;
pub mod shard_stream;
pub mod sphinx;
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

pub use clock::{
    Clock,
    StdClock,
    ManualClock,
};

pub use fountain::{
    FountainSymbol,
    FountainConfig,
    fountain_encode,
    split_payload,
    join_payload,
    FountainDecoder,
    FountainEncodeReport,
    encode_payload_with_repair,
    try_decode_payload,
    progressive_recovery_count,
};

pub use framing::{
    WIRE_DATAGRAM_SIZE,
    APP_CELL_PAYLOAD_SIZE,
    SIMD_SCRATCHPAD_SIZE,
    SphinxPqcCell,
    UmemFrameDescriptor,
};

pub use gf28::{
    PRIMITIVE_POLYNOMIAL_MASK_0X1D,
    gf_mul_0x1d,
    gf_inv_0x1d,
    align_simd_symbol_slice,
    ReedSolomon16_10,
};

pub use handshake::{
    X25519NodeSecret,
    X25519NodePublic,
    LinkSharedSecret,
};

pub use hybrid_route::{
    MlKem768Ciphertext,
    MlKem768RouteKeypair,
    HybridRouteEncapsulation,
    HybridRouteError,
    encapsulate_route_secret,
};

pub use mix_policy::{
    AdaptiveMixDecision,
    MixProfile,
    AdaptiveMixConfig,
    MixTelemetry,
    AdaptiveMixer,
};

pub use relay_packet::{
    RELAY_PACKET_MAGIC,
    RELAY_PACKET_VERSION,
    RELAY_PACKET_HEADER_SIZE,
    RELAY_PACKET_MAX_PAYLOAD,
    RELAY_PACKET_MAX_BYTES,
    RelayPacketType,
    RelayErrorCode,
    RelayPacketError,
    RelayPacket,
};

pub use secure_cell::{
    SECURE_CELL_MAGIC,
    SECURE_CELL_VERSION,
    SECURE_CELL_HEADER_SIZE,
    SECURE_CELL_CIPHERTEXT_SIZE,
    SECURE_CELL_TAG_SIZE,
    SECURE_CELL_RESERVED_SIZE,
    SECURE_CELL_AAD_SIZE,
    SecureCellError,
    derive_link_key,
    SecureShardCell,
    ReplayError,
    ReplayWindow,
    SecureCellReceiver,
    ReceiveCellError,
};

pub use shard_stream::{
    SHARD_STREAM_MAGIC,
    SHARD_STREAM_K,
    SHARD_STREAM_N,
    SHARD_STREAM_HEADER_SIZE,
    SHARD_STREAM_MAX_SYMBOL_BYTES,
    SHARD_STREAM_FLAG_PARITY,
    ShardStreamError,
    SecureShardBlockCodec,
};

pub use sphinx::{
    SphinxOnionProcessor,
};

pub use tdm::{
    TdmCellKind,
    TdmSlot,
    TdmScheduler,
};

#[cfg(feature = "std")]
pub use anonymity_metrics::{
    shannon_entropy,
    kl_divergence,
    interval_histogram,
    length_histogram,
    FlowTimingPair,
    mutual_information_timing,
    latencies_us,
    percentile,
    LatencyCdf,
    latency_cdf,
    bandwidth_multiplier,
    MixExperimentReport,
    simulate_adaptive_mix,
    sweep_mix_k_latency_csv,
    FecCompareRow,
    compare_fec_overhead,
};

#[cfg(feature = "std")]
pub use handshake_protocol::{
    HANDSHAKE_MAGIC,
    HANDSHAKE_VERSION,
    HANDSHAKE_SUITE_MLKEM768_X25519_CHACHA20POLY1305,
    KEY_CONFIRM_SIZE,
    MLKEM768_PUBLIC_KEY_BYTES,
    MLKEM768_CIPHERTEXT_BYTES,
    ED25519_PUBLIC_KEY_BYTES,
    ED25519_SIGNATURE_BYTES,
    SERVER_HELLO_PAYLOAD_BYTES,
    CLIENT_KEY_SHARE_PAYLOAD_BYTES,
    HandshakePacketType,
    HandshakeError,
    HandshakePacket,
    HandshakePublicKeys,
    ClientHandshakeState,
    ServerHandshakeState,
    client_begin_handshake,
    server_accept_handshake,
    client_verify_server_confirm,
};

#[cfg(feature = "std")]
pub use key_store::{
    X25519_KEY_FILE,
    MLKEM768_SEED_FILE,
    ED25519_IDENTITY_FILE,
    KeyStoreError,
    NodeKeyMaterial,
};

#[cfg(feature = "std")]
pub use pow::{
    SramCuckooBloomFilter,
    PoWVerificationEngine,
};

#[cfg(feature = "std")]
pub use pow_admission::{
    PowChallenge,
    PowAdmissionError,
    solve_pow_for_tests,
    PowAdmissionCache,
};

#[cfg(feature = "std")]
pub use ratchet::{
    SessionKeyRatchet,
};

#[cfg(feature = "std")]
pub use relay_handler::{
    RelayHandlerError,
    RelayDecision,
    RelayPacketHandler,
};

#[cfg(feature = "std")]
pub use route_layer::{
    ROUTE_LAYER_MAGIC,
    ROUTE_LAYER_VERSION,
    ROUTE_LAYER_HEADER_SIZE,
    ROUTE_LAYER_TAG_SIZE,
    ROUTE_LAYER_MAX_BODY,
    ROUTE_PACKET_MAGIC,
    ROUTE_PACKET_HEADER_SIZE,
    RouteLayerError,
    RouteCommandKind,
    RouteCommand,
    RouteHopSecret,
    LayeredRoutePacket,
    PeeledRouteLayer,
    RouteReplayCache,
    RouteLayerProcessor,
    SingleUseReplyBlock,
    build_layered_route_packet,
    peel_route_layer,
};

#[cfg(feature = "std")]
pub use session::{
    SessionState,
    CircuitSession,
    SessionError,
    SessionManager,
};

#[cfg(feature = "std")]
pub use traffic_analysis::{
    PacketObservation,
    TrafficShapeReport,
    analyze_observations,
    synthesize_constant_rate_trace,
    TrafficClassifierScore,
    heuristic_classifier_score,
    observations_to_csv,
    observations_from_csv,
};
