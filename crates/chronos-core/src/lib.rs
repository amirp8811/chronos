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

pub use fountain::*;
pub use framing::*;
pub use gf28::*;
pub use handshake::*;
pub use hybrid_route::*;
pub use mix_policy::*;
pub use relay_packet::*;
pub use secure_cell::*;
pub use shard_stream::*;
pub use sphinx::*;
pub use tdm::*;

#[cfg(feature = "std")]
pub use anonymity_metrics::*;
#[cfg(feature = "std")]
pub use handshake_protocol::*;
#[cfg(feature = "std")]
pub use key_store::*;
#[cfg(feature = "std")]
pub use pow::*;
#[cfg(feature = "std")]
pub use pow_admission::*;
#[cfg(feature = "std")]
pub use ratchet::*;
#[cfg(feature = "std")]
pub use relay_handler::*;
#[cfg(feature = "std")]
pub use route_layer::*;
#[cfg(feature = "std")]
pub use session::*;
#[cfg(feature = "std")]
pub use traffic_analysis::*;

mod kani_harness;
mod kat_tests;
