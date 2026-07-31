#![deny(unsafe_code)]
//! Experimental WebAssembly bindings.
//!
//! The default build exposes only small local protocol demonstrations. Optional
//! browser-behaviour models are explicitly feature-gated as simulations and are
//! not transport implementations.

pub mod bindings;

#[cfg(feature = "simulation")]
pub mod equihash;
#[cfg(feature = "simulation")]
pub mod hydra_tcp;
#[cfg(feature = "simulation")]
pub mod imes;
#[cfg(feature = "simulation")]
pub mod mobile_power;
#[cfg(feature = "simulation")]
pub mod stego_ws;
#[cfg(feature = "simulation")]
pub mod transport;

pub use bindings::*;
#[cfg(feature = "simulation")]
pub use equihash::*;
#[cfg(feature = "simulation")]
pub use hydra_tcp::*;
#[cfg(feature = "simulation")]
pub use imes::*;
#[cfg(feature = "simulation")]
pub use mobile_power::*;
#[cfg(feature = "simulation")]
pub use stego_ws::*;
#[cfg(feature = "simulation")]
pub use transport::*;
