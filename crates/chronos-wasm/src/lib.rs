#![deny(unsafe_code)]
//! Experimental WebAssembly bindings and bounded local parsers.
//!
//! This crate does not implement a browser transport or network client.

pub mod bindings;
pub mod websocket_frame;

pub use bindings::*;
pub use websocket_frame::*;
