//! Requests tawnydns sends to pdns on its own behalf (e.g. for dyndns), as opposed to the
//! passthrough models of the proxy. The models are strict: only what is read and written.

pub mod api;
mod error;
pub mod model;

pub use error::Error;
