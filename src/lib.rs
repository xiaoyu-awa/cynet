#![warn(missing_docs, unnameable_types)]

//! The library of cynet, which builds a WireGuard mesh and routes it with the
//! Babel routing protocol ([RFC 8966]).
//!
//! Every WireGuard peer is a Babel neighbour over a point-to-point link. The
//! [`babel`] module implements the protocol as a state machine that does no I/O
//! and reads no clock: it is fed received packets and the time, and outputs
//! packets to send, routes to select, hold, or remove, and when to call it next.
//!
//! [RFC 8966]: https://www.rfc-editor.org/info/rfc8966/

/// An IPv6-only implementation of the Babel routing protocol over point-to-point links.
pub mod babel;
mod tun;
mod wireguard;
