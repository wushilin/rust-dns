//! Prototype: a trigger-captured, hash-chained SQLite change log, replicated
//! leader → follower over a JSON/HTTP protocol.

pub mod client;
pub mod clients;
pub mod hash;
pub mod node;
pub mod schema;
pub mod server;
pub mod store;
pub mod wire;
