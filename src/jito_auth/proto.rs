//! Generated tonic/prost bindings for the subset of Jito MEV protos we need.
//!
//! Only `auth`, `shared`, `shredstream` packages are compiled — the relayer,
//! searcher, bundle, and block surfaces stay out of the binary.

#![allow(dead_code)] // some generated message types aren't used directly

pub mod shared {
    tonic::include_proto!("shared");
}

pub mod auth {
    tonic::include_proto!("auth");
}

pub mod shredstream {
    tonic::include_proto!("shredstream");
}
