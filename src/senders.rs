//! Transaction submitters. Each module here owns its own transport and
//! exposes a non-blocking `submit(bytes)` handle that the slot trigger
//! can call from the receiver thread without awaiting.
//!
//! Today: node1 over QUIC. Later: more (Astralane, Helius sender,
//! …) — when the second one lands we factor a shared trait.

pub mod node1;
