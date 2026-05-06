//! 8-byte instruction discriminators for the pump.fun program. Pulled
//! verbatim from `docs/pump-sdk/src/idl/pump.json` — never recompute them
//! at runtime, just embed the canonical bytes.

pub const CREATE_V2: [u8; 8] = [214, 144, 76, 236, 95, 139, 49, 180];
pub const BUY: [u8; 8] = [102, 6, 61, 18, 1, 218, 235, 234];
pub const SELL: [u8; 8] = [51, 230, 133, 164, 1, 127, 131, 173];
pub const BUY_EXACT_SOL_IN: [u8; 8] = [56, 252, 116, 8, 158, 223, 205, 95];
