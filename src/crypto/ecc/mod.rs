// ECC module for elliptic curve cryptography operations

// Sub-modules
pub mod ecdh;
pub mod ecdsa;

// Re-export commonly used functions
pub use ecdsa::{ecdsa_sign, ecdsa_verify, generate_ecdsa_keypair};

pub use ecdh::derive_shared_secret;
