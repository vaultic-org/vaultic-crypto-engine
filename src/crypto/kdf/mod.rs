// KDF module for key derivation functions

// Sub-modules
pub mod hkdf;
pub mod pbkdf2;

// Re-export commonly used functions
pub use pbkdf2::{PBKDF2_DEFAULT_ITERATIONS, derive_key_pbkdf2};

// Re-export derive_key_from_shared_secret from hkdf.rs
// pub use hkdf::derive_key_from_shared_secret; // This line is removed
