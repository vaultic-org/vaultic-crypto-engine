// AES module for symmetric encryption operations

// Sub-modules
pub mod aes_gcm;

// Re-export commonly used functions
#[cfg(feature = "wasm")]
pub use self::aes_gcm::{decrypt_with_derived_key, encrypt_with_derived_key};
