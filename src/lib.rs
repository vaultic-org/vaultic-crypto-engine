//! # Vaultic Crypto Engine
//!
//! A high-performance cryptographic library for secure RSA operations,
//! with support for both native Rust and WebAssembly environments.
//!
//! This library provides RSA key generation, encryption, and decryption
//! using PKCS#1 v1.5 padding and Base64 encoding.
//!
//! ## Security Considerations
//!
//! This library uses a pure Rust implementation of RSA that is vulnerable
//! to timing side-channel attacks (Marvin Attack - RUSTSEC-2023-0071).
//! To mitigate this:
//!
//! 1. Random delays are added during decryption operations
//! 2. Stronger blinding factors are applied
//! 3. Use is recommended in non-networked or low-risk environments only

// Module declarations
mod crypto;
pub mod models;
mod utils;

// Re-exports from top-level module for easy access
pub use crypto::{
    MAX_RSA_SIZE, direct_rsa_decrypt, direct_rsa_encrypt_base64, generate_keypair_impl,
    generate_rsa_keypair_pem, hybrid_rsa_aes_decrypt, hybrid_rsa_aes_encrypt_base64,
    protect_keypair, protect_keypair_impl, protect_message, protect_message_impl,
    rsa_decrypt_base64, rsa_decrypt_base64_impl, rsa_encrypt_base64, rsa_encrypt_base64_impl,
    unprotect_keypair, unprotect_keypair_impl, unprotect_message, unprotect_message_impl,
};

#[cfg(feature = "wasm")]
pub use crypto::{unprotect_keypair_raw, unprotect_message_obj};

pub use models::{
    EncryptedKeypairInput, EncryptedKeypairResult, HybridEncryptedData, KeyPair, ProtectedMessage,
};

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
/// Initializes panic hook to forward Rust panics to the JavaScript console.
/// This is automatically invoked when the WASM module is loaded.
#[wasm_bindgen(start)]
pub fn wasm_init() {
    console_error_panic_hook::set_once();
}
