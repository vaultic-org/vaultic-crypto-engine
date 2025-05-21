//! # Vaultic Crypto Engine
//!
//! A high-performance cryptographic library for secure RSA and ECC operations,
//! with support for both native Rust and WebAssembly environments.
//!
//! This library provides:
//! - RSA key generation, encryption, and decryption using PKCS#1 v1.5 padding
//! - ECDSA signature generation and verification
//! - ECDH key agreement for shared secrets
//! - AES-GCM encryption with keys derived from shared secrets or passphrases
//! - Key derivation functions (PBKDF2, HKDF)
//!
//! ## Security Considerations
//!
//! This library uses pure Rust implementations of cryptographic algorithms.
//! The RSA implementation is vulnerable to timing side-channel attacks
//! (Marvin Attack - RUSTSEC-2023-0071). To mitigate this:
//!
//! 1. Random delays are added during decryption operations
//! 2. Stronger blinding factors are applied
//! 3. Use is recommended in non-networked or low-risk environments only
//! 4. Consider using ECC-based cryptography when possible

// Module declarations
mod crypto;
pub mod models;
mod utils;

// Re-exports from top-level module for easy access

// RSA-related exports
pub use crypto::{
    MAX_RSA_SIZE, direct_rsa_decrypt, direct_rsa_encrypt_base64, generate_keypair_impl,
    generate_rsa_keypair_pem, hybrid_rsa_aes_decrypt, hybrid_rsa_aes_encrypt_base64,
    protect_keypair, protect_keypair_impl, protect_message, protect_message_impl,
    rsa_decrypt_base64, rsa_decrypt_base64_impl, rsa_encrypt_base64, rsa_encrypt_base64_impl,
    unprotect_keypair, unprotect_keypair_impl, unprotect_message, unprotect_message_impl,
};

// ECC-related exports
pub use crypto::{derive_shared_secret, ecdsa_sign, ecdsa_verify, generate_ecdsa_keypair};

// AES and key derivation exports
pub use crypto::{
    decrypt_aes_gcm, decrypt_with_derived_key, derive_key_hkdf, derive_key_pbkdf2, encrypt_aes_gcm,
    encrypt_with_derived_key,
};

#[cfg(feature = "wasm")]
pub use crypto::{unprotect_keypair_raw, unprotect_message_obj};

// Model exports
pub use models::{
    EccCurve, EccKeyPair, EccSignature, EncryptedKeypairInput, EncryptedKeypairResult,
    HybridEncryptedData, KeyPair, ProtectedMessage, SharedSecret,
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
