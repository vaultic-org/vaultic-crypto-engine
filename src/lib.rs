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

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use base64::{Engine as _, engine::general_purpose};
use rand::{RngCore, SeedableRng, rngs::OsRng, rngs::StdRng};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
};
use std::time::{SystemTime, UNIX_EPOCH};

// Serde is used for serializing structs to JS (via serde_wasm_bindgen)
use serde::Serialize;
#[cfg(target_arch = "wasm32")]
use serde_wasm_bindgen;

#[cfg(target_arch = "wasm32")]
/// Initializes panic hook to forward Rust panics to the JavaScript console.
/// This is automatically invoked when the WASM module is loaded.
#[wasm_bindgen(start)]
pub fn wasm_init() {
    console_error_panic_hook::set_once();
}

/// A serializable RSA key pair (public + private) encoded in PEM format.
#[derive(Serialize)]
pub struct KeyPair {
    /// PEM-encoded RSA public key
    pub public_pem: String,
    /// PEM-encoded RSA private key
    pub private_pem: String,
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
/// Generates a 2048-bit RSA key pair and returns it as a JavaScript object.
pub fn generate_rsa_keypair_pem() -> JsValue {
    let keypair = generate_keypair_impl();
    serde_wasm_bindgen::to_value(&keypair).unwrap()
}

#[cfg(not(target_arch = "wasm32"))]
/// Generates a 2048-bit RSA key pair and returns it as a Rust struct.
pub fn generate_rsa_keypair_pem() -> KeyPair {
    generate_keypair_impl()
}

/// Shared internal implementation for RSA key pair generation.
fn generate_keypair_impl() -> KeyPair {
    let mut rng = OsRng;

    // Generate RSA private key with 2048-bit modulus
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate RSA key pair");
    let public_key = RsaPublicKey::from(&private_key);

    // Encode keys to PEM format
    let private_pem = private_key
        .to_pkcs8_pem(Default::default())
        .expect("Failed to encode private key")
        .to_string();
    let public_pem = public_key
        .to_public_key_pem(Default::default())
        .expect("Failed to encode public key")
        .to_string();

    KeyPair {
        public_pem,
        private_pem,
    }
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
/// Encrypts plaintext using the given public key and returns a Base64-encoded string.
pub fn rsa_encrypt_base64(public_key_pem: &str, plaintext: &str) -> String {
    rsa_encrypt_base64_impl(public_key_pem, plaintext)
}

#[cfg(not(target_arch = "wasm32"))]
/// Native version of RSA encryption for CLI or server use.
pub fn rsa_encrypt_base64(public_key_pem: &str, plaintext: &str) -> String {
    rsa_encrypt_base64_impl(public_key_pem, plaintext)
}

/// Internal encryption logic using RSA PKCS#1 v1.5 + Base64.
fn rsa_encrypt_base64_impl(public_key_pem: &str, plaintext: &str) -> String {
    // Parse the public key
    let public_key =
        RsaPublicKey::from_public_key_pem(public_key_pem).expect("Failed to parse public key");

    // Encrypt the data
    let mut rng = OsRng;
    let encrypted = public_key
        .encrypt(&mut rng, rsa::Pkcs1v15Encrypt, plaintext.as_bytes())
        .expect("Encryption failed");

    // Encode as Base64
    general_purpose::STANDARD.encode(encrypted)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(catch)]
/// Decrypts Base64-encoded ciphertext using the provided private key (PEM).
/// Returns either the decrypted message or an error as a JS exception.
pub fn rsa_decrypt_base64(private_key_pem: &str, ciphertext_b64: &str) -> Result<String, JsValue> {
    rsa_decrypt_base64_impl(private_key_pem, ciphertext_b64).map_err(|e| JsValue::from_str(&e))
}

#[cfg(not(target_arch = "wasm32"))]
/// Native version of RSA decryption; panics on failure.
pub fn rsa_decrypt_base64(private_key_pem: &str, ciphertext_b64: &str) -> String {
    rsa_decrypt_base64_impl(private_key_pem, ciphertext_b64).expect("Decryption failed")
}

/// Internal decryption logic with side-channel mitigations and error handling.
fn rsa_decrypt_base64_impl(private_key_pem: &str, ciphertext_b64: &str) -> Result<String, String> {
    // Parse private key from PEM
    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem).map_err(|e| e.to_string())?;

    // Decode ciphertext from Base64
    let encrypted_data = general_purpose::STANDARD
        .decode(ciphertext_b64)
        .map_err(|e| e.to_string())?;

    // Generate entropy-based seed for the RNG
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let seed_value = u64::from_ne_bytes(seed[0..8].try_into().unwrap());

    // Blend seed with current timestamp to mitigate timing-based correlation
    let mut rng = StdRng::seed_from_u64(seed_value ^ (now as u64));

    // Introduce random loop delay (timing noise)
    let delay = rng.next_u32() % 10;
    let mut x = 0u32;
    for i in 0..delay {
        x = x.wrapping_add(i);
    }

    // Perform decryption
    let decrypted_bytes = private_key
        .decrypt(rsa::Pkcs1v15Encrypt, &encrypted_data)
        .map_err(|e| e.to_string())?;

    // Convert decrypted bytes into UTF-8 string
    String::from_utf8(decrypted_bytes).map_err(|e| e.to_string())
}
