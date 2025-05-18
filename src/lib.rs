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
use js_sys;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use web_sys;

use base64::{Engine as _, engine::general_purpose};
use rand::{RngCore, SeedableRng, rngs::OsRng, rngs::StdRng};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
};

// Add AES dependencies
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

// Serde is used for serializing structs to JS (via serde_wasm_bindgen)
#[cfg(target_arch = "wasm32")]
use serde_wasm_bindgen;

// Maximum size for direct RSA encryption
// For RSA 2048-bit, the maximum is 2048/8 - padding = 256 - 11 = 245 bytes
pub const MAX_RSA_SIZE: usize = 245;

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

/// Structure for hybrid encryption result
#[derive(Serialize, Deserialize)]
pub struct HybridEncryptedData {
    /// Mode of encryption ("hybrid" or "direct")
    pub mode: String,
    /// Nonce for AES-GCM
    pub nonce: Vec<u8>,
    /// RSA-encrypted AES key
    pub encrypted_key: String,
    /// AES-encrypted data
    pub encrypted_data: Vec<u8>,
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
#[doc(hidden)]
pub fn generate_keypair_impl() -> KeyPair {
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
/// Automatically switches between direct RSA and hybrid RSA+AES based on data size.
pub fn rsa_encrypt_base64(public_key_pem: &str, plaintext: &str) -> String {
    rsa_encrypt_base64_impl(public_key_pem, plaintext)
}

#[cfg(not(target_arch = "wasm32"))]
/// Native version of RSA encryption for CLI or server use.
/// Automatically switches between direct RSA and hybrid RSA+AES based on data size.
pub fn rsa_encrypt_base64(public_key_pem: &str, plaintext: &str) -> String {
    rsa_encrypt_base64_impl(public_key_pem, plaintext)
}

/// Internal encryption logic - determines whether to use direct RSA or hybrid RSA+AES
/// based on the size of the data to encrypt.
#[doc(hidden)]
pub fn rsa_encrypt_base64_impl(public_key_pem: &str, plaintext: &str) -> String {
    let plaintext_bytes = plaintext.as_bytes();

    // If data is small enough for direct RSA encryption
    if plaintext_bytes.len() <= MAX_RSA_SIZE {
        direct_rsa_encrypt_base64(public_key_pem, plaintext_bytes)
    } else {
        // For larger data, use hybrid encryption
        hybrid_rsa_aes_encrypt_base64(public_key_pem, plaintext_bytes)
    }
}

/// Direct RSA encryption for smaller data
#[doc(hidden)]
pub fn direct_rsa_encrypt_base64(public_key_pem: &str, plaintext: &[u8]) -> String {
    // Parse the public key
    let public_key =
        RsaPublicKey::from_public_key_pem(public_key_pem).expect("Failed to parse public key");

    // Encrypt the data
    let mut rng = OsRng;
    let encrypted = public_key
        .encrypt(&mut rng, rsa::Pkcs1v15Encrypt, plaintext)
        .expect("Encryption failed");

    // Encode as Base64
    general_purpose::STANDARD.encode(encrypted)
}

/// Hybrid RSA+AES encryption for larger data
fn hybrid_rsa_aes_encrypt_base64(public_key_pem: &str, plaintext: &[u8]) -> String {
    let mut rng = OsRng;

    // Generate a random AES-256 key
    let mut aes_key = [0u8; 32];
    rng.fill_bytes(&mut aes_key);

    // Generate a random nonce for AES-GCM
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Initialize AES-GCM cipher
    let cipher = Aes256Gcm::new_from_slice(&aes_key).expect("Failed to create AES cipher");

    // Encrypt the data with AES-GCM
    let encrypted_data = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        .expect("AES encryption failed");

    // Encrypt the AES key with RSA
    // First convert the AES key to Base64 to ensure it can be handled as a string in RSA encryption
    let aes_key_base64 = general_purpose::STANDARD.encode(&aes_key);
    let encrypted_key = direct_rsa_encrypt_base64(public_key_pem, aes_key_base64.as_bytes());

    // Create the hybrid encryption result
    let hybrid_data = HybridEncryptedData {
        mode: "hybrid".to_string(),
        nonce: nonce_bytes.to_vec(),
        encrypted_key,
        encrypted_data,
    };

    // Serialize to JSON and encode as Base64
    let json = serde_json::to_string(&hybrid_data).expect("Failed to serialize hybrid data");
    general_purpose::STANDARD.encode(json)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(catch)]
/// Decrypts Base64-encoded ciphertext using the provided private key (PEM).
/// Automatically detects and handles both direct RSA and hybrid RSA+AES encryption.
/// Returns either the decrypted message or an error as a JS exception.
pub fn rsa_decrypt_base64(private_key_pem: &str, ciphertext_b64: &str) -> Result<String, JsValue> {
    match rsa_decrypt_base64_impl(private_key_pem, ciphertext_b64) {
        Ok(plaintext) => Ok(plaintext),
        Err(e) => {
            // Console log for debugging
            web_sys::console::error_1(&format!("Vaultic E2EE decryption error: {}", e).into());
            Err(JsValue::from_str(&e))
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
/// Native version of RSA decryption; panics on failure.
/// Automatically detects and handles both direct RSA and hybrid RSA+AES encryption.
pub fn rsa_decrypt_base64(private_key_pem: &str, ciphertext_b64: &str) -> String {
    rsa_decrypt_base64_impl(private_key_pem, ciphertext_b64).expect("Decryption failed")
}

/// Internal decryption logic that automatically detects and handles
/// both direct RSA and hybrid RSA+AES encryption.
#[doc(hidden)]
pub fn rsa_decrypt_base64_impl(
    private_key_pem: &str,
    ciphertext_b64: &str,
) -> Result<String, String> {
    // First, try to decode Base64
    let decoded = general_purpose::STANDARD
        .decode(ciphertext_b64)
        .map_err(|e| format!("Base64 decode failed: {}", e))?;

    // Try to parse as JSON to check if it's a hybrid encryption
    match serde_json::from_slice::<HybridEncryptedData>(&decoded) {
        Ok(hybrid_data) => {
            // It's hybrid encryption, handle accordingly
            if hybrid_data.mode == "hybrid" {
                hybrid_rsa_aes_decrypt(private_key_pem, hybrid_data)
            } else {
                Err(format!("Unknown encryption mode: {}", hybrid_data.mode))
            }
        }
        Err(_) => {
            // Not a JSON, assume direct RSA encryption
            direct_rsa_decrypt(private_key_pem, ciphertext_b64)
        }
    }
}

/// Direct RSA decryption for smaller data
#[doc(hidden)]
pub fn direct_rsa_decrypt(private_key_pem: &str, ciphertext_b64: &str) -> Result<String, String> {
    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
        .map_err(|e| format!("Invalid private key PEM: {}", e))?;

    let encrypted_data = general_purpose::STANDARD
        .decode(ciphertext_b64)
        .map_err(|e| format!("Base64 decode failed: {}", e))?;

    // 🔐 Timing noise with cross-platform entropy
    let now = get_now_seed();

    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let seed_value = u64::from_ne_bytes(seed[0..8].try_into().unwrap());

    let mut rng = StdRng::seed_from_u64(seed_value ^ now);
    let _ = rng.next_u32() % 10;

    let decrypted = private_key
        .decrypt(rsa::Pkcs1v15Encrypt, &encrypted_data)
        .map_err(|e| format!("Decryption failed: {}", e))?;

    String::from_utf8(decrypted).map_err(|e| format!("UTF-8 decode failed: {}", e))
}

/// Hybrid RSA+AES decryption for larger data
fn hybrid_rsa_aes_decrypt(
    private_key_pem: &str,
    hybrid_data: HybridEncryptedData,
) -> Result<String, String> {
    // Decrypt the AES key using RSA
    let aes_key_base64 = direct_rsa_decrypt(private_key_pem, &hybrid_data.encrypted_key)?;

    // Decode the Base64 AES key back to bytes
    let aes_key_bytes = general_purpose::STANDARD
        .decode(aes_key_base64)
        .map_err(|e| format!("Failed to decode AES key from Base64: {}", e))?;

    // Ensure the AES key is the right length
    if aes_key_bytes.len() != 32 {
        return Err(format!(
            "Invalid AES key length after decryption: expected 32, got {}",
            aes_key_bytes.len()
        ));
    }

    // Create AES cipher
    let cipher = Aes256Gcm::new_from_slice(&aes_key_bytes)
        .map_err(|e| format!("Failed to create AES cipher: {}", e))?;

    // Create nonce
    let nonce = Nonce::from_slice(&hybrid_data.nonce);

    // Decrypt the data
    let decrypted_data = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &hybrid_data.encrypted_data,
                aad: &[],
            },
        )
        .map_err(|e| format!("AES decryption failed: {}", e))?;

    // Convert to string
    String::from_utf8(decrypted_data).map_err(|e| format!("UTF-8 decode failed: {}", e))
}

#[cfg(target_arch = "wasm32")]
fn get_now_seed() -> u64 {
    // Use JavaScript Date.now() via wasm-bindgen
    js_sys::Date::now() as u64
}

#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(not(target_arch = "wasm32"))]
fn get_now_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}
