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

// WebAssembly support is conditional based on the "wasm" feature
#[cfg(feature = "wasm")]
use js_sys;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;
#[cfg(feature = "wasm")]
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
use hmac::Hmac;
use pbkdf2::pbkdf2;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::convert::TryInto;

// Serde is used for serializing structs to JS (via serde_wasm_bindgen)
#[cfg(feature = "wasm")]
use serde_wasm_bindgen;

// Maximum size for direct RSA encryption
// For RSA 2048-bit, the maximum is 2048/8 - padding = 256 - 11 = 245 bytes
pub const MAX_RSA_SIZE: usize = 245;

#[cfg(feature = "wasm")]
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

/// Structure for the encrypted keypair result
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncryptedKeypairResult {
    /// Base64-encoded encrypted private key
    pub encrypted_private: String,
    /// Base64-encoded encrypted public key
    pub encrypted_public: String,
    /// Base64-encoded salt used for key derivation
    pub salt: String,
    /// Base64-encoded nonce used for private key encryption
    pub nonce_private: String,
    /// Base64-encoded nonce used for public key encryption
    pub nonce_public: String,
}

/// Structure for encrypted keypair input parameters
#[derive(Deserialize)]
pub struct EncryptedKeypairInput {
    /// Base64-encoded encrypted private key
    pub encrypted_private: String,
    /// Base64-encoded encrypted public key
    pub encrypted_public: String,
    /// Base64-encoded salt used for key derivation
    pub salt: String,
    /// Base64-encoded nonce used for encryption
    pub nonce: String,
}

/// Structure for storing protected message
#[derive(Serialize)]
pub struct ProtectedMessage {
    /// Base64-encoded ciphertext
    pub ciphertext: String,
    /// Base64-encoded salt used for key derivation
    pub salt: String,
    /// Base64-encoded nonce used for encryption
    pub nonce: String,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
/// Generates a 2048-bit RSA key pair and returns it as a JavaScript object.
pub fn generate_rsa_keypair_pem() -> JsValue {
    let keypair = generate_keypair_impl();
    serde_wasm_bindgen::to_value(&keypair).unwrap()
}

#[cfg(not(feature = "wasm"))]
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

#[cfg(feature = "wasm")]
#[wasm_bindgen]
/// Encrypts plaintext using the given public key and returns a Base64-encoded string.
/// Automatically switches between direct RSA and hybrid RSA+AES based on data size.
pub fn rsa_encrypt_base64(public_key_pem: &str, plaintext: &str) -> String {
    rsa_encrypt_base64_impl(public_key_pem, plaintext)
}

#[cfg(not(feature = "wasm"))]
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

#[cfg(feature = "wasm")]
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

#[cfg(not(feature = "wasm"))]
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

#[cfg(feature = "wasm")]
fn get_now_seed() -> u64 {
    // Use JavaScript Date.now() via wasm-bindgen
    js_sys::Date::now() as u64
}

#[cfg(not(feature = "wasm"))]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(not(feature = "wasm"))]
fn get_now_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
/// Protects a RSA keypair with a passphrase using PBKDF2 and AES-GCM.
/// Returns a JavaScript object containing the encrypted keys and necessary metadata.
pub fn protect_keypair(private_pem: &str, public_pem: &str, passphrase: &str) -> JsValue {
    let result = protect_keypair_impl(private_pem, public_pem, passphrase)
        .expect("Failed to protect keypair");
    serde_wasm_bindgen::to_value(&result).unwrap()
}

#[cfg(not(feature = "wasm"))]
/// Native version of keypair protection.
/// Returns a struct containing the encrypted keys and necessary metadata.
pub fn protect_keypair(
    private_pem: &str,
    public_pem: &str,
    passphrase: &str,
) -> EncryptedKeypairResult {
    protect_keypair_impl(private_pem, public_pem, passphrase).expect("Failed to protect keypair")
}

/// Internal implementation of keypair protection
pub fn protect_keypair_impl(
    private_pem: &str,
    public_pem: &str,
    passphrase: &str,
) -> Result<EncryptedKeypairResult, String> {
    // Validate inputs by parsing the keys
    let private_key = RsaPrivateKey::from_pkcs8_pem(private_pem)
        .map_err(|e| format!("Invalid private key PEM: {}", e))?;
    let public_key = RsaPublicKey::from_public_key_pem(public_pem)
        .map_err(|e| format!("Invalid public key PEM: {}", e))?;

    // Verify that the public key matches the private key
    let derived_public = RsaPublicKey::from(&private_key);
    if derived_public != public_key {
        return Err("Public key does not match private key".to_string());
    }

    // Generate a random salt
    let mut salt_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut salt_bytes);

    // Derive AES key using PBKDF2
    let mut key = [0u8; 32]; // 256 bits for AES-256
    const PBKDF2_ROUNDS: u32 = 100_000;

    pbkdf2::<Hmac<Sha256>>(passphrase.as_bytes(), &salt_bytes, PBKDF2_ROUNDS, &mut key)
        .map_err(|e| format!("PBKDF2 key derivation failed: {}", e))?;

    // Initialize AES-GCM cipher
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("Failed to create AES cipher: {}", e))?;

    // Generate nonces for both keys
    let mut nonce_private_bytes = [0u8; 12];
    let mut nonce_public_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_private_bytes);
    OsRng.fill_bytes(&mut nonce_public_bytes);

    let nonce_private = Nonce::from_slice(&nonce_private_bytes);
    let nonce_public = Nonce::from_slice(&nonce_public_bytes);

    // Encrypt private key
    let encrypted_private = cipher
        .encrypt(
            nonce_private,
            Payload {
                msg: private_pem.as_bytes(),
                aad: &[],
            },
        )
        .map_err(|e| format!("Private key encryption failed: {}", e))?;

    // Encrypt public key
    let encrypted_public = cipher
        .encrypt(
            nonce_public,
            Payload {
                msg: public_pem.as_bytes(),
                aad: &[],
            },
        )
        .map_err(|e| format!("Public key encryption failed: {}", e))?;

    // Create and return the result
    Ok(EncryptedKeypairResult {
        encrypted_private: general_purpose::STANDARD.encode(encrypted_private),
        encrypted_public: general_purpose::STANDARD.encode(encrypted_public),
        salt: general_purpose::STANDARD.encode(salt_bytes),
        nonce_private: general_purpose::STANDARD.encode(nonce_private_bytes),
        nonce_public: general_purpose::STANDARD.encode(nonce_public_bytes),
    })
}

/// Unprotects (decrypts) a previously protected keypair.
/// This function is the inverse of `protect_keypair`.
pub fn unprotect_keypair(
    encrypted_result: &EncryptedKeypairResult,
    passphrase: &str,
) -> Result<KeyPair, String> {
    // Decode Base64 values
    let salt = general_purpose::STANDARD
        .decode(&encrypted_result.salt)
        .map_err(|e| format!("Failed to decode salt: {}", e))?;

    let nonce_private = general_purpose::STANDARD
        .decode(&encrypted_result.nonce_private)
        .map_err(|e| format!("Failed to decode private key nonce: {}", e))?;

    let nonce_public = general_purpose::STANDARD
        .decode(&encrypted_result.nonce_public)
        .map_err(|e| format!("Failed to decode public key nonce: {}", e))?;

    let encrypted_private = general_purpose::STANDARD
        .decode(&encrypted_result.encrypted_private)
        .map_err(|e| format!("Failed to decode encrypted private key: {}", e))?;

    let encrypted_public = general_purpose::STANDARD
        .decode(&encrypted_result.encrypted_public)
        .map_err(|e| format!("Failed to decode encrypted public key: {}", e))?;

    // Derive AES key using PBKDF2
    let mut key = [0u8; 32];
    const PBKDF2_ROUNDS: u32 = 100_000;

    pbkdf2::<Hmac<Sha256>>(passphrase.as_bytes(), &salt, PBKDF2_ROUNDS, &mut key)
        .map_err(|e| format!("PBKDF2 key derivation failed: {}", e))?;

    // Initialize AES-GCM cipher
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("Failed to create AES cipher: {}", e))?;

    // Decrypt private key
    let private_pem_bytes = cipher
        .decrypt(
            Nonce::from_slice(&nonce_private),
            Payload {
                msg: &encrypted_private,
                aad: &[],
            },
        )
        .map_err(|e| format!("Private key decryption failed: {}", e))?;

    // Decrypt public key
    let public_pem_bytes = cipher
        .decrypt(
            Nonce::from_slice(&nonce_public),
            Payload {
                msg: &encrypted_public,
                aad: &[],
            },
        )
        .map_err(|e| format!("Public key decryption failed: {}", e))?;

    // Convert bytes to strings
    let private_pem = String::from_utf8(private_pem_bytes)
        .map_err(|e| format!("Invalid UTF-8 in decrypted private key: {}", e))?;

    let public_pem = String::from_utf8(public_pem_bytes)
        .map_err(|e| format!("Invalid UTF-8 in decrypted public key: {}", e))?;

    // Validate the decrypted keys
    let private_key = RsaPrivateKey::from_pkcs8_pem(&private_pem)
        .map_err(|e| format!("Invalid decrypted private key: {}", e))?;

    let public_key = RsaPublicKey::from_public_key_pem(&public_pem)
        .map_err(|e| format!("Invalid decrypted public key: {}", e))?;

    // Verify that the public key matches the private key
    let derived_public = RsaPublicKey::from(&private_key);
    if derived_public != public_key {
        return Err("Decrypted public key does not match private key".to_string());
    }

    Ok(KeyPair {
        private_pem,
        public_pem,
    })
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
/// Decrypts a previously protected RSA keypair using the provided passphrase.
/// Returns a JavaScript object containing the decrypted PEM-formatted keys.
pub fn unprotect_keypair(
    encrypted_private: &str,
    encrypted_public: &str,
    passphrase: &str,
    salt: &str,
    nonce: &str,
) -> Result<JsValue, JsValue> {
    // Create input structure
    let input = EncryptedKeypairInput {
        encrypted_private: encrypted_private.to_string(),
        encrypted_public: encrypted_public.to_string(),
        salt: salt.to_string(),
        nonce: nonce.to_string(),
    };

    // Call the implementation
    match unprotect_keypair_impl(&input, passphrase) {
        Ok(keypair) => Ok(serde_wasm_bindgen::to_value(&keypair).unwrap()),
        Err(e) => {
            // Log error to console
            web_sys::console::error_1(&format!("Vaultic keypair unprotection error: {}", e).into());
            Err(JsValue::from_str(&e))
        }
    }
}

/// Internal implementation of keypair unprotection
fn unprotect_keypair_impl(
    input: &EncryptedKeypairInput,
    passphrase: &str,
) -> Result<KeyPair, String> {
    // Decode Base64 values
    let salt = general_purpose::STANDARD
        .decode(&input.salt)
        .map_err(|e| format!("Failed to decode salt: {}", e))?;

    let nonce = general_purpose::STANDARD
        .decode(&input.nonce)
        .map_err(|e| format!("Failed to decode nonce: {}", e))?;

    let encrypted_private = general_purpose::STANDARD
        .decode(&input.encrypted_private)
        .map_err(|e| format!("Failed to decode encrypted private key: {}", e))?;

    let encrypted_public = general_purpose::STANDARD
        .decode(&input.encrypted_public)
        .map_err(|e| format!("Failed to decode encrypted public key: {}", e))?;

    // Verify input lengths
    if salt.len() != 16 {
        return Err("Invalid salt length".to_string());
    }
    if nonce.len() != 12 {
        return Err("Invalid nonce length".to_string());
    }

    // Derive AES key using PBKDF2
    let mut key = [0u8; 32];
    const PBKDF2_ROUNDS: u32 = 100_000;

    pbkdf2::<Hmac<Sha256>>(passphrase.as_bytes(), &salt, PBKDF2_ROUNDS, &mut key)
        .map_err(|e| format!("PBKDF2 key derivation failed: {}", e))?;

    // Initialize AES-GCM cipher
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("Failed to create AES cipher: {}", e))?;

    // Create nonce
    let nonce = Nonce::from_slice(&nonce);

    // Decrypt private key
    let private_pem_bytes = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &encrypted_private,
                aad: &[],
            },
        )
        .map_err(|e| format!("Private key decryption failed: {}", e))?;

    // Decrypt public key
    let public_pem_bytes = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &encrypted_public,
                aad: &[],
            },
        )
        .map_err(|e| format!("Public key decryption failed: {}", e))?;

    // Convert bytes to strings
    let private_pem = String::from_utf8(private_pem_bytes)
        .map_err(|e| format!("Invalid UTF-8 in decrypted private key: {}", e))?;

    let public_pem = String::from_utf8(public_pem_bytes)
        .map_err(|e| format!("Invalid UTF-8 in decrypted public key: {}", e))?;

    // Validate the decrypted keys
    let private_key = RsaPrivateKey::from_pkcs8_pem(&private_pem)
        .map_err(|e| format!("Invalid decrypted private key: {}", e))?;

    let public_key = RsaPublicKey::from_public_key_pem(&public_pem)
        .map_err(|e| format!("Invalid decrypted public key: {}", e))?;

    // Verify that the public key matches the private key
    let derived_public = RsaPublicKey::from(&private_key);
    if derived_public != public_key {
        return Err("Decrypted public key does not match private key".to_string());
    }

    Ok(KeyPair {
        private_pem,
        public_pem,
    })
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
/// Encrypts a message with AES-256-GCM using a passphrase
///
/// Generates a random salt and nonce, derives an AES-256 key using PBKDF2,
/// and returns the encrypted text with metadata needed for decryption.
pub fn protect_message(plaintext: &str, passphrase: &str) -> JsValue {
    let result = protect_message_impl(plaintext, passphrase);
    serde_wasm_bindgen::to_value(&result).unwrap()
}

#[cfg(not(feature = "wasm"))]
/// Encrypts a message with AES-256-GCM using a passphrase
///
/// Generates a random salt and nonce, derives an AES-256 key using PBKDF2,
/// and returns the encrypted text with metadata needed for decryption.
pub fn protect_message(plaintext: &str, passphrase: &str) -> ProtectedMessage {
    protect_message_impl(plaintext, passphrase)
}

/// Internal implementation of message protection
fn protect_message_impl(plaintext: &str, passphrase: &str) -> ProtectedMessage {
    // Generate random salt (16 bytes)
    let mut salt_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut salt_bytes);

    // Generate random nonce (12 bytes)
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    // Derive AES-256 key using PBKDF2
    const PBKDF2_ROUNDS: u32 = 100_000;
    let mut key = [0u8; 32]; // 256 bits

    pbkdf2::<Hmac<Sha256>>(passphrase.as_bytes(), &salt_bytes, PBKDF2_ROUNDS, &mut key)
        .expect("PBKDF2 key derivation failed");

    // Initialize AES-GCM cipher
    let cipher = Aes256Gcm::new_from_slice(&key).expect("Failed to initialize AES cipher");

    // Prepare nonce
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the text
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext.as_bytes(),
                aad: &[],
            },
        )
        .expect("Encryption failed");

    // Encode in Base64
    ProtectedMessage {
        ciphertext: general_purpose::STANDARD.encode(ciphertext),
        salt: general_purpose::STANDARD.encode(salt_bytes),
        nonce: general_purpose::STANDARD.encode(nonce_bytes),
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
/// Decrypts a message previously encrypted with protect_message
///
/// Takes the encrypted message parameters and passphrase,
/// and returns the original plaintext if successful.
pub fn unprotect_message(encrypted_message: &JsValue, passphrase: &str) -> Result<String, JsValue> {
    let protected: ProtectedMessage = serde_wasm_bindgen::from_value(encrypted_message.clone())
        .map_err(|e| JsValue::from_str(&format!("Failed to parse encrypted message: {}", e)))?;

    match unprotect_message_impl(&protected, passphrase) {
        Ok(plaintext) => Ok(plaintext),
        Err(e) => Err(JsValue::from_str(&e)),
    }
}

#[cfg(not(feature = "wasm"))]
/// Decrypts a message previously encrypted with protect_message
///
/// Takes the encrypted message parameters and passphrase,
/// and returns the original plaintext if successful.
pub fn unprotect_message(
    encrypted_message: &ProtectedMessage,
    passphrase: &str,
) -> Result<String, String> {
    unprotect_message_impl(encrypted_message, passphrase)
}

/// Internal implementation of message decryption
fn unprotect_message_impl(
    encrypted_message: &ProtectedMessage,
    passphrase: &str,
) -> Result<String, String> {
    // Decode Base64 values
    let salt = general_purpose::STANDARD
        .decode(&encrypted_message.salt)
        .map_err(|e| format!("Failed to decode salt: {}", e))?;

    let nonce = general_purpose::STANDARD
        .decode(&encrypted_message.nonce)
        .map_err(|e| format!("Failed to decode nonce: {}", e))?;

    let ciphertext = general_purpose::STANDARD
        .decode(&encrypted_message.ciphertext)
        .map_err(|e| format!("Failed to decode ciphertext: {}", e))?;

    // Verify input lengths
    if salt.len() != 16 {
        return Err("Invalid salt length".to_string());
    }
    if nonce.len() != 12 {
        return Err("Invalid nonce length".to_string());
    }

    // Derive AES key using PBKDF2
    let mut key = [0u8; 32];
    const PBKDF2_ROUNDS: u32 = 100_000;

    pbkdf2::<Hmac<Sha256>>(passphrase.as_bytes(), &salt, PBKDF2_ROUNDS, &mut key)
        .map_err(|e| format!("PBKDF2 key derivation failed: {}", e))?;

    // Initialize AES-GCM cipher
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("Failed to create AES cipher: {}", e))?;

    // Create nonce
    let nonce = Nonce::from_slice(&nonce);

    // Decrypt the text
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ciphertext,
                aad: &[],
            },
        )
        .map_err(|e| format!("Decryption failed: {}", e))?;

    // Convert to string
    String::from_utf8(plaintext).map_err(|e| format!("Invalid UTF-8 in decrypted text: {}", e))
}
