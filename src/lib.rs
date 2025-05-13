//! # Vaultic Crypto Engine
//! 
//! A high-performance cryptographic library for secure RSA operations,
//! with support for both native Rust and WebAssembly environments.
//! 
//! This library provides RSA key generation, encryption, and decryption
//! capabilities using industry-standard formats and algorithms.

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use rsa::{
    RsaPrivateKey, RsaPublicKey, Oaep, PublicKey,
    pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, DecodeRsaPrivateKey, DecodeRsaPublicKey}
};
use rand::rngs::OsRng;
use base64::{engine::general_purpose, Engine as _};

// Serde is used for the WASM interface
#[cfg(target_arch = "wasm32")]
use serde::Serialize;
#[cfg(target_arch = "wasm32")]
use serde_json;

/// RSA key pair structure containing both public and private keys in PEM format.
///
/// This structure is returned by the key generation function and can be used
/// for subsequent encryption and decryption operations.
#[derive(serde::Serialize)]
pub struct KeyPair {
    /// The public key in PEM format (PKCS#1)
    pub public_pem: String,
    
    /// The private key in PEM format (PKCS#1)
    pub private_pem: String,
}

/// Generates a new RSA key pair with 2048-bit keys.
///
/// # WebAssembly
/// When compiled for WebAssembly, this function returns a JsValue containing
/// the key pair that can be accessed from JavaScript.
///
/// # Returns
/// Returns a KeyPair struct containing both the public and private keys in PEM format.
///
/// # Examples
/// ```
/// use vaultic_crypto_engine::generate_rsa_keypair_pem;
///
/// let keypair = generate_rsa_keypair_pem();
/// println!("Public key: {}", keypair.public_pem);
/// ```
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn generate_rsa_keypair_pem() -> JsValue {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("key generation failed");
    let public_key = RsaPublicKey::from(&private_key);

    let private_pem = private_key.to_pkcs1_pem(Default::default()).unwrap().to_string();
    let public_pem = public_key.to_pkcs1_pem(Default::default()).unwrap().to_string();

    let keypair = KeyPair {
        public_pem,
        private_pem,
    };

    JsValue::from_serde(&keypair).unwrap()
}

/// Generates a new RSA key pair with 2048-bit keys.
///
/// # Returns
/// Returns a KeyPair struct containing both the public and private keys in PEM format.
///
/// # Examples
/// ```
/// use vaultic_crypto_engine::generate_rsa_keypair_pem;
///
/// let keypair = generate_rsa_keypair_pem();
/// println!("Public key: {}", keypair.public_pem);
/// ```
#[cfg(not(target_arch = "wasm32"))]
pub fn generate_rsa_keypair_pem() -> KeyPair {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("key generation failed");
    let public_key = RsaPublicKey::from(&private_key);

    let private_pem = private_key.to_pkcs1_pem(Default::default()).unwrap().to_string();
    let public_pem = public_key.to_pkcs1_pem(Default::default()).unwrap().to_string();

    KeyPair {
        public_pem,
        private_pem,
    }
}

/// Encrypts plaintext using RSA-OAEP with SHA-256 and returns Base64-encoded ciphertext.
///
/// # Parameters
/// * `public_key_pem` - RSA public key in PEM format
/// * `plaintext` - The text to encrypt
///
/// # Returns
/// Base64-encoded encrypted data
///
/// # Examples
/// ```
/// use vaultic_crypto_engine::{generate_rsa_keypair_pem, rsa_encrypt_base64};
///
/// let keypair = generate_rsa_keypair_pem();
/// let encrypted = rsa_encrypt_base64(&keypair.public_pem, "Secret message");
/// ```
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn rsa_encrypt_base64(public_key_pem: &str, plaintext: &str) -> String {
    rsa_encrypt_base64_impl(public_key_pem, plaintext)
}

/// Encrypts plaintext using RSA-OAEP with SHA-256 and returns Base64-encoded ciphertext.
///
/// # Parameters
/// * `public_key_pem` - RSA public key in PEM format
/// * `plaintext` - The text to encrypt
///
/// # Returns
/// Base64-encoded encrypted data
///
/// # Examples
/// ```
/// use vaultic_crypto_engine::{generate_rsa_keypair_pem, rsa_encrypt_base64};
///
/// let keypair = generate_rsa_keypair_pem();
/// let encrypted = rsa_encrypt_base64(&keypair.public_pem, "Secret message");
/// ```
#[cfg(not(target_arch = "wasm32"))]
pub fn rsa_encrypt_base64(public_key_pem: &str, plaintext: &str) -> String {
    rsa_encrypt_base64_impl(public_key_pem, plaintext)
}

/// Common implementation for RSA encryption, used by both WASM and native targets.
///
/// # Parameters
/// * `public_key_pem` - RSA public key in PEM format
/// * `plaintext` - The text to encrypt
///
/// # Returns
/// Base64-encoded encrypted data
fn rsa_encrypt_base64_impl(public_key_pem: &str, plaintext: &str) -> String {
    // Parse the public key from PEM format
    let public_key = RsaPublicKey::from_pkcs1_pem(public_key_pem).expect("Invalid public key");
    let mut rng = OsRng;

    // Encrypt using RSA-OAEP with SHA-256
    let encrypted_data = public_key.encrypt(
        &mut rng,
        Oaep::new::<sha2::Sha256>(),
        plaintext.as_bytes(),
    ).expect("Encryption failed");

    // Encode the encrypted data in Base64
    general_purpose::STANDARD.encode(encrypted_data)
}

/// Decrypts Base64-encoded ciphertext using RSA-OAEP with SHA-256.
///
/// # Parameters
/// * `private_key_pem` - RSA private key in PEM format
/// * `ciphertext_b64` - Base64-encoded ciphertext to decrypt
///
/// # Returns
/// The decrypted plaintext as a UTF-8 string
///
/// # Examples
/// ```
/// use vaultic_crypto_engine::{generate_rsa_keypair_pem, rsa_encrypt_base64, rsa_decrypt_base64};
///
/// let keypair = generate_rsa_keypair_pem();
/// let encrypted = rsa_encrypt_base64(&keypair.public_pem, "Secret message");
/// let decrypted = rsa_decrypt_base64(&keypair.private_pem, &encrypted);
/// assert_eq!(decrypted, "Secret message");
/// ```
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn rsa_decrypt_base64(private_key_pem: &str, ciphertext_b64: &str) -> String {
    rsa_decrypt_base64_impl(private_key_pem, ciphertext_b64)
}

/// Decrypts Base64-encoded ciphertext using RSA-OAEP with SHA-256.
///
/// # Parameters
/// * `private_key_pem` - RSA private key in PEM format
/// * `ciphertext_b64` - Base64-encoded ciphertext to decrypt
///
/// # Returns
/// The decrypted plaintext as a UTF-8 string
///
/// # Examples
/// ```
/// use vaultic_crypto_engine::{generate_rsa_keypair_pem, rsa_encrypt_base64, rsa_decrypt_base64};
///
/// let keypair = generate_rsa_keypair_pem();
/// let encrypted = rsa_encrypt_base64(&keypair.public_pem, "Secret message");
/// let decrypted = rsa_decrypt_base64(&keypair.private_pem, &encrypted);
/// assert_eq!(decrypted, "Secret message");
/// ```
#[cfg(not(target_arch = "wasm32"))]
pub fn rsa_decrypt_base64(private_key_pem: &str, ciphertext_b64: &str) -> String {
    rsa_decrypt_base64_impl(private_key_pem, ciphertext_b64)
}

/// Common implementation for RSA decryption, used by both WASM and native targets.
///
/// # Parameters
/// * `private_key_pem` - RSA private key in PEM format
/// * `ciphertext_b64` - Base64-encoded ciphertext to decrypt
///
/// # Returns
/// The decrypted plaintext as a UTF-8 string
fn rsa_decrypt_base64_impl(private_key_pem: &str, ciphertext_b64: &str) -> String {
    // Parse the private key from PEM format
    let private_key = RsaPrivateKey::from_pkcs1_pem(private_key_pem).expect("Invalid private key");
    
    // Decode the Base64 ciphertext
    let encrypted_data = general_purpose::STANDARD.decode(ciphertext_b64).expect("Invalid base64");

    // Decrypt using RSA-OAEP with SHA-256
    let decrypted_data = private_key.decrypt(
        Oaep::new::<sha2::Sha256>(),
        &encrypted_data,
    ).expect("Decryption failed");

    // Convert the decrypted bytes to a UTF-8 string
    String::from_utf8(decrypted_data).expect("Invalid UTF-8")
}