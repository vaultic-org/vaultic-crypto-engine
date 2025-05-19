use crate::models::{EncryptedKeypairInput, EncryptedKeypairResult, KeyPair};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine as _, engine::general_purpose};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::{RngCore, rngs::OsRng};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
};
use sha2::Sha256;

#[cfg(feature = "wasm")]
use serde_wasm_bindgen;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;
#[cfg(feature = "wasm")]
use web_sys;

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

#[cfg(feature = "wasm")]
#[wasm_bindgen]
/// Unprotects (decrypts) a previously protected keypair.
/// Takes a JavaScript object containing the encrypted keypair result and passphrase.
/// Returns a JavaScript object containing the decrypted PEM-formatted keys.
pub fn unprotect_keypair(encrypted_result: &JsValue, passphrase: &str) -> Result<JsValue, JsValue> {
    // Parse the JavaScript object to our Rust structure
    let result: EncryptedKeypairResult =
        serde_wasm_bindgen::from_value(encrypted_result.clone())
            .map_err(|e| JsValue::from_str(&format!("Failed to parse encrypted result: {}", e)))?;

    // Call the implementation directly to avoid conflict with the function name
    let result =
        unprotect_keypair_internal(&result, passphrase).map_err(|e| JsValue::from_str(&e))?;

    Ok(serde_wasm_bindgen::to_value(&result).unwrap())
}

/// Non-public helper function to avoid name conflicts
#[cfg(feature = "wasm")]
fn unprotect_keypair_internal(
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
#[wasm_bindgen(js_name = unprotectKeypairRaw)]
/// Decrypts a previously protected RSA keypair using the provided passphrase.
/// Returns a JavaScript object containing the decrypted PEM-formatted keys.
pub fn unprotect_keypair_raw(
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
pub fn unprotect_keypair_impl(
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

#[cfg(not(feature = "wasm"))]
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
