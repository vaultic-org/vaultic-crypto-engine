use crate::models::ProtectedMessage;
use crate::utils::{
    create_aes_cipher, decode_base64, derive_aes_key, encode_base64, generate_nonce, generate_salt,
};
use aes_gcm::{
    Nonce,
    aead::{Aead, Payload},
};

#[cfg(feature = "wasm")]
use serde_wasm_bindgen;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

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
pub fn protect_message_impl(plaintext: &str, passphrase: &str) -> ProtectedMessage {
    // Generate random salt and nonce using utility functions
    let salt_bytes = generate_salt();
    let nonce_bytes = generate_nonce();

    // Derive AES-256 key using utility function
    let key = derive_aes_key(passphrase, &salt_bytes).expect("PBKDF2 key derivation failed");

    // Initialize AES-GCM cipher using utility function
    let cipher = create_aes_cipher(&key).expect("Failed to initialize AES cipher");

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

    // Encode in Base64 using utility functions
    ProtectedMessage {
        ciphertext: encode_base64(&ciphertext),
        salt: encode_base64(&salt_bytes),
        nonce: encode_base64(&nonce_bytes),
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen(js_name = unprotectMessageObj)]
/// Decrypts a message previously encrypted with protect_message
///
/// Takes the encrypted message parameters as a JavaScript object and passphrase,
/// and returns the original plaintext if successful.
pub fn unprotect_message_obj(
    encrypted_message: &JsValue,
    passphrase: &str,
) -> Result<String, JsValue> {
    let protected: ProtectedMessage = serde_wasm_bindgen::from_value(encrypted_message.clone())
        .map_err(|e| JsValue::from_str(&format!("Failed to parse encrypted message: {}", e)))?;

    match unprotect_message_impl(&protected, passphrase) {
        Ok(plaintext) => Ok(plaintext),
        Err(e) => Err(JsValue::from_str(&e)),
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
/// Decrypts a message previously encrypted with protect_message
///
/// Takes individual encryption parameters:
/// - encrypted_data: Base64-encoded ciphertext
/// - passphrase: The passphrase used for encryption
/// - salt: Base64-encoded salt used for key derivation
/// - nonce: Base64-encoded nonce used for AES-GCM encryption
///
/// Returns the original plaintext if successful or an error.
pub fn unprotect_message(
    encrypted_data: &str,
    passphrase: &str,
    salt: &str,
    nonce: &str,
) -> Result<String, JsValue> {
    // Create a ProtectedMessage structure from the individual parameters
    let protected = ProtectedMessage {
        ciphertext: encrypted_data.to_string(),
        salt: salt.to_string(),
        nonce: nonce.to_string(),
    };

    // Reuse the existing implementation
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
pub fn unprotect_message_impl(
    encrypted_message: &ProtectedMessage,
    passphrase: &str,
) -> Result<String, String> {
    // Decode Base64 values using utility functions
    let salt = decode_base64(&encrypted_message.salt)?;
    let nonce = decode_base64(&encrypted_message.nonce)?;
    let ciphertext = decode_base64(&encrypted_message.ciphertext)?;

    // Verify input lengths
    if salt.len() != 16 {
        return Err("Invalid salt length".to_string());
    }
    if nonce.len() != 12 {
        return Err("Invalid nonce length".to_string());
    }

    // Derive AES key using utility function
    let key = derive_aes_key(passphrase, &salt)?;

    // Initialize AES-GCM cipher using utility function
    let cipher = create_aes_cipher(&key)?;

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
