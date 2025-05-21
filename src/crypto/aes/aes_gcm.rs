use crate::{
    crypto::kdf::{PBKDF2_DEFAULT_ITERATIONS, derive_key_pbkdf2},
    models::{ProtectedMessage, SharedSecret},
    utils::{decode_base64, encode_base64, generate_nonce, generate_salt},
};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};

/// Encrypts data using AES-256-GCM with a provided key
///
/// # Arguments
/// * `plaintext` - The data to encrypt
/// * `key` - The 32-byte AES key
/// * `nonce` - The 12-byte nonce (should be unique for each encryption)
/// * `aad` - Optional additional authenticated data
///
/// # Returns
/// * `Result<Vec<u8>, String>` - The encrypted data or an error message
pub fn encrypt_aes_gcm(
    plaintext: &[u8],
    key: &[u8],
    nonce: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    // Validate key length
    if key.len() != 32 {
        return Err(format!(
            "AES-256 requires a 32-byte key, got {} bytes",
            key.len()
        ));
    }

    // Validate nonce length
    if nonce.len() != 12 {
        return Err(format!(
            "AES-GCM requires a 12-byte nonce, got {} bytes",
            nonce.len()
        ));
    }

    // Initialize AES-GCM cipher
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("Failed to create AES cipher: {}", e))?;

    // Create nonce
    let nonce = Nonce::from_slice(nonce);

    // Encrypt the data
    let ciphertext = match aad {
        Some(aad_bytes) => cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: aad_bytes,
                },
            )
            .map_err(|e| format!("AES encryption failed: {}", e))?,
        None => cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| format!("AES encryption failed: {}", e))?,
    };

    Ok(ciphertext)
}

/// Decrypts data using AES-256-GCM with a provided key
///
/// # Arguments
/// * `ciphertext` - The encrypted data
/// * `key` - The 32-byte AES key
/// * `nonce` - The 12-byte nonce used for encryption
/// * `aad` - Optional additional authenticated data (must match what was used for encryption)
///
/// # Returns
/// * `Result<Vec<u8>, String>` - The decrypted data or an error message
pub fn decrypt_aes_gcm(
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    // Validate key length
    if key.len() != 32 {
        return Err(format!(
            "AES-256 requires a 32-byte key, got {} bytes",
            key.len()
        ));
    }

    // Validate nonce length
    if nonce.len() != 12 {
        return Err(format!(
            "AES-GCM requires a 12-byte nonce, got {} bytes",
            nonce.len()
        ));
    }

    // Initialize AES-GCM cipher
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("Failed to create AES cipher: {}", e))?;

    // Create nonce
    let nonce = Nonce::from_slice(nonce);

    // Decrypt the data
    let plaintext = match aad {
        Some(aad_bytes) => cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: aad_bytes,
                },
            )
            .map_err(|e| format!("AES decryption failed: {}", e))?,
        None => cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("AES decryption failed: {}", e))?,
    };

    Ok(plaintext)
}

/// Encrypts data using AES-256-GCM with a key derived from a passphrase
///
/// # Arguments
/// * `plaintext` - The data to encrypt
/// * `passphrase` - The passphrase to derive the key from
///
/// # Returns
/// * `Result<ProtectedMessage, String>` - The encrypted data and metadata or an error message
#[allow(dead_code)]
pub fn encrypt_with_passphrase(
    plaintext: &[u8],
    passphrase: &str,
) -> Result<ProtectedMessage, String> {
    // Generate salt and nonce
    let salt = generate_salt();
    let nonce = generate_nonce();

    // Derive AES key using PBKDF2
    let key = derive_key_pbkdf2(passphrase.as_bytes(), &salt, PBKDF2_DEFAULT_ITERATIONS, 32)?;

    // Encrypt the data
    let ciphertext = encrypt_aes_gcm(plaintext, &key, &nonce, None)?;

    // Create and return the protected message
    Ok(ProtectedMessage {
        ciphertext: encode_base64(&ciphertext),
        salt: encode_base64(&salt),
        nonce: encode_base64(&nonce),
    })
}

/// Decrypts data using AES-256-GCM with a key derived from a passphrase
///
/// # Arguments
/// * `protected` - The protected message containing ciphertext and metadata
/// * `passphrase` - The passphrase to derive the key from
///
/// # Returns
/// * `Result<Vec<u8>, String>` - The decrypted data or an error message
#[allow(dead_code)]
pub fn decrypt_with_passphrase(
    protected: &ProtectedMessage,
    passphrase: &str,
) -> Result<Vec<u8>, String> {
    // Decode Base64 values
    let salt = decode_base64(&protected.salt)?;
    let nonce = decode_base64(&protected.nonce)?;
    let ciphertext = decode_base64(&protected.ciphertext)?;

    // Derive AES key using PBKDF2
    let key = derive_key_pbkdf2(passphrase.as_bytes(), &salt, PBKDF2_DEFAULT_ITERATIONS, 32)?;

    // Decrypt the data
    decrypt_aes_gcm(&ciphertext, &key, &nonce, None)
}

/// Encrypts data using AES-256-GCM with a key derived from a shared secret
///
/// # Arguments
/// * `plaintext` - The data to encrypt
/// * `shared_secret` - The shared secret from ECDH
/// * `salt` - Optional salt for key derivation (random salt will be generated if None)
/// * `info` - Optional context information for key derivation
///
/// # Returns
/// * `Result<ProtectedMessage, String>` - The encrypted data and metadata or an error message
pub fn encrypt_with_derived_key(
    plaintext: &[u8],
    shared_secret: &SharedSecret,
    salt: Option<&[u8]>,
    info: Option<&[u8]>,
) -> Result<ProtectedMessage, String> {
    // Generate nonce
    let nonce = generate_nonce();

    // Generate salt if not provided
    let owned_salt;
    let salt_bytes = match salt {
        Some(s) => s,
        None => {
            owned_salt = generate_salt();
            &owned_salt
        }
    };

    // Derive AES key using HKDF
    let key = derive_key_from_shared_secret(shared_secret, Some(salt_bytes), info, 32)?;

    // Encrypt the data
    let ciphertext = encrypt_aes_gcm(plaintext, &key, &nonce, None)?;

    // Create and return the protected message
    Ok(ProtectedMessage {
        ciphertext: encode_base64(&ciphertext),
        salt: encode_base64(salt_bytes),
        nonce: encode_base64(&nonce),
    })
}

/// Decrypts data using AES-256-GCM with a key derived from a shared secret
///
/// # Arguments
/// * `protected` - The protected message containing ciphertext and metadata
/// * `shared_secret` - The shared secret from ECDH
/// * `info` - Optional context information for key derivation (must match what was used for encryption)
///
/// # Returns
/// * `Result<Vec<u8>, String>` - The decrypted data or an error message
pub fn decrypt_with_derived_key(
    protected: &ProtectedMessage,
    shared_secret: &SharedSecret,
    info: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    // Decode Base64 values
    let salt = decode_base64(&protected.salt)?;
    let nonce = decode_base64(&protected.nonce)?;
    let ciphertext = decode_base64(&protected.ciphertext)?;

    // Derive AES key using HKDF
    let key = derive_key_from_shared_secret(shared_secret, Some(&salt), info, 32)?;

    // Decrypt the data
    decrypt_aes_gcm(&ciphertext, &key, &nonce, None)
}

/// Derives a key from a shared secret using HKDF-SHA256
///
/// # Arguments
/// * `shared_secret` - The shared secret from ECDH
/// * `salt` - Optional salt value (can be None)
/// * `info` - Optional context information for key derivation
/// * `key_length` - The desired key length in bytes
///
/// # Returns
/// * `Result<Vec<u8>, String>` - The derived key or an error message
fn derive_key_from_shared_secret(
    shared_secret: &SharedSecret,
    salt: Option<&[u8]>,
    info: Option<&[u8]>,
    key_length: usize,
) -> Result<Vec<u8>, String> {
    crate::crypto::kdf::hkdf::derive_key_from_shared_secret(shared_secret, salt, info, key_length)
}
