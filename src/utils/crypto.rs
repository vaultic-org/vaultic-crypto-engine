use aes_gcm::{
    Aes256Gcm,
    aead::KeyInit,
};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;

/// Number of PBKDF2 iterations for key derivation
pub const PBKDF2_ROUNDS: u32 = 100_000;

/// Derive AES-256 key from passphrase and salt using PBKDF2-HMAC-SHA256
/// 
/// # Arguments
/// * `passphrase` - User-provided passphrase
/// * `salt` - Salt bytes for key derivation
/// 
/// # Returns
/// * `Result<[u8; 32], String>` - Derived 32-byte key or error message
pub fn derive_aes_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32]; // 256 bits for AES-256
    
    pbkdf2::<Hmac<Sha256>>(passphrase.as_bytes(), salt, PBKDF2_ROUNDS, &mut key)
        .map_err(|e| format!("PBKDF2 key derivation failed: {}", e))?;
        
    Ok(key)
}

/// Create an AES-256-GCM cipher from a key
/// 
/// # Arguments
/// * `key` - 32-byte AES key
/// 
/// # Returns
/// * `Result<Aes256Gcm, String>` - Initialized cipher or error message
pub fn create_aes_cipher(key: &[u8; 32]) -> Result<Aes256Gcm, String> {
    Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("Failed to create AES cipher: {}", e))
} 