use rand::{RngCore, rngs::OsRng};

/// Generate a cryptographically secure random nonce (12 bytes)
/// 
/// Suitable for AES-GCM operations
pub fn generate_nonce() -> [u8; 12] {
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    nonce_bytes
}

/// Generate a cryptographically secure random salt (16 bytes)
/// 
/// Suitable for key derivation functions
pub fn generate_salt() -> [u8; 16] {
    let mut salt_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut salt_bytes);
    salt_bytes
}

/// Generate cryptographically secure random bytes of a specified length
/// 
/// # Arguments
/// * `length` - Number of random bytes to generate
pub fn generate_random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    OsRng.fill_bytes(&mut bytes);
    bytes
} 