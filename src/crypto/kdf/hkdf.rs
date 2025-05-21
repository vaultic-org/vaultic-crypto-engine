use crate::models::SharedSecret;
use hkdf::Hkdf;
use sha2::Sha256;

/// Derives a key using HKDF-SHA256
///
/// # Arguments
/// * `ikm` - The input key material (e.g., a shared secret)
/// * `salt` - Optional salt value (can be None)
/// * `info` - Optional context and application specific information (can be None)
/// * `key_length` - The desired key length in bytes
///
/// # Returns
/// * `Result<Vec<u8>, String>` - The derived key or an error message
pub fn derive_key_hkdf(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: Option<&[u8]>,
    key_length: usize,
) -> Result<Vec<u8>, String> {
    // Validate inputs
    if ikm.is_empty() {
        return Err("Input key material cannot be empty".to_string());
    }

    if key_length < 16 || key_length > 255 * 32 {
        return Err("Key length should be between 16 and 8160 bytes".to_string());
    }

    // Create HKDF instance
    let hkdf = match salt {
        Some(salt_bytes) => Hkdf::<Sha256>::new(Some(salt_bytes), ikm),
        None => Hkdf::<Sha256>::new(None, ikm),
    };

    // Allocate output buffer
    let mut okm = vec![0u8; key_length];

    // Derive the key
    hkdf.expand(info.unwrap_or(&[]), &mut okm)
        .map_err(|e| format!("HKDF key derivation failed: {}", e))?;

    Ok(okm)
}

/// Derives a key from a shared secret using HKDF-SHA256
///
/// # Arguments
/// * `shared_secret` - The shared secret from ECDH
/// * `salt` - Optional salt value (can be None)
/// * `info` - Optional context and application specific information (can be None)
/// * `key_length` - The desired key length in bytes
///
/// # Returns
/// * `Result<Vec<u8>, String>` - The derived key or an error message
pub fn derive_key_from_shared_secret(
    shared_secret: &SharedSecret,
    salt: Option<&[u8]>,
    info: Option<&[u8]>,
    key_length: usize,
) -> Result<Vec<u8>, String> {
    derive_key_hkdf(&shared_secret.bytes, salt, info, key_length)
}
