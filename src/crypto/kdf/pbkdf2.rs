use crate::utils::generate_salt;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;

/// Default number of iterations for PBKDF2
pub const PBKDF2_DEFAULT_ITERATIONS: u32 = 100_000;

/// Derives a key using PBKDF2-HMAC-SHA256
///
/// # Arguments
/// * `password` - The password or passphrase
/// * `salt` - The salt bytes (should be at least 16 bytes)
/// * `iterations` - The number of iterations
/// * `key_length` - The desired key length in bytes
///
/// # Returns
/// * `Result<Vec<u8>, String>` - The derived key or an error message
pub fn derive_key_pbkdf2(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_length: usize,
) -> Result<Vec<u8>, String> {
    // Validate inputs
    if password.is_empty() {
        return Err("Password cannot be empty".to_string());
    }

    if salt.len() < 16 {
        return Err("Salt should be at least 16 bytes".to_string());
    }

    if iterations < 10_000 {
        return Err("Iterations should be at least 10,000 for security".to_string());
    }

    if key_length < 16 || key_length > 64 {
        return Err("Key length should be between 16 and 64 bytes".to_string());
    }

    // Allocate output buffer
    let mut key = vec![0u8; key_length];

    // Derive the key
    pbkdf2::<Hmac<Sha256>>(password, salt, iterations, &mut key)
        .map_err(|e| format!("PBKDF2 key derivation failed: {}", e))?;

    Ok(key)
}

/// Generates a random salt and derives a key using PBKDF2-HMAC-SHA256
///
/// # Arguments
/// * `password` - The password or passphrase
/// * `key_length` - The desired key length in bytes
///
/// # Returns
/// * `Result<(Vec<u8>, Vec<u8>), String>` - The derived key and salt, or an error message
#[allow(dead_code)]
pub fn derive_key_pbkdf2_with_random_salt(
    password: &[u8],
    key_length: usize,
) -> Result<(Vec<u8>, [u8; 16]), String> {
    // Generate a random salt
    let salt = generate_salt();

    // Derive the key
    let key = derive_key_pbkdf2(password, &salt, PBKDF2_DEFAULT_ITERATIONS, key_length)?;

    Ok((key, salt))
}
