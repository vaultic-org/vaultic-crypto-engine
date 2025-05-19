use base64::{Engine as _, engine::general_purpose};

/// Encode bytes to Base64 string using standard encoding
pub fn encode_base64(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

/// Decode Base64 string to bytes
///
/// # Arguments
/// * `encoded` - Base64 encoded string
///
/// # Returns
/// * `Result<Vec<u8>, String>` - Decoded bytes or error message
pub fn decode_base64(encoded: &str) -> Result<Vec<u8>, String> {
    general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("Base64 decode failed: {}", e))
}
