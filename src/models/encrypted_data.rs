use serde::{Deserialize, Serialize};

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