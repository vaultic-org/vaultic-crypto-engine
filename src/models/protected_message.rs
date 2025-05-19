use serde::Serialize;

/// Structure for storing protected message
#[derive(Serialize)]
pub struct ProtectedMessage {
    /// Base64-encoded ciphertext
    pub ciphertext: String,
    /// Base64-encoded salt used for key derivation
    pub salt: String,
    /// Base64-encoded nonce used for encryption
    pub nonce: String,
} 