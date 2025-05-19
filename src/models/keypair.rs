use serde::{Deserialize, Serialize};

/// A serializable RSA key pair (public + private) encoded in PEM format.
#[derive(Serialize)]
pub struct KeyPair {
    /// PEM-encoded RSA public key
    pub public_pem: String,
    /// PEM-encoded RSA private key
    pub private_pem: String,
}

/// Structure for the encrypted keypair result
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncryptedKeypairResult {
    /// Base64-encoded encrypted private key
    pub encrypted_private: String,
    /// Base64-encoded encrypted public key
    pub encrypted_public: String,
    /// Base64-encoded salt used for key derivation
    pub salt: String,
    /// Base64-encoded nonce used for private key encryption
    pub nonce_private: String,
    /// Base64-encoded nonce used for public key encryption
    pub nonce_public: String,
}

/// Structure for encrypted keypair input parameters
#[derive(Deserialize)]
pub struct EncryptedKeypairInput {
    /// Base64-encoded encrypted private key
    pub encrypted_private: String,
    /// Base64-encoded encrypted public key
    pub encrypted_public: String,
    /// Base64-encoded salt used for key derivation
    pub salt: String,
    /// Base64-encoded nonce used for encryption
    pub nonce: String,
} 