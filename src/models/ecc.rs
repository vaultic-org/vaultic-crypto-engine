use serde::{Deserialize, Serialize};

/// Supported elliptic curves
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub enum EccCurve {
    /// NIST P-256 (secp256r1)
    P256,
    /// secp256k1 (used in Bitcoin and Ethereum)
    K256,
}

/// A serializable ECC key pair encoded in PEM format
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EccKeyPair {
    /// PEM-encoded public key
    pub public_pem: String,
    /// PEM-encoded private key
    pub private_pem: String,
    /// The elliptic curve used
    pub curve: EccCurve,
}

/// ECDSA signature with curve information
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EccSignature {
    /// The signature bytes in DER format
    pub bytes: Vec<u8>,
    /// The elliptic curve used
    pub curve: EccCurve,
}

/// Shared secret derived from ECDH key agreement
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SharedSecret {
    /// The raw shared secret bytes
    pub bytes: Vec<u8>,
    /// The elliptic curve used
    pub curve: EccCurve,
}
