use crate::models::{EccCurve, EccKeyPair, EccSignature};
use ecdsa::signature::{Signer, Verifier};
use elliptic_curve::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use k256::ecdsa::{SigningKey as K256SigningKey, VerifyingKey as K256VerifyingKey};
use p256::ecdsa::{SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};
use rand::rngs::OsRng;

/// Generates an ECDSA key pair using the specified elliptic curve
///
/// # Arguments
/// * `curve` - The elliptic curve to use (P256/secp256r1 or K256/secp256k1)
///
/// # Returns
/// * `EccKeyPair` - The generated key pair with public and private keys in PEM format
pub fn generate_ecdsa_keypair(curve: EccCurve) -> EccKeyPair {
    match curve {
        EccCurve::P256 => generate_p256_keypair(),
        EccCurve::K256 => generate_k256_keypair(),
    }
}

/// Internal function to generate a P-256 (secp256r1) key pair
pub fn generate_p256_keypair() -> EccKeyPair {
    // Generate a random signing key
    let signing_key = P256SigningKey::random(&mut OsRng);

    // Derive the verifying key from the signing key
    let verifying_key = signing_key.verifying_key();

    // Convert to PEM format
    let private_pem = signing_key
        .to_pkcs8_pem(Default::default())
        .expect("Failed to encode P-256 private key")
        .to_string();

    let public_pem = verifying_key
        .to_public_key_pem(Default::default())
        .expect("Failed to encode P-256 public key")
        .to_string();

    EccKeyPair {
        public_pem,
        private_pem,
        curve: EccCurve::P256,
    }
}

/// Internal function to generate a K-256 (secp256k1) key pair
pub fn generate_k256_keypair() -> EccKeyPair {
    // Generate a random signing key
    let signing_key = K256SigningKey::random(&mut OsRng);

    // Derive the verifying key from the signing key
    let verifying_key = signing_key.verifying_key();

    // Convert to PEM format
    let private_pem = signing_key
        .to_pkcs8_pem(Default::default())
        .expect("Failed to encode K-256 private key")
        .to_string();

    let public_pem = verifying_key
        .to_public_key_pem(Default::default())
        .expect("Failed to encode K-256 public key")
        .to_string();

    EccKeyPair {
        public_pem,
        private_pem,
        curve: EccCurve::K256,
    }
}

/// Signs a message using an ECDSA private key
///
/// # Arguments
/// * `message` - The message to sign
/// * `private_key_pem` - The ECDSA private key in PEM format
/// * `curve` - The elliptic curve used by the key (P256/secp256r1 or K256/secp256k1)
///
/// # Returns
/// * `Result<EccSignature, String>` - The signature or an error message
pub fn ecdsa_sign(
    message: &[u8],
    private_key_pem: &str,
    curve: EccCurve,
) -> Result<EccSignature, String> {
    match curve {
        EccCurve::P256 => ecdsa_sign_p256(message, private_key_pem),
        EccCurve::K256 => ecdsa_sign_k256(message, private_key_pem),
    }
}

/// Internal function to sign a message using a P-256 private key
pub fn ecdsa_sign_p256(message: &[u8], private_key_pem: &str) -> Result<EccSignature, String> {
    // Parse the private key from PEM
    let signing_key = P256SigningKey::from_pkcs8_pem(private_key_pem)
        .map_err(|e| format!("Failed to parse P-256 private key: {}", e))?;

    // Sign the message
    let signature: p256::ecdsa::Signature = signing_key.sign(message);

    // Convert to ASN.1 DER format
    let signature_bytes = signature.to_der();

    Ok(EccSignature {
        bytes: signature_bytes.as_bytes().to_vec(),
        curve: EccCurve::P256,
    })
}

/// Internal function to sign a message using a K-256 private key
pub fn ecdsa_sign_k256(message: &[u8], private_key_pem: &str) -> Result<EccSignature, String> {
    // Parse the private key from PEM
    let signing_key = K256SigningKey::from_pkcs8_pem(private_key_pem)
        .map_err(|e| format!("Failed to parse K-256 private key: {}", e))?;

    // Sign the message
    let signature: k256::ecdsa::Signature = signing_key.sign(message);

    // Convert to ASN.1 DER format
    let signature_bytes = signature.to_der();

    Ok(EccSignature {
        bytes: signature_bytes.as_bytes().to_vec(),
        curve: EccCurve::K256,
    })
}

/// Verifies an ECDSA signature against a message and public key
///
/// # Arguments
/// * `message` - The original message
/// * `signature` - The signature to verify
/// * `public_key_pem` - The ECDSA public key in PEM format
/// * `curve` - The elliptic curve used by the key (P256/secp256r1 or K256/secp256k1)
///
/// # Returns
/// * `Result<bool, String>` - True if the signature is valid, false otherwise
pub fn ecdsa_verify(
    message: &[u8],
    signature: &EccSignature,
    public_key_pem: &str,
) -> Result<bool, String> {
    match signature.curve {
        EccCurve::P256 => ecdsa_verify_p256(message, &signature.bytes, public_key_pem),
        EccCurve::K256 => ecdsa_verify_k256(message, &signature.bytes, public_key_pem),
    }
}

/// Internal function to verify a signature using a P-256 public key
pub fn ecdsa_verify_p256(
    message: &[u8],
    signature_bytes: &[u8],
    public_key_pem: &str,
) -> Result<bool, String> {
    // Parse the public key from PEM
    let verifying_key = P256VerifyingKey::from_public_key_pem(public_key_pem)
        .map_err(|e| format!("Failed to parse P-256 public key: {}", e))?;

    // Parse the signature from DER format
    let signature = p256::ecdsa::Signature::from_der(signature_bytes)
        .map_err(|e| format!("Failed to parse P-256 signature: {}", e))?;

    // Verify the signature
    match verifying_key.verify(message, &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false), // Signature verification failed but not due to an error
                             // Err(e) => Err(format!("Verification error: {}", e)), // Uncommenting would report actual errors
    }
}

/// Internal function to verify a signature using a K-256 public key
pub fn ecdsa_verify_k256(
    message: &[u8],
    signature_bytes: &[u8],
    public_key_pem: &str,
) -> Result<bool, String> {
    // Parse the public key from PEM
    let verifying_key = K256VerifyingKey::from_public_key_pem(public_key_pem)
        .map_err(|e| format!("Failed to parse K-256 public key: {}", e))?;

    // Parse the signature from DER format
    let signature = k256::ecdsa::Signature::from_der(signature_bytes)
        .map_err(|e| format!("Failed to parse K-256 signature: {}", e))?;

    // Verify the signature
    match verifying_key.verify(message, &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false), // Signature verification failed but not due to an error
                             // Err(e) => Err(format!("Verification error: {}", e)), // Uncommenting would report actual errors
    }
}
