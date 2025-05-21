use crate::models::{EccCurve, SharedSecret};
use elliptic_curve::pkcs8::{DecodePrivateKey, DecodePublicKey};
use k256::{
    PublicKey as K256PublicKey, SecretKey as K256SecretKey,
    ecdh::diffie_hellman as k256_diffie_hellman,
};
use p256::{
    PublicKey as P256PublicKey, SecretKey as P256SecretKey,
    ecdh::diffie_hellman as p256_diffie_hellman,
};

/// Derives a shared secret using ECDH key agreement
///
/// # Arguments
/// * `private_key_pem` - The local private key in PEM format
/// * `public_key_pem` - The remote public key in PEM format
/// * `curve` - The elliptic curve used by the keys (P256/secp256r1 or K256/secp256k1)
///
/// # Returns
/// * `Result<SharedSecret, String>` - The derived shared secret or an error message
pub fn derive_shared_secret(
    private_key_pem: &str,
    public_key_pem: &str,
    curve: EccCurve,
) -> Result<SharedSecret, String> {
    match curve {
        EccCurve::P256 => derive_p256_shared_secret(private_key_pem, public_key_pem),
        EccCurve::K256 => derive_k256_shared_secret(private_key_pem, public_key_pem),
    }
}

/// Internal function to derive a shared secret using P-256 keys
pub fn derive_p256_shared_secret(
    private_key_pem: &str,
    public_key_pem: &str,
) -> Result<SharedSecret, String> {
    // Parse the private key from PEM
    let private_key = P256SecretKey::from_pkcs8_pem(private_key_pem)
        .map_err(|e| format!("Failed to parse P-256 private key: {}", e))?;

    // Parse the public key from PEM
    let public_key = P256PublicKey::from_public_key_pem(public_key_pem)
        .map_err(|e| format!("Failed to parse P-256 public key: {}", e))?;

    // Get the private scalar for ECDH calculation
    let secret_scalar = private_key.to_nonzero_scalar();

    // Convert PublicKey to AffinePoint for diffie_hellman
    let public_affine_point = public_key.to_projective().to_affine();

    // Perform ECDH key agreement
    let shared_secret = p256_diffie_hellman(secret_scalar, &public_affine_point);

    // Extract the bytes
    let secret_bytes = shared_secret.raw_secret_bytes().to_vec();

    Ok(SharedSecret {
        bytes: secret_bytes,
        curve: EccCurve::P256,
    })
}

/// Internal function to derive a shared secret using K-256 keys
pub fn derive_k256_shared_secret(
    private_key_pem: &str,
    public_key_pem: &str,
) -> Result<SharedSecret, String> {
    // Parse the private key from PEM
    let private_key = K256SecretKey::from_pkcs8_pem(private_key_pem)
        .map_err(|e| format!("Failed to parse K-256 private key: {}", e))?;

    // Parse the public key from PEM
    let public_key = K256PublicKey::from_public_key_pem(public_key_pem)
        .map_err(|e| format!("Failed to parse K-256 public key: {}", e))?;

    // Get the private scalar for ECDH calculation
    let secret_scalar = private_key.to_nonzero_scalar();

    // Convert PublicKey to AffinePoint for diffie_hellman
    let public_affine_point = public_key.to_projective().to_affine();

    // Perform ECDH key agreement
    let shared_secret = k256_diffie_hellman(secret_scalar, &public_affine_point);

    // Extract the bytes
    let secret_bytes = shared_secret.raw_secret_bytes().to_vec();

    Ok(SharedSecret {
        bytes: secret_bytes,
        curve: EccCurve::K256,
    })
}

/* // Removing these wasm functions as they are handled by the bindings module
#[cfg(feature = "wasm")]
#[wasm_bindgen]
/// Derives a shared secret using P-256 ECDH key agreement
///
/// # Arguments
/// * `private_key_pem` - The local P-256 private key in PEM format
/// * `public_key_pem` - The remote P-256 public key in PEM format
///
/// # Returns
/// * `Result<JsValue, JsValue>` - The derived shared secret as a JavaScript object or an error
pub fn derive_p256_shared_secret_wasm(
    private_key_pem: &str,
    public_key_pem: &str,
) -> Result<JsValue, JsValue> {
    let result = derive_p256_shared_secret(private_key_pem, public_key_pem)
        .map_err(|e| JsValue::from_str(&e))?;

    Ok(serde_wasm_bindgen::to_value(&result).unwrap())
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
/// Derives a shared secret using K-256 ECDH key agreement
///
/// # Arguments
/// * `private_key_pem` - The local K-256 private key in PEM format
/// * `public_key_pem` - The remote K-256 public key in PEM format
///
/// # Returns
/// * `Result<JsValue, JsValue>` - The derived shared secret as a JavaScript object or an error
pub fn derive_k256_shared_secret_wasm(
    private_key_pem: &str,
    public_key_pem: &str,
) -> Result<JsValue, JsValue> {
    let result = derive_k256_shared_secret(private_key_pem, public_key_pem)
        .map_err(|e| JsValue::from_str(&e))?;

    Ok(serde_wasm_bindgen::to_value(&result).unwrap())
}
*/
