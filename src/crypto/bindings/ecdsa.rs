#[cfg(feature = "wasm")]
// This module provides WASM-compatible bindings for ECDSA functionality
#[allow(unused_imports)]
mod ecdsa_wasm {
    use crate::{
        crypto::ecc::ecdsa::{
            ecdsa_sign_k256, ecdsa_sign_p256, ecdsa_verify_k256, ecdsa_verify_p256,
            generate_k256_keypair, generate_p256_keypair,
        },
        models::{EccCurve, EccKeyPair, EccSignature},
    };
    use serde_wasm_bindgen;
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    /// ECDSA supported curves
    ///
    /// - P256: NIST P-256 (secp256r1)
    /// - K256: secp256k1 (used in Bitcoin and Ethereum)
    pub enum WasmEccCurve {
        P256 = 0,
        K256 = 1,
    }

    #[wasm_bindgen]
    /// Generates an ECDSA key pair using the specified curve
    ///
    /// # Arguments
    /// * `curve` - The elliptic curve to use (P256 or K256)
    ///
    /// # Returns
    /// * `JsValue` - The generated key pair as a JavaScript object
    pub fn generate_ecdsa_keypair_wasm(curve: WasmEccCurve) -> JsValue {
        match curve {
            WasmEccCurve::P256 => {
                let keypair = generate_p256_keypair();
                serde_wasm_bindgen::to_value(&keypair).unwrap()
            }
            WasmEccCurve::K256 => {
                let keypair = generate_k256_keypair();
                serde_wasm_bindgen::to_value(&keypair).unwrap()
            }
        }
    }

    // ECDSA sign function for P-256
    #[wasm_bindgen]
    pub fn ecdsa_sign_p256_wasm(message: &str, private_key_pem: &str) -> Result<JsValue, JsValue> {
        let result = ecdsa_sign_p256(message.as_bytes(), private_key_pem)
            .map_err(|e| JsValue::from_str(e.as_str()))?;

        Ok(serde_wasm_bindgen::to_value(&result).unwrap())
    }

    // ECDSA sign function for K-256
    #[wasm_bindgen]
    pub fn ecdsa_sign_k256_wasm(message: &str, private_key_pem: &str) -> Result<JsValue, JsValue> {
        let result = ecdsa_sign_k256(message.as_bytes(), private_key_pem)
            .map_err(|e| JsValue::from_str(e.as_str()))?;

        Ok(serde_wasm_bindgen::to_value(&result).unwrap())
    }

    // ECDSA verify function for P-256
    #[wasm_bindgen]
    pub fn ecdsa_verify_p256_wasm(
        message: &str,
        signature: &JsValue,
        public_key_pem: &str,
    ) -> Result<bool, JsValue> {
        // Parse the signature from JavaScript
        let signature: EccSignature = serde_wasm_bindgen::from_value(signature.clone())
            .map_err(|e| JsValue::from_str(&format!("Failed to parse signature: {}", e)))?;

        // Verify the signature
        ecdsa_verify_p256(message.as_bytes(), &signature.bytes, public_key_pem)
            .map_err(|e| JsValue::from_str(e.as_str()))
    }

    // ECDSA verify function for K-256
    #[wasm_bindgen]
    pub fn ecdsa_verify_k256_wasm(
        message: &str,
        signature: &JsValue,
        public_key_pem: &str,
    ) -> Result<bool, JsValue> {
        // Parse the signature from JavaScript
        let signature: EccSignature = serde_wasm_bindgen::from_value(signature.clone())
            .map_err(|e| JsValue::from_str(&format!("Failed to parse signature: {}", e)))?;

        // Verify the signature
        ecdsa_verify_k256(message.as_bytes(), &signature.bytes, public_key_pem)
            .map_err(|e| JsValue::from_str(e.as_str()))
    }
}

#[cfg(feature = "wasm")]
#[allow(unused_imports)]
pub use ecdsa_wasm::*;
