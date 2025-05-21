#[cfg(feature = "wasm")]
// This module provides WASM-compatible bindings for ECDH functionality
#[allow(unused_imports)]
mod ecdh_wasm {
    use crate::crypto::ecc::ecdh::{derive_k256_shared_secret, derive_p256_shared_secret};
    use crate::models::{EccCurve, SharedSecret};
    use serde_wasm_bindgen;
    use wasm_bindgen::prelude::*;

    // Re-export ECDH key derivation functions for WASM
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
            .map_err(|e| JsValue::from_str(e.as_str()))?;

        Ok(serde_wasm_bindgen::to_value(&result).unwrap())
    }

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
            .map_err(|e| JsValue::from_str(e.as_str()))?;

        Ok(serde_wasm_bindgen::to_value(&result).unwrap())
    }
}

#[cfg(feature = "wasm")]
#[allow(unused_imports)]
pub use ecdh_wasm::*;
