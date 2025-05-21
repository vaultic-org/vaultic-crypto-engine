#[cfg(feature = "wasm")]
// This module provides WASM-compatible bindings for AES functionality
mod aes_wasm {
    use crate::models::{ProtectedMessage, SharedSecret};
    use serde_wasm_bindgen;
    use wasm_bindgen::prelude::*;

    /// Re-export AES-GCM encrypt function for WASM
    #[wasm_bindgen]
    pub fn encrypt_with_shared_secret_wasm(
        plaintext: &str,
        shared_secret: &JsValue,
        info: Option<String>,
    ) -> Result<JsValue, JsValue> {
        use crate::crypto::aes::encrypt_with_derived_key;

        // Parse the shared secret
        let shared_secret: SharedSecret = serde_wasm_bindgen::from_value(shared_secret.clone())
            .map_err(|e| JsValue::from_str(&format!("Failed to parse shared secret: {}", e)))?;

        // Convert info to bytes if provided
        let info_bytes = info.map(|s| s.into_bytes());
        let info_ref = info_bytes.as_deref();

        // Encrypt the data
        let result = encrypt_with_derived_key(plaintext.as_bytes(), &shared_secret, None, info_ref)
            .map_err(|e| JsValue::from_str(&e))?;

        // Convert to JavaScript object
        Ok(serde_wasm_bindgen::to_value(&result).unwrap())
    }

    /// Re-export AES-GCM decrypt function for WASM
    #[wasm_bindgen]
    pub fn decrypt_with_shared_secret_wasm(
        protected_message: &JsValue,
        shared_secret: &JsValue,
        info: Option<String>,
    ) -> Result<String, JsValue> {
        use crate::crypto::aes::decrypt_with_derived_key;

        // Parse the protected message
        let protected: ProtectedMessage = serde_wasm_bindgen::from_value(protected_message.clone())
            .map_err(|e| JsValue::from_str(&format!("Failed to parse protected message: {}", e)))?;

        // Parse the shared secret
        let shared_secret: SharedSecret = serde_wasm_bindgen::from_value(shared_secret.clone())
            .map_err(|e| JsValue::from_str(&format!("Failed to parse shared secret: {}", e)))?;

        // Convert info to bytes if provided
        let info_bytes = info.map(|s| s.into_bytes());
        let info_ref = info_bytes.as_deref();

        // Decrypt the data
        let plaintext = decrypt_with_derived_key(&protected, &shared_secret, info_ref)
            .map_err(|e| JsValue::from_str(&e))?;

        // Convert to string
        String::from_utf8(plaintext)
            .map_err(|e| JsValue::from_str(&format!("Invalid UTF-8 in decrypted text: {}", e)))
    }
}

#[cfg(feature = "wasm")]
#[allow(unused_imports)]
pub use aes_wasm::*;
