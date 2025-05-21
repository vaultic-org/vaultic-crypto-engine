#[cfg(feature = "wasm")]
// This module provides WASM-compatible bindings for the library's functionality
use serde_wasm_bindgen;
use wasm_bindgen::prelude::*;

// Re-export AES-GCM functions for WASM
pub mod aes;

// Re-export ECDSA functions for WASM
pub mod ecdsa;

// Re-export ECDH functions for WASM
pub mod ecdh;

#[wasm_bindgen]
/// Returns the version of the library
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[wasm_bindgen]
/// Returns information about the library
pub fn info() -> JsValue {
    let info = serde_json::json!({
        "name": env!("CARGO_PKG_NAME"),
        "version": env!("CARGO_PKG_VERSION"),
        "description": env!("CARGO_PKG_DESCRIPTION"),
        "repository": env!("CARGO_PKG_REPOSITORY"),
        "features": {
            "rsa": true,
            "ecdsa": true,
            "ecdh": true,
            "aes": true,
            "kdf": true,
        }
    });

    serde_wasm_bindgen::to_value(&info).unwrap()
}
