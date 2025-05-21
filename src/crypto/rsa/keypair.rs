use crate::models::KeyPair;
use rand::rngs::OsRng;
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs8::{EncodePrivateKey, EncodePublicKey},
};

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
use serde_wasm_bindgen;

#[cfg(feature = "wasm")]
#[wasm_bindgen]
/// Generates a 2048-bit RSA key pair and returns it as a JavaScript object.
pub fn generate_rsa_keypair_pem() -> JsValue {
    let keypair = generate_keypair_impl();
    serde_wasm_bindgen::to_value(&keypair).unwrap()
}

#[cfg(not(feature = "wasm"))]
/// Generates a 2048-bit RSA key pair and returns it as a Rust struct.
pub fn generate_rsa_keypair_pem() -> KeyPair {
    generate_keypair_impl()
}

/// Shared internal implementation for RSA key pair generation.
#[doc(hidden)]
pub fn generate_keypair_impl() -> KeyPair {
    let mut rng = OsRng;

    // Generate RSA private key with 2048-bit modulus
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate RSA key pair");
    let public_key = RsaPublicKey::from(&private_key);

    // Encode keys to PEM format
    let private_pem = private_key
        .to_pkcs8_pem(Default::default())
        .expect("Failed to encode private key")
        .to_string();
    let public_pem = public_key
        .to_public_key_pem(Default::default())
        .expect("Failed to encode public key")
        .to_string();

    KeyPair {
        public_pem,
        private_pem,
    }
}
