// Maximum size for direct RSA encryption
// For RSA 2048-bit, the maximum is 2048/8 - padding = 256 - 11 = 245 bytes
pub const MAX_RSA_SIZE: usize = 245;

// Sub-modules
pub mod keypair;
pub mod keypair_protection;
pub mod message;
pub mod rsa;

// Re-export commonly used functions and types
pub use keypair::{generate_keypair_impl, generate_rsa_keypair_pem};
#[cfg(feature = "wasm")]
pub use keypair_protection::unprotect_keypair_raw;
pub use keypair_protection::{
    protect_keypair, protect_keypair_impl, unprotect_keypair, unprotect_keypair_impl,
};
#[cfg(feature = "wasm")]
pub use message::unprotect_message_obj;
pub use message::{
    protect_message, protect_message_impl, unprotect_message, unprotect_message_impl,
};
pub use rsa::{
    direct_rsa_decrypt, direct_rsa_encrypt_base64, hybrid_rsa_aes_decrypt,
    hybrid_rsa_aes_encrypt_base64, rsa_decrypt_base64, rsa_decrypt_base64_impl, rsa_encrypt_base64,
    rsa_encrypt_base64_impl,
};
