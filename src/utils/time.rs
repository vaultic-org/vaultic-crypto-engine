#[cfg(feature = "wasm")]

#[cfg(feature = "wasm")]
/// Get current timestamp suitable for use as a random seed
/// Uses JavaScript Date.now() in WebAssembly environments
pub fn get_now_seed() -> u64 {
    // Use JavaScript Date.now() via wasm-bindgen
    js_sys::Date::now() as u64
}

#[cfg(not(feature = "wasm"))]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(not(feature = "wasm"))]
/// Get current timestamp suitable for use as a random seed
/// Uses system time in native environments
pub fn get_now_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}
