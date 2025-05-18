# Vaultic Crypto Engine

A high-performance cryptographic library for secure RSA operations with support for both native Rust and WebAssembly environments.

## 🔐 New Features (v0.1.4)

- **Automatic hybrid encryption**: handles data of any size seamlessly
  - For small messages (<245 bytes), uses direct RSA encryption
  - For larger messages, automatically switches to hybrid RSA+AES-GCM encryption
- **Automatic mode detection**: decryption automatically detects and handles both formats
- **Backward compatibility**: messages encrypted with previous versions can still be decrypted

## 🛡️ Security Warning

This library uses a pure Rust RSA implementation with additional mitigations against the Marvin Attack (RUSTSEC-2023-0071), a timing side-channel vulnerability. The mitigations implemented include:
1. Random delays added to operations involving private keys
2. More aggressive blinding factors
3. Usage recommendations for non-network environments

For critical applications, consider using a library with constant-time guarantees such as `aws-lc-rs`.

## Features

- 🔑 RSA key generation (2048-bit)
- 🔒 RSA-PKCS#1 encryption with automatic size handling
- 🔁 Hybrid RSA+AES encryption for large data
- 🔓 RSA decryption with timing attack protections
- 📦 Base64 encoding/decoding for easy transport
- 🌐 WebAssembly support for browser environments

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
vaultic-crypto-engine = "0.1.4"
```

For WebAssembly support, enable the `wasm` feature:

```toml
[dependencies]
vaultic-crypto-engine = { version = "0.1.4", features = ["wasm"] }
```

## Usage

### Key Generation

```rust
use vaultic_crypto_engine::generate_rsa_keypair_pem;

fn main() {
    let keypair = generate_rsa_keypair_pem();
    
    println!("Public Key:\n{}", keypair.public_pem);
    println!("Private Key:\n{}", keypair.private_pem);
}
```

### Encryption and Decryption

```rust
use vaultic_crypto_engine::{generate_rsa_keypair_pem, rsa_encrypt_base64, rsa_decrypt_base64};

fn main() {
    // Generate a key pair
    let keypair = generate_rsa_keypair_pem();
    
    // Message to encrypt (can be of any size)
    let message = "This is a very long secret message that will be automatically handled by the hybrid RSA+AES encryption. You don't need to worry about the message size, the library will adapt automatically based on the amount of data to encrypt.";
    
    // Encrypt with the public key
    let encrypted = rsa_encrypt_base64(&keypair.public_pem, message);
    println!("Encrypted: {}", encrypted);
    
    // Decrypt with the private key
    let decrypted = rsa_decrypt_base64(&keypair.private_pem, &encrypted);
    println!("Decrypted: {}", decrypted);
    
    assert_eq!(message, decrypted);
}
```

### WebAssembly Usage

When compiled to WebAssembly, the library can be used from JavaScript:

```javascript
import init, { generate_rsa_keypair_pem, rsa_encrypt_base64, rsa_decrypt_base64 } from 'vaultic-crypto-engine';

async function run() {
  await init();
  
  // Generate a key pair
  const keypair = generate_rsa_keypair_pem();
  
  // Encrypt a message (even a very large one)
  const message = "Secret message from JavaScript with lots of data...";
  const encrypted = rsa_encrypt_base64(keypair.public_pem, message);
  
  // Decrypt the message
  const decrypted = rsa_decrypt_base64(keypair.private_pem, encrypted);
  console.log(decrypted); // "Secret message from JavaScript..."
}

run();
```

## How Hybrid Encryption Works

For small messages (≤ 245 bytes), we use direct RSA encryption with PKCS#1 v1.5 padding.

For larger messages, we use a hybrid approach:
1. Generate a random AES-256 key
2. Encrypt the message with AES-GCM
3. Encrypt the AES key with RSA
4. Encode all this information in a special JSON format which is then Base64 encoded

Decryption automatically detects the format used and applies the correct algorithm.

## Building for WebAssembly

To build the WebAssembly module:

```bash
wasm-pack build --release --target bundler -- --features wasm
```

## License

MIT License

## Contributing

Contributions to improve security and add features are welcome. Please see the CONTRIBUTING.md file for more information.