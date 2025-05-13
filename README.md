# Vaultic Crypto Engine

A high-performance cryptographic library for secure RSA operations with support for both native Rust and WebAssembly environments.

## 🛡️ Security Warning

This library uses a pure Rust RSA implementation with additional mitigations against the Marvin Attack (RUSTSEC-2023-0071), a timing side-channel vulnerability. The mitigations implemented include:

1. Random delays added to operations involving private keys
2. More aggressive blinding factors
3. Usage recommendations for non-network environments

For critical applications, consider using a library with constant-time guarantees such as `aws-lc-rs`.

## Features

- 🔑 RSA key generation (2048-bit)
- 🔒 RSA-PKCS#1 encryption
- 🔓 RSA decryption with timing attack protections
- 📦 Base64 encoding/decoding for easy transport
- 🌐 WebAssembly support for browser environments

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
vaultic-crypto-engine = "0.1.0"
```

For WebAssembly support, enable the `wasm` feature:

```toml
[dependencies]
vaultic-crypto-engine = { version = "0.1.0", features = ["wasm"] }
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
    
    // Message to encrypt
    let message = "This is a secret message";
    
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
  
  // Encrypt a message
  const message = "Secret message from JavaScript";
  const encrypted = rsa_encrypt_base64(keypair.public_pem, message);
  
  // Decrypt the message
  const decrypted = rsa_decrypt_base64(keypair.private_pem, encrypted);
  console.log(decrypted); // "Secret message from JavaScript"
}

run();
```

## Building for WebAssembly

To build the WebAssembly module:

```bash
wasm-pack build --release --target bundler -- --features wasm
```

## License

MIT License

## Contributing

Contributions to improve security and add features are welcome. Please see the CONTRIBUTING.md file for more information.