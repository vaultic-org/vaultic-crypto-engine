# Vaultic Crypto Engine

A high-performance cryptographic library for secure RSA operations with support for both native Rust and WebAssembly environments.

## 🔐 New Features (v0.1.5)

- **Improved code structure**: modular architecture for better maintainability
- **Key pair protection**: encrypt and decrypt RSA key pairs with password protection
- **Message protection**: protect messages with AES-256-GCM and password-based key derivation
- **Cryptographic utilities**: reusable functions for common operations
  - Base64 encoding/decoding utilities
  - Secure random generation for cryptographic material
  - PBKDF2 key derivation with SHA-256
  - AES cipher creation helpers
  - Cross-platform timestamp generators

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
- 🔐 Key pair protection/unprotection with password
- 🔏 Message protection/unprotection with password
- 🧰 Cryptographic utilities for AES key derivation and random generation
- 📦 Base64 encoding/decoding for easy transport
- 🌐 WebAssembly support for browser environments

## Installation

### Rust

Add this to your `Cargo.toml`:

```toml
[dependencies]
vaultic-crypto-engine = "0.1.5"
```

For WebAssembly support, enable the `wasm` feature:

```toml
[dependencies]
vaultic-crypto-engine = { version = "0.1.5", features = ["wasm"] }
```

### JavaScript/TypeScript

#### npm
```bash
npm install @vaultic/crypto-engine
```

#### yarn
```bash
yarn add @vaultic/crypto-engine
```

#### pnpm
```bash
pnpm add @vaultic/crypto-engine
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

### Key Pair Protection

```rust
use vaultic_crypto_engine::{generate_rsa_keypair_pem, protect_keypair, unprotect_keypair};

fn main() {
    // Generate a key pair
    let keypair = generate_rsa_keypair_pem();
    
    // Protect the key pair with a passphrase
    let passphrase = "my-secure-passphrase";
    let protected = protect_keypair(&keypair.private_pem, &keypair.public_pem, passphrase);
    
    // The protected keypair can be safely stored
    println!("Protected Private Key: {}", protected.encrypted_private);
    println!("Salt: {}", protected.salt);
    
    // Later, unprotect the keypair with the passphrase
    let recovered = unprotect_keypair(&protected, passphrase).expect("Failed to unprotect keypair");
    
    // Verify the keys match
    assert_eq!(keypair.private_pem, recovered.private_pem);
    assert_eq!(keypair.public_pem, recovered.public_pem);
}
```

### Message Protection

```rust
use vaultic_crypto_engine::{protect_message, unprotect_message};

fn main() {
    let message = "Secret message protected with password";
    let passphrase = "my-secure-passphrase";
    
    // Protect the message with a passphrase
    let protected = protect_message(message, passphrase);
    
    // The protected message can be safely stored or transmitted
    println!("Protected Message: {}", protected.ciphertext);
    println!("Salt: {}", protected.salt);
    println!("Nonce: {}", protected.nonce);
    
    // Later, unprotect the message with the passphrase
    let recovered = unprotect_message(&protected, passphrase).expect("Failed to unprotect message");
    
    // Verify the message matches
    assert_eq!(message, recovered);
}
```

### WebAssembly Usage

When compiled to WebAssembly, the library can be used from JavaScript:

```javascript
import init, { 
  generate_rsa_keypair_pem, 
  rsa_encrypt_base64, 
  rsa_decrypt_base64,
  protect_keypair,
  unprotect_keypair,
  protect_message,
  unprotect_message
} from 'vaultic-crypto-engine';

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
  
  // Protect a keypair with a password
  const passphrase = "secure-password-123";
  const protectedKeypair = protect_keypair(keypair.private_pem, keypair.public_pem, passphrase);
  
  // Unprotect the keypair later
  const recoveredKeypair = unprotect_keypair(protectedKeypair, passphrase);
  
  // Protect a message with a password
  const sensitiveMessage = "Secret message protected with password";
  const protectedMessage = protect_message(sensitiveMessage, passphrase);
  
  // Unprotect the message later
  const recoveredMessage = unprotect_message(protectedMessage, passphrase);
  console.log(recoveredMessage); // "Secret message protected with password"
}

run();
```

## Technical Details

### How Hybrid Encryption Works

For small messages (≤ 245 bytes), we use direct RSA encryption with PKCS#1 v1.5 padding.

For larger messages, we use a hybrid approach:
1. Generate a random AES-256 key
2. Encrypt the message with AES-GCM
3. Encrypt the AES key with RSA
4. Encode all this information in a special JSON format which is then Base64 encoded

Decryption automatically detects the format used and applies the correct algorithm.

### Password-Based Protection

For protecting keys and messages with passwords:
1. A cryptographically secure random salt (16 bytes) is generated
2. The password is used with PBKDF2-HMAC-SHA256 (100,000 iterations) to derive a key
3. AES-256-GCM is used with a random nonce (12 bytes) to encrypt the data
4. The salt, nonce, and encrypted data are encoded in Base64 for storage/transport

### Utility Functions

The library provides several utility functions:
- Base64 encoding/decoding
- Secure random generation for salts, nonces and keys
- Key derivation with PBKDF2
- AES cipher creation
- Cross-platform timestamp generators

## Building for WebAssembly

To build the WebAssembly module:

```bash
wasm-pack build --release --target bundler -- --features wasm
```

## License

MIT License

## Contributing

Contributions to improve security and add features are welcome. Please see the CONTRIBUTING.md file for more information.