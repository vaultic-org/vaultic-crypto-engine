# Vaultic Crypto Engine

A high-performance cryptographic library for secure RSA and ECC operations with support for both native Rust and WebAssembly environments.

## 🔐 New Features (v0.1.6)

- **ECC Support**: Added ECDSA signing/verification (P-256, K-256) and ECDH key agreement (P-256, K-256).
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
- ✒️ ECDSA signing and verification (P-256/secp256r1 and K-256/secp256k1)
- 🤝 ECDH shared secret derivation (P-256/secp256r1 and K-256/secp256k1)
- 🔐 Key pair protection/unprotection with password (currently RSA only)
- 🔏 Message protection/unprotection with password
- 🛡️ AES-GCM encryption/decryption with derived keys (from ECDH or passphrase)
- 🔑 Key Derivation Functions: HKDF and PBKDF2
- 🧰 Cryptographic utilities for AES key derivation and random generation
- 📦 Base64 encoding/decoding for easy transport
- 🌐 WebAssembly support for browser environments

## Installation

### Rust

Add this to your `Cargo.toml`:

```toml
[dependencies]
vaultic-crypto-engine = "0.1.6"
```

For WebAssembly support, enable the `wasm` feature:

```toml
[dependencies]
vaultic-crypto-engine = { version = "0.1.6", features = ["wasm"] }
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

### ECDSA Signing and Verification

```rust
use vaultic_crypto_engine::{generate_ecdsa_keypair, ecdsa_sign, ecdsa_verify};
use vaultic_crypto_engine::models::EccCurve; // Make sure EccCurve is in models and public

fn main() {
    // Generate an ECDSA key pair (e.g., P-256)
    let keypair_p256 = generate_ecdsa_keypair(EccCurve::P256);
    
    let message = b"This is a message to sign with ECDSA";
    
    // Sign the message
    let signature = ecdsa_sign(message, &keypair_p256.private_pem, EccCurve::P256)
        .expect("ECDSA signing failed");
    
    println!("Signature (P-256): {:?}", signature.bytes);
    
    // Verify the signature
    let is_valid = ecdsa_verify(message, &signature, &keypair_p256.public_pem)
        .expect("ECDSA verification failed");
        
    assert!(is_valid);
    println!("P-256 signature is valid: {}", is_valid);

    // Example with K-256 (secp256k1)
    let keypair_k256 = generate_ecdsa_keypair(EccCurve::K256);
    let signature_k256 = ecdsa_sign(message, &keypair_k256.private_pem, EccCurve::K256)
        .expect("K-256 signing failed");
    let is_valid_k256 = ecdsa_verify(message, &signature_k256, &keypair_k256.public_pem)
        .expect("K-256 verification failed");
    assert!(is_valid_k256);
    println!("K-256 signature is valid: {}", is_valid_k256);
}
```

### ECDH Key Agreement

```rust
use vaultic_crypto_engine::{generate_ecdsa_keypair, derive_shared_secret};
use vaultic_crypto_engine::models::EccCurve; // Make sure EccCurve is in models and public

fn main() {
    // Party A generates a P-256 key pair
    let party_a_keypair = generate_ecdsa_keypair(EccCurve::P256);
    
    // Party B generates a P-256 key pair
    let party_b_keypair = generate_ecdsa_keypair(EccCurve::P256);
    
    // Party A derives shared secret using their private key and Party B's public key
    let shared_secret_a = derive_shared_secret(
        &party_a_keypair.private_pem,
        &party_b_keypair.public_pem,
        EccCurve::P256
    ).expect("ECDH for Party A failed");
    
    // Party B derives shared secret using their private key and Party A's public key
    let shared_secret_b = derive_shared_secret(
        &party_b_keypair.private_pem,
        &party_a_keypair.public_pem,
        EccCurve::P256
    ).expect("ECDH for Party B failed");
    
    // The shared secrets must be identical
    assert_eq!(shared_secret_a.bytes, shared_secret_b.bytes);
    println!("Shared secret (P-256) derived successfully and matches!");

    // You can then use this shared secret with a KDF (like HKDF) to derive an encryption key
    // For example, using vaultic_crypto_engine::encrypt_with_derived_key
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

When compiled to WebAssembly, the library can be used from JavaScript. First, ensure you initialize the WASM module:

```javascript
import init, {
  // Import specific functions you need for each use case
  generate_rsa_keypair_pem, 
  rsa_encrypt_base64, 
  rsa_decrypt_base64,
  generate_ecdsa_keypair_wasm,
  WasmEccCurve,
  ecdsa_sign_p256_wasm,
  ecdsa_verify_p256_wasm,
  ecdsa_sign_k256_wasm,
  ecdsa_verify_k256_wasm,
  derive_p256_shared_secret_wasm,
  derive_k256_shared_secret_wasm,
  encrypt_with_shared_secret_wasm,
  decrypt_with_shared_secret_wasm,
  protect_keypair,
  unprotect_keypair,
  protect_message,
  unprotect_message
} from 'vaultic-crypto-engine';

async function initializeWasm() {
  await init();
}

// Call initialization once
initializeWasm();
```

Below are examples for specific use cases. Ensure `initializeWasm()` has been called before running these snippets.

**1. RSA Key Generation, Encryption, and Decryption**

```javascript
// Assuming init() has been called

// Generate an RSA key pair
const rsaKeypair = generate_rsa_keypair_pem();
console.log("RSA Public Key:", rsaKeypair.public_pem);

// Encrypt an RSA message
const rsaMessage = "Secret message for RSA from JavaScript...";
const rsaEncrypted = rsa_encrypt_base64(rsaKeypair.public_pem, rsaMessage);
console.log("RSA Encrypted:", rsaEncrypted);

// Decrypt the RSA message
const rsaDecrypted = rsa_decrypt_base64(rsaKeypair.private_pem, rsaEncrypted);
console.log("RSA Decrypted:", rsaDecrypted);
```

**2. ECDSA Key Generation, Signing, and Verification (P-256)**

```javascript
// Assuming init() has been called

// Generate an ECDSA P-256 key pair
const p256Keypair = generate_ecdsa_keypair_wasm(WasmEccCurve.P256);
console.log("P256 Public Key:", p256Keypair.public_pem);

// Sign a message with ECDSA P-256
const messageToSignP256 = "Hello from ECDSA P-256 in WASM!";
const p256Signature = ecdsa_sign_p256_wasm(messageToSignP256, p256Keypair.private_pem);
console.log("P256 Signature:", p256Signature);

// Verify the P-256 signature
const isP256Valid = ecdsa_verify_p256_wasm(messageToSignP256, p256Signature, p256Keypair.public_pem);
console.log("Is P256 Signature Valid?", isP256Valid);
```

**3. ECDSA Key Generation, Signing, and Verification (K-256)**

```javascript
// Assuming init() has been called

// Generate an ECDSA K-256 key pair
const k256Keypair = generate_ecdsa_keypair_wasm(WasmEccCurve.K256);
console.log("K256 Public Key:", k256Keypair.public_pem);

// Sign a message with ECDSA K-256
const messageToSignK256 = "Hello from ECDSA K-256 in WASM!";
const k256Signature = ecdsa_sign_k256_wasm(messageToSignK256, k256Keypair.private_pem);
console.log("K256 Signature:", k256Signature);

// Verify the K-256 signature
const isK256Valid = ecdsa_verify_k256_wasm(messageToSignK256, k256Signature, k256Keypair.public_pem);
console.log("Is K256 Signature Valid?", isK256Valid);
```

**4. ECDH Key Agreement (P-256) and AES Encryption/Decryption**

```javascript
// Assuming init() has been called

// ECDH with P-256
const ecdhPartyA_P256 = generate_ecdsa_keypair_wasm(WasmEccCurve.P256);
const ecdhPartyB_P256 = generate_ecdsa_keypair_wasm(WasmEccCurve.P256);

const sharedSecretA_P256 = derive_p256_shared_secret_wasm(ecdhPartyA_P256.private_pem, ecdhPartyB_P256.public_pem);
const sharedSecretB_P256 = derive_p256_shared_secret_wasm(ecdhPartyB_P256.private_pem, ecdhPartyA_P256.public_pem);

// Verify shared secrets match (developer check, not typically exposed to end user like this)
if (JSON.stringify(sharedSecretA_P256.bytes) !== JSON.stringify(sharedSecretB_P256.bytes)) {
  console.error("P-256 Shared secrets do not match!");
} else {
  console.log("P-256 Shared secrets derived successfully and match.");
}

// Encrypt data using the derived shared secret (Party A's perspective)
const plaintextForECDH_P256 = "Encrypt me with a key from P-256 ECDH!";
const infoContextP256 = "p256-encryption-context"; // Optional context for HKDF

const encryptedWithP256SharedKey = encrypt_with_shared_secret_wasm(plaintextForECDH_P256, sharedSecretA_P256, infoContextP256);
console.log("Encrypted with P256 ECDH shared key:", encryptedWithP256SharedKey);

// Decrypt data using the derived shared secret (Party B's perspective, using their derived secret)
const decryptedWithP256SharedKey = decrypt_with_shared_secret_wasm(encryptedWithP256SharedKey, sharedSecretB_P256, infoContextP256);
console.log("Decrypted with P256 ECDH shared key:", decryptedWithP256SharedKey);
```

**5. ECDH Key Agreement (K-256) and AES Encryption/Decryption**

```javascript
// Assuming init() has been called

// ECDH with K-256
const ecdhPartyA_K256 = generate_ecdsa_keypair_wasm(WasmEccCurve.K256);
const ecdhPartyB_K256 = generate_ecdsa_keypair_wasm(WasmEccCurve.K256);

const sharedSecretA_K256 = derive_k256_shared_secret_wasm(ecdhPartyA_K256.private_pem, ecdhPartyB_K256.public_pem);
const sharedSecretB_K256 = derive_k256_shared_secret_wasm(ecdhPartyB_K256.private_pem, ecdhPartyA_K256.public_pem);

// Verify shared secrets match
if (JSON.stringify(sharedSecretA_K256.bytes) !== JSON.stringify(sharedSecretB_K256.bytes)) {
  console.error("K-256 Shared secrets do not match!");
} else {
  console.log("K-256 Shared secrets derived successfully and match.");
}

// Encrypt data using the derived shared secret (Party A's perspective)
const plaintextForECDH_K256 = "Encrypt me with a key from K-256 ECDH!";
const infoContextK256 = "k256-encryption-context"; // Optional context for HKDF

const encryptedWithK256SharedKey = encrypt_with_shared_secret_wasm(plaintextForECDH_K256, sharedSecretA_K256, infoContextK256);
console.log("Encrypted with K256 ECDH shared key:", encryptedWithK256SharedKey);

// Decrypt data using the derived shared secret (Party B's perspective)
const decryptedWithK256SharedKey = decrypt_with_shared_secret_wasm(encryptedWithK256SharedKey, sharedSecretB_K256, infoContextK256);
console.log("Decrypted with K256 ECDH shared key:", decryptedWithK256SharedKey);
```

**6. Key Pair Protection (Passphrase-based)**

```javascript
// Assuming init() has been called

// Example with an RSA keypair, but could be any PEM keypair
const keypairToProtect = generate_rsa_keypair_pem(); 
const passphraseForKeyProtection = "my-strong-password-for-keys";

const protectedKeypair = protect_keypair(keypairToProtect.private_pem, keypairToProtect.public_pem, passphraseForKeyProtection);
console.log("Protected Key (Private):", protectedKeypair.encrypted_private);
console.log("Protected Key (Salt):", protectedKeypair.salt);

// Unprotect the keypair later
const recoveredKeypair = unprotect_keypair(protectedKeypair, passphraseForKeyProtection);
console.log("Recovered Private Key PEM matches original:", recoveredKeypair.private_pem === keypairToProtect.private_pem);
```

**7. Message Protection (Passphrase-based)**

```javascript
// Assuming init() has been called

const sensitiveMessage = "This is a very secret message to protect with a password.";
const passphraseForMessage = "another-secure-password!@#";

const protectedMessage = protect_message(sensitiveMessage, passphraseForMessage);
console.log("Protected Message (Ciphertext):", protectedMessage.ciphertext);

// Unprotect the message later
const recoveredMessage = unprotect_message(protectedMessage, passphraseForMessage);
console.log("Recovered Message:", recoveredMessage);
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