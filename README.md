# vaultic-crypto-engine

`vaultic-crypto-engine` is the core Rust crate powering Vaultic’s end-to-end encryption service. It provides:

- **RSA-2048 keypair generation** in PEM format  
- **RSA-OAEP encryption & decryption**, Base64 input/output  
- **WebAssembly bindings** for browser and Node.js SDKs  
- A lightweight, audited, and memory-safe implementation  

## 🚀 Quickstart

### 1. Install via npm, pnpm or yarn (WASM build)

```bash
# npm
npm install @vaultic/crypto-engine-wasm

# or pnpm
pnpm add @vaultic/crypto-engine-wasm

# or yarn
yarn add @vaultic/crypto-engine-wasm
```

---

### 2. In your JS/TS code

```ts
import init, {
  generate_rsa_keypair_pem,
  rsa_encrypt_base64,
  rsa_decrypt_base64
} from "@vaultic/crypto-engine-wasm";

async function demo() {
  await init(); // Initialize the WASM runtime

  // 1. Generate a new keypair
  const [pubPem, privPem] = JSON.parse(generate_rsa_keypair_pem() as string);
  console.log("Public Key PEM:", pubPem);
  console.log("Private Key PEM:", privPem);

  // 2. Encrypt a message
  const ciphertext = rsa_encrypt_base64(pubPem, "Hello, Vaultic!");
  console.log("Ciphertext (Base64):", ciphertext);

  // 3. Decrypt it back
  const plaintext = rsa_decrypt_base64(privPem, ciphertext);
  console.log("Decrypted message:", plaintext);
}

demo();
```

---

## 📦 Repository Layout

```
vaultic-crypto-engine/
├─ src/
│   └─ lib.rs           # Core RSA-OAEP functions + wasm-bindgen exports
├─ Cargo.toml           # Crate metadata and dependencies
├─ README.md            # This file
└─ LICENSE              # MIT or your chosen license
```

---

## 🛠️ Building & Testing

1. **Build native Rust library**

   ```bash
   cargo build --release
   ```

2. **Run Rust unit tests**

   ```bash
   cargo test
   ```

3. **Build WASM package**

   ```bash
   wasm-pack build --target bundler --out-dir ../packages/crypto-engine-wasm
   ```

---

## 🔒 Security & Auditing

* Uses `rsa` crate for RSA-OAEP with SHA-256 padding
* Randomness from `OsRng` (Operating-system CSPRNG)
* No secret keys are logged or stored by default

---

## ❤️ Contributing

1. Fork the repo
2. Create a branch (`git checkout -b feat/your-feature`)
3. Implement and test
4. Submit a Pull Request

---

## 📄 License

[MIT License](LICENSE)

---

*Built for Vaultic’s E2EE service — keeping your data private by design.*
