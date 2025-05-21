#[cfg(test)]
mod ecdh_encryption_tests {
    use rand::{RngCore, rngs::OsRng};
    use vaultic_crypto_engine::{
        EccCurve, decrypt_aes_gcm, decrypt_with_derived_key, derive_shared_secret, encrypt_aes_gcm,
        encrypt_with_derived_key, generate_ecdsa_keypair,
    };

    #[test]
    /// Test encryption and decryption with a derived key
    fn test_ecdh_aes_encryption() {
        // Alice and Bob generate key pairs
        let alice_keypair = generate_ecdsa_keypair(EccCurve::P256);
        let bob_keypair = generate_ecdsa_keypair(EccCurve::P256);

        // Alice derives a shared secret using her private key and Bob's public key
        let alice_secret = derive_shared_secret(
            &alice_keypair.private_pem,
            &bob_keypair.public_pem,
            EccCurve::P256,
        )
        .expect("Alice's shared secret derivation failed");

        // Bob derives a shared secret using his private key and Alice's public key
        let bob_secret = derive_shared_secret(
            &bob_keypair.private_pem,
            &alice_keypair.public_pem,
            EccCurve::P256,
        )
        .expect("Bob's shared secret derivation failed");

        // Verify that both derived the same secret
        assert_eq!(alice_secret.bytes, bob_secret.bytes);

        // Alice encrypts a message for Bob
        let plaintext = b"This is a secret message from Alice to Bob";
        let context_info = b"chat-session-123";

        let encrypted =
            encrypt_with_derived_key(plaintext, &alice_secret, None, Some(context_info))
                .expect("Encryption failed");

        // Bob decrypts the message
        let decrypted = decrypt_with_derived_key(&encrypted, &bob_secret, Some(context_info))
            .expect("Decryption failed");

        // Verify decryption result
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    /// Test encryption and decryption with different context info
    fn test_ecdh_aes_encryption_context() {
        // Generate key pairs
        let alice_keypair = generate_ecdsa_keypair(EccCurve::P256);
        let bob_keypair = generate_ecdsa_keypair(EccCurve::P256);

        // Derive shared secrets
        let alice_secret = derive_shared_secret(
            &alice_keypair.private_pem,
            &bob_keypair.public_pem,
            EccCurve::P256,
        )
        .expect("Alice's shared secret derivation failed");

        let bob_secret = derive_shared_secret(
            &bob_keypair.private_pem,
            &alice_keypair.public_pem,
            EccCurve::P256,
        )
        .expect("Bob's shared secret derivation failed");

        // Alice encrypts a message with context A
        let plaintext = b"Message with context A";
        let context_a = b"context-A";

        let encrypted_a = encrypt_with_derived_key(plaintext, &alice_secret, None, Some(context_a))
            .expect("Encryption with context A failed");

        // Alice encrypts a message with context B
        let context_b = b"context-B";
        let encrypted_b = encrypt_with_derived_key(plaintext, &alice_secret, None, Some(context_b))
            .expect("Encryption with context B failed");

        // Verify that different contexts produce different ciphertexts
        assert_ne!(encrypted_a.ciphertext, encrypted_b.ciphertext);

        // Bob decrypts the messages
        let decrypted_a = decrypt_with_derived_key(&encrypted_a, &bob_secret, Some(context_a))
            .expect("Decryption with context A failed");

        // Try to decrypt message A with context B (should fail)
        let result = decrypt_with_derived_key(&encrypted_a, &bob_secret, Some(context_b));
        assert!(result.is_err(), "Decryption with wrong context should fail");

        // Verify decryption result
        assert_eq!(decrypted_a, plaintext);
    }

    #[test]
    /// Test AES-GCM encryption and decryption directly
    fn test_aes_gcm_direct() {
        // Generate a random key and nonce
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut nonce);

        // Encrypt a message
        let plaintext = b"Direct AES-GCM encryption test";
        let aad = b"additional authenticated data";

        let ciphertext =
            encrypt_aes_gcm(plaintext, &key, &nonce, Some(aad)).expect("AES-GCM encryption failed");

        // Decrypt the message
        let decrypted = decrypt_aes_gcm(&ciphertext, &key, &nonce, Some(aad))
            .expect("AES-GCM decryption failed");

        // Verify decryption result
        assert_eq!(decrypted, plaintext);

        // Decrypt with wrong key
        let mut wrong_key = key.clone();
        wrong_key[0] = !wrong_key[0];

        let result = decrypt_aes_gcm(&ciphertext, &wrong_key, &nonce, Some(aad));
        assert!(result.is_err(), "Decryption with wrong key should fail");

        // Decrypt with wrong nonce
        let mut wrong_nonce = nonce.clone();
        wrong_nonce[0] = !wrong_nonce[0];

        let result = decrypt_aes_gcm(&ciphertext, &key, &wrong_nonce, Some(aad));
        assert!(result.is_err(), "Decryption with wrong nonce should fail");

        // Decrypt with wrong AAD
        let wrong_aad = b"wrong authenticated data";

        let result = decrypt_aes_gcm(&ciphertext, &key, &nonce, Some(wrong_aad));
        assert!(result.is_err(), "Decryption with wrong AAD should fail");
    }

    #[test]
    /// Test AES-GCM with large data
    fn test_aes_gcm_large_data() {
        // Generate a random key and nonce
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut nonce);

        // Create a large plaintext (1 MB)
        let plaintext = vec![0xAA; 1024 * 1024];

        // Encrypt the data
        let ciphertext =
            encrypt_aes_gcm(&plaintext, &key, &nonce, None).expect("AES-GCM encryption failed");

        // Decrypt the data
        let decrypted =
            decrypt_aes_gcm(&ciphertext, &key, &nonce, None).expect("AES-GCM decryption failed");

        // Verify decryption result
        assert_eq!(decrypted, plaintext);
    }
}
