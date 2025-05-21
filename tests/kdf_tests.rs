#[cfg(test)]
mod kdf_tests {
    use vaultic_crypto_engine::{
        EccCurve, derive_key_hkdf, derive_key_pbkdf2, derive_shared_secret, generate_ecdsa_keypair,
    };

    #[test]
    /// Test PBKDF2 key derivation
    fn test_pbkdf2() {
        let password = b"test-password";
        let salt = b"test-salt-12345678";
        let iterations = 10_000;
        let key_length = 32;

        // Derive a key
        let key = derive_key_pbkdf2(password, salt, iterations, key_length)
            .expect("PBKDF2 key derivation failed");

        // Check key length
        assert_eq!(key.len(), key_length);

        // Derive the key again with the same parameters
        let key2 = derive_key_pbkdf2(password, salt, iterations, key_length)
            .expect("PBKDF2 key derivation failed");

        // Verify that the keys match
        assert_eq!(key, key2);

        // Derive a key with different parameters
        let key3 = derive_key_pbkdf2(password, b"different-salt-12345", iterations, key_length)
            .expect("PBKDF2 key derivation failed");

        // Verify that the keys are different
        assert_ne!(key, key3);
    }

    #[test]
    /// Test PBKDF2 with invalid parameters
    fn test_pbkdf2_invalid_params() {
        let password = b"test-password";
        let salt = b"test-salt-12345678";
        let iterations = 10_000;

        // Test with empty password
        let result = derive_key_pbkdf2(b"", salt, iterations, 32);
        assert!(result.is_err());

        // Test with short salt
        let result = derive_key_pbkdf2(password, b"short", iterations, 32);
        assert!(result.is_err());

        // Test with low iterations
        let result = derive_key_pbkdf2(password, salt, 100, 32);
        assert!(result.is_err());

        // Test with invalid key length
        let result = derive_key_pbkdf2(password, salt, iterations, 8);
        assert!(result.is_err());
    }

    #[test]
    /// Test HKDF key derivation
    fn test_hkdf() {
        let ikm = b"input-key-material";
        let salt = b"hkdf-salt-12345678";
        let info = b"context-info";
        let key_length = 32;

        // Derive a key
        let key = derive_key_hkdf(ikm, Some(salt), Some(info), key_length)
            .expect("HKDF key derivation failed");

        // Check key length
        assert_eq!(key.len(), key_length);

        // Derive the key again with the same parameters
        let key2 = derive_key_hkdf(ikm, Some(salt), Some(info), key_length)
            .expect("HKDF key derivation failed");

        // Verify that the keys match
        assert_eq!(key, key2);

        // Derive a key with different salt
        let key3 = derive_key_hkdf(ikm, Some(b"different-salt-123"), Some(info), key_length)
            .expect("HKDF key derivation failed");

        // Verify that the keys are different
        assert_ne!(key, key3);

        // Derive a key with different info
        let key4 = derive_key_hkdf(ikm, Some(salt), Some(b"different-info"), key_length)
            .expect("HKDF key derivation failed");

        // Verify that the keys are different
        assert_ne!(key, key4);
    }

    #[test]
    /// Test HKDF with invalid parameters
    fn test_hkdf_invalid_params() {
        let salt = b"hkdf-salt-12345678";
        let info = b"context-info";

        // Test with empty IKM
        let result = derive_key_hkdf(b"", Some(salt), Some(info), 32);
        assert!(result.is_err());

        // Test with invalid key length
        let result = derive_key_hkdf(b"input-key-material", Some(salt), Some(info), 8);
        assert!(result.is_err());
    }

    #[test]
    /// Test HKDF with shared secret
    fn test_hkdf_with_shared_secret() {
        // Generate key pairs
        let alice_keypair = generate_ecdsa_keypair(EccCurve::P256);
        let bob_keypair = generate_ecdsa_keypair(EccCurve::P256);

        // Derive shared secrets
        let alice_secret = derive_shared_secret(
            &alice_keypair.private_pem,
            &bob_keypair.public_pem,
            EccCurve::P256,
        )
        .expect("Shared secret derivation failed");

        let bob_secret = derive_shared_secret(
            &bob_keypair.private_pem,
            &alice_keypair.public_pem,
            EccCurve::P256,
        )
        .expect("Shared secret derivation failed");

        // Verify that the shared secrets match
        assert_eq!(alice_secret.bytes, bob_secret.bytes);

        // Use HKDF to derive keys from the shared secrets
        let alice_key = derive_key_hkdf(
            &alice_secret.bytes,
            Some(b"salt-12345678"),
            Some(b"context-info"),
            32,
        )
        .expect("HKDF key derivation failed");

        let bob_key = derive_key_hkdf(
            &bob_secret.bytes,
            Some(b"salt-12345678"),
            Some(b"context-info"),
            32,
        )
        .expect("HKDF key derivation failed");

        // Verify that the derived keys match
        assert_eq!(alice_key, bob_key);
    }
}
