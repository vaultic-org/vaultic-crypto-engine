#[cfg(test)]
mod ecc_tests {
    use vaultic_crypto_engine::{
        EccCurve, decrypt_with_derived_key, derive_shared_secret, ecdsa_sign, ecdsa_verify,
        encrypt_with_derived_key, generate_ecdsa_keypair,
    };

    #[test]
    /// Test ECDSA key generation for P-256
    fn test_p256_key_generation() {
        let keypair = generate_ecdsa_keypair(EccCurve::P256);

        // Verify that keys are in PEM format
        assert!(keypair.public_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert!(keypair.public_pem.ends_with("-----END PUBLIC KEY-----\n"));
        assert!(
            keypair
                .private_pem
                .starts_with("-----BEGIN PRIVATE KEY-----")
        );
        assert!(keypair.private_pem.ends_with("-----END PRIVATE KEY-----\n"));

        // Verify curve
        assert_eq!(keypair.curve, EccCurve::P256);
    }

    #[test]
    /// Test ECDSA key generation for K-256
    fn test_k256_key_generation() {
        let keypair = generate_ecdsa_keypair(EccCurve::K256);

        // Verify that keys are in PEM format
        assert!(keypair.public_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert!(keypair.public_pem.ends_with("-----END PUBLIC KEY-----\n"));
        assert!(
            keypair
                .private_pem
                .starts_with("-----BEGIN PRIVATE KEY-----")
        );
        assert!(keypair.private_pem.ends_with("-----END PRIVATE KEY-----\n"));

        // Verify curve
        assert_eq!(keypair.curve, EccCurve::K256);
    }

    #[test]
    /// Test ECDSA signing and verification for P-256
    fn test_p256_sign_verify() {
        let keypair = generate_ecdsa_keypair(EccCurve::P256);
        let message = b"Hello, world!";

        // Sign the message
        let signature =
            ecdsa_sign(message, &keypair.private_pem, EccCurve::P256).expect("Signing failed");

        // Verify the signature
        let is_valid =
            ecdsa_verify(message, &signature, &keypair.public_pem).expect("Verification failed");

        assert!(is_valid, "Signature verification should succeed");

        // Test with wrong message
        let wrong_message = b"Wrong message";
        let is_valid = ecdsa_verify(wrong_message, &signature, &keypair.public_pem)
            .expect("Verification failed");

        assert!(
            !is_valid,
            "Signature verification should fail with wrong message"
        );
    }

    #[test]
    /// Test ECDSA signing and verification for K-256
    fn test_k256_sign_verify() {
        let keypair = generate_ecdsa_keypair(EccCurve::K256);
        let message = b"Hello, world!";

        // Sign the message
        let signature =
            ecdsa_sign(message, &keypair.private_pem, EccCurve::K256).expect("Signing failed");

        // Verify the signature
        let is_valid =
            ecdsa_verify(message, &signature, &keypair.public_pem).expect("Verification failed");

        assert!(is_valid, "Signature verification should succeed");

        // Test with wrong message
        let wrong_message = b"Wrong message";
        let is_valid = ecdsa_verify(wrong_message, &signature, &keypair.public_pem)
            .expect("Verification failed");

        assert!(
            !is_valid,
            "Signature verification should fail with wrong message"
        );
    }

    #[test]
    /// Test ECDH key agreement for P-256
    fn test_p256_shared_secret() {
        let alice_keypair = generate_ecdsa_keypair(EccCurve::P256);
        let bob_keypair = generate_ecdsa_keypair(EccCurve::P256);

        // Alice derives shared secret using her private key and Bob's public key
        let alice_secret = derive_shared_secret(
            &alice_keypair.private_pem,
            &bob_keypair.public_pem,
            EccCurve::P256,
        )
        .expect("Alice's shared secret derivation failed");

        // Bob derives shared secret using his private key and Alice's public key
        let bob_secret = derive_shared_secret(
            &bob_keypair.private_pem,
            &alice_keypair.public_pem,
            EccCurve::P256,
        )
        .expect("Bob's shared secret derivation failed");

        // Verify that both derived the same secret
        assert_eq!(alice_secret.bytes, bob_secret.bytes);
        assert_eq!(alice_secret.curve, EccCurve::P256);
        assert_eq!(bob_secret.curve, EccCurve::P256);
    }

    #[test]
    /// Test ECDH key agreement for K-256
    fn test_k256_shared_secret() {
        let alice_keypair = generate_ecdsa_keypair(EccCurve::K256);
        let bob_keypair = generate_ecdsa_keypair(EccCurve::K256);

        // Alice derives shared secret using her private key and Bob's public key
        let alice_secret = derive_shared_secret(
            &alice_keypair.private_pem,
            &bob_keypair.public_pem,
            EccCurve::K256,
        )
        .expect("Alice's shared secret derivation failed");

        // Bob derives shared secret using his private key and Alice's public key
        let bob_secret = derive_shared_secret(
            &bob_keypair.private_pem,
            &alice_keypair.public_pem,
            EccCurve::K256,
        )
        .expect("Bob's shared secret derivation failed");

        // Verify that both derived the same secret
        assert_eq!(alice_secret.bytes, bob_secret.bytes);
        assert_eq!(alice_secret.curve, EccCurve::K256);
        assert_eq!(bob_secret.curve, EccCurve::K256);
    }

    #[test]
    /// Test encryption and decryption with ECDH-derived key
    fn test_encryption_with_shared_secret() {
        let alice_keypair = generate_ecdsa_keypair(EccCurve::P256);
        let bob_keypair = generate_ecdsa_keypair(EccCurve::P256);

        // Alice and Bob derive shared secrets
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

        // Alice encrypts a message using the shared secret
        let plaintext = b"Secret message from Alice to Bob";
        let encrypted =
            encrypt_with_derived_key(plaintext, &alice_secret, None, Some(b"Alice and Bob"))
                .expect("Encryption failed");

        // Bob decrypts the message using his derived shared secret
        let decrypted = decrypt_with_derived_key(&encrypted, &bob_secret, Some(b"Alice and Bob"))
            .expect("Decryption failed");

        // Verify the decrypted message matches the original
        assert_eq!(decrypted, plaintext);

        // Test with wrong context info
        let result = decrypt_with_derived_key(&encrypted, &bob_secret, Some(b"Wrong context"));

        assert!(result.is_err(), "Decryption with wrong context should fail");
    }

    #[test]
    /// Test cross-curve compatibility (should fail)
    fn test_cross_curve_incompatibility() {
        let p256_keypair = generate_ecdsa_keypair(EccCurve::P256);
        let k256_keypair = generate_ecdsa_keypair(EccCurve::K256);

        // Try to derive a shared secret between different curves
        let result = derive_shared_secret(
            &p256_keypair.private_pem,
            &k256_keypair.public_pem,
            EccCurve::P256,
        );

        assert!(
            result.is_err(),
            "Deriving a shared secret between different curves should fail"
        );
    }
}
