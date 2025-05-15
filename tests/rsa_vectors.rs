#[cfg(test)]
mod rsa_test_vectors {
    use vaultic_crypto_engine::{generate_rsa_keypair_pem, rsa_decrypt_base64, rsa_encrypt_base64};

    const TEST_MESSAGES: [&str; 3] = [
        "",                                                     // Empty string
        "Hello, World!",                                        // Simple ASCII
        "Special characters: !@#$%^&*()_+{}|:<>?~`-=[]\\;',./", // Special characters
    ];

    #[test]
    fn test_encrypt_decrypt_cycle_with_vectors() {
        // Generate a key pair for testing
        let keypair = generate_rsa_keypair_pem();

        // Test each vector
        for &message in TEST_MESSAGES.iter() {
            // Encrypt the message
            let encrypted = rsa_encrypt_base64(&keypair.public_pem, message);

            // Verify non-empty result
            assert!(!encrypted.is_empty());

            // Decrypt the message
            let decrypted = rsa_decrypt_base64(&keypair.private_pem, &encrypted);

            // Verify the result matches the original
            assert_eq!(decrypted, message);
        }
    }

    #[test]
    fn test_different_key_pairs() {
        // Generate two different key pairs
        let keypair1 = generate_rsa_keypair_pem();
        let keypair2 = generate_rsa_keypair_pem();

        // Verify the key pairs are different
        assert_ne!(keypair1.public_pem, keypair2.public_pem);
        assert_ne!(keypair1.private_pem, keypair2.private_pem);

        // Test encryption/decryption with the first key pair
        let message = "Test message";
        let encrypted = rsa_encrypt_base64(&keypair1.public_pem, message);

        // Attempt to decrypt with second key pair should fail
        let result =
            std::panic::catch_unwind(|| rsa_decrypt_base64(&keypair2.private_pem, &encrypted));

        // Verify decryption fails with the wrong key
        assert!(result.is_err());
    }
}
