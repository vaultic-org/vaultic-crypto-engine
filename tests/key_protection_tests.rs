#[cfg(test)]
mod key_protection_tests {
    use base64::Engine;
    use base64::engine::general_purpose;
    use std::time::{Duration, Instant};
    use vaultic_crypto_engine::*;

    /// Helper function to generate a test keypair
    fn generate_test_keypair() -> KeyPair {
        generate_keypair_impl()
    }

    /// Helper function to protect a keypair
    fn protect_and_parse(
        private_pem: &str,
        public_pem: &str,
        passphrase: &str,
    ) -> EncryptedKeypairResult {
        protect_keypair_impl(private_pem, public_pem, passphrase).unwrap()
    }

    #[test]
    /// Test basic functionality with valid inputs
    fn test_basic_protection() {
        let keypair = generate_test_keypair();
        let passphrase = "test-passphrase-123!@#";

        let result = protect_and_parse(&keypair.private_pem, &keypair.public_pem, passphrase);

        // Verify all required fields are present and non-empty
        assert!(!result.encrypted_private.is_empty());
        assert!(!result.encrypted_public.is_empty());
        assert!(!result.salt.is_empty());
        assert!(!result.nonce_private.is_empty());
        assert!(!result.nonce_public.is_empty());

        // Verify all fields are valid base64
        for field in [
            &result.encrypted_private,
            &result.encrypted_public,
            &result.salt,
            &result.nonce_private,
            &result.nonce_public,
        ]
        .iter()
        {
            let decoded = general_purpose::STANDARD.decode(field);
            assert!(decoded.is_ok(), "Field is not valid base64");
        }

        // Verify specific field lengths
        let salt = general_purpose::STANDARD.decode(&result.salt).unwrap();
        assert_eq!(salt.len(), 16, "Salt should be 16 bytes");

        let nonce_private = general_purpose::STANDARD
            .decode(&result.nonce_private)
            .unwrap();
        let nonce_public = general_purpose::STANDARD
            .decode(&result.nonce_public)
            .unwrap();
        assert_eq!(nonce_private.len(), 12, "Private nonce should be 12 bytes");
        assert_eq!(nonce_public.len(), 12, "Public nonce should be 12 bytes");
    }

    #[test]
    /// Test that different passphrases produce different ciphertexts
    fn test_passphrase_uniqueness() {
        let keypair = generate_test_keypair();
        let passphrase1 = "passphrase1";
        let passphrase2 = "passphrase2";

        let result1 = protect_and_parse(&keypair.private_pem, &keypair.public_pem, passphrase1);
        let result2 = protect_and_parse(&keypair.private_pem, &keypair.public_pem, passphrase2);

        // All encrypted fields should be different
        assert_ne!(
            result1.encrypted_private, result2.encrypted_private,
            "Different passphrases should produce different ciphertexts for private key"
        );
        assert_ne!(
            result1.encrypted_public, result2.encrypted_public,
            "Different passphrases should produce different ciphertexts for public key"
        );
        assert_ne!(
            result1.salt, result2.salt,
            "Different passphrases should use different salts"
        );
    }

    #[test]
    /// Test that the same passphrase produces different ciphertexts due to random salt/nonce
    fn test_randomness() {
        let keypair = generate_test_keypair();
        let passphrase = "same-passphrase";

        let result1 = protect_and_parse(&keypair.private_pem, &keypair.public_pem, passphrase);
        let result2 = protect_and_parse(&keypair.private_pem, &keypair.public_pem, passphrase);

        // All encrypted fields should be different due to random salt/nonce
        assert_ne!(
            result1.encrypted_private, result2.encrypted_private,
            "Same passphrase should produce different ciphertexts due to random salt/nonce"
        );
        assert_ne!(
            result1.encrypted_public, result2.encrypted_public,
            "Same passphrase should produce different ciphertexts due to random salt/nonce"
        );
        assert_ne!(
            result1.salt, result2.salt,
            "Each protection should use a different salt"
        );
        assert_ne!(
            result1.nonce_private, result2.nonce_private,
            "Each protection should use a different private nonce"
        );
        assert_ne!(
            result1.nonce_public, result2.nonce_public,
            "Each protection should use a different public nonce"
        );
    }

    #[test]
    /// Test with various passphrase lengths and characters
    fn test_passphrase_variations() {
        let keypair = generate_test_keypair();
        let passphrases = [
            "",                                   // Empty passphrase
            "a",                                  // Single character
            &"a".repeat(1000),                    // Very long passphrase
            "!@#$%^&*()_+-=[]{}|;:,.<>?/~`",      // Special characters
            "你好，世界！",                       // Unicode characters
            "🚀✨🔐",                             // Emoji
            &format!("{}\n\t\r", "a".repeat(50)), // Whitespace
        ];

        for passphrase in passphrases.iter() {
            let result = protect_and_parse(&keypair.private_pem, &keypair.public_pem, passphrase);

            // Verify all fields are present and valid
            for field in [
                &result.encrypted_private,
                &result.encrypted_public,
                &result.salt,
                &result.nonce_private,
                &result.nonce_public,
            ]
            .iter()
            {
                assert!(!field.is_empty(), "Field should not be empty");
                assert!(
                    general_purpose::STANDARD.decode(field).is_ok(),
                    "Field should be valid base64"
                );
            }
        }
    }

    #[test]
    /// Test with various key formats and sizes
    fn test_key_variations() {
        let passphrase = "test-passphrase";

        // Test with different key sizes (if supported by the library)
        let keypairs = [
            generate_test_keypair(), // Default 2048-bit
        ];

        for keypair in keypairs.iter() {
            let result = protect_and_parse(&keypair.private_pem, &keypair.public_pem, passphrase);

            // Verify encryption worked
            assert!(!result.encrypted_private.is_empty());
            assert!(!result.encrypted_public.is_empty());
        }
    }

    #[test]
    /// Test timing consistency to detect potential timing attacks
    fn test_timing_consistency() {
        let keypair = generate_test_keypair();
        let passphrase = "test-passphrase";
        let iterations = 100;
        let mut timings = Vec::with_capacity(iterations);

        // Measure protection time
        for _ in 0..iterations {
            let start = Instant::now();
            protect_keypair_impl(&keypair.private_pem, &keypair.public_pem, passphrase).unwrap();
            timings.push(start.elapsed());
        }

        // Calculate statistics
        let total: Duration = timings.iter().sum();
        let avg = total / iterations as u32;
        let max = timings.iter().max().unwrap();
        let min = timings.iter().min().unwrap();

        // Log timing information
        println!("Timing statistics for {} iterations:", iterations);
        println!("  Average: {:?}", avg);
        println!("  Min: {:?}", min);
        println!("  Max: {:?}", max);
        println!(
            "  Max/Min ratio: {:.2}",
            (max.as_nanos() as f64) / (min.as_nanos() as f64)
        );

        // Verify timing consistency
        // The ratio between max and min should not be too large
        // This is a basic check - real timing analysis would be more sophisticated
        assert!(
            (max.as_nanos() as f64) / (min.as_nanos() as f64) < 10.0,
            "Timing variation is too large, potential timing attack vulnerability"
        );
    }

    #[test]
    /// Test error handling with invalid inputs
    fn test_error_handling() {
        let valid_keypair = generate_test_keypair();
        let passphrase = "test-passphrase";

        // Test with invalid PEM formats
        let invalid_pems = [
            "",                                                                     // Empty
            "not-a-pem", // Invalid format
            "-----BEGIN PUBLIC KEY-----\ninvalid-base64\n-----END PUBLIC KEY-----", // Invalid base64
            &"a".repeat(10000),                                                     // Too long
        ];

        for invalid_pem in invalid_pems.iter() {
            let result = protect_keypair_impl(invalid_pem, &valid_keypair.public_pem, passphrase);
            assert!(
                result.is_err(),
                "Should handle invalid private PEM: {}",
                invalid_pem
            );

            let result = protect_keypair_impl(&valid_keypair.private_pem, invalid_pem, passphrase);
            assert!(
                result.is_err(),
                "Should handle invalid public PEM: {}",
                invalid_pem
            );
        }

        // Test with mismatched key pairs
        let keypair2 = generate_test_keypair();
        let result =
            protect_keypair_impl(&keypair2.private_pem, &valid_keypair.public_pem, passphrase);
        assert!(result.is_err(), "Should handle mismatched key pairs");
    }

    #[test]
    /// Test that the protected keys cannot be decrypted with wrong passphrase
    fn test_wrong_passphrase_protection() {
        let keypair = generate_test_keypair();
        let correct_passphrase = "correct-passphrase";
        let wrong_passphrase = "wrong-passphrase";

        // Protect with correct passphrase
        let protected = protect_and_parse(
            &keypair.private_pem,
            &keypair.public_pem,
            correct_passphrase,
        );

        // Verify that the protected data is different from the original
        assert_ne!(
            protected.encrypted_private, keypair.private_pem,
            "Protected private key should not match original"
        );
        assert_ne!(
            protected.encrypted_public, keypair.public_pem,
            "Protected public key should not match original"
        );

        // Try to unprotect with wrong passphrase
        let result = unprotect_keypair(&protected, wrong_passphrase);
        assert!(
            result.is_err(),
            "Unprotection with wrong passphrase should fail"
        );

        // Verify we can unprotect with correct passphrase
        let unprotect_result = unprotect_keypair(&protected, correct_passphrase).unwrap();
        assert_eq!(unprotect_result.private_pem, keypair.private_pem);
        assert_eq!(unprotect_result.public_pem, keypair.public_pem);
    }

    #[test]
    /// Test that the salt is properly used in key derivation
    fn test_salt_usage() {
        let keypair = generate_test_keypair();
        let passphrase = "test-passphrase";

        // Protect the same keypair twice
        let result1 = protect_and_parse(&keypair.private_pem, &keypair.public_pem, passphrase);
        let result2 = protect_and_parse(&keypair.private_pem, &keypair.public_pem, passphrase);

        // Get the salts
        let salt1 = general_purpose::STANDARD.decode(&result1.salt).unwrap();
        let salt2 = general_purpose::STANDARD.decode(&result2.salt).unwrap();

        // Verify salts are different
        assert_ne!(salt1, salt2, "Each protection should use a different salt");

        // Verify salt length
        assert_eq!(salt1.len(), 16, "Salt should be 16 bytes");
        assert_eq!(salt2.len(), 16, "Salt should be 16 bytes");

        // Verify salt entropy (basic check)
        let mut unique_bytes1 = std::collections::HashSet::new();
        let mut unique_bytes2 = std::collections::HashSet::new();
        for &byte in salt1.iter() {
            unique_bytes1.insert(byte);
        }
        for &byte in salt2.iter() {
            unique_bytes2.insert(byte);
        }

        // A good salt should have high entropy
        assert!(
            unique_bytes1.len() > 8,
            "Salt should have high entropy (unique bytes: {})",
            unique_bytes1.len()
        );
        assert!(
            unique_bytes2.len() > 8,
            "Salt should have high entropy (unique bytes: {})",
            unique_bytes2.len()
        );
    }
}
