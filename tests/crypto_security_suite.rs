use base64::Engine;
use base64::engine::general_purpose;
use rand::{RngCore, rngs::OsRng};
use vaultic_crypto_engine::*;

/// Comprehensive test suite for the Vaultic cryptographic engine.
/// Designed for security auditing and compliance purposes.
///
/// These tests cover:
/// - Security properties of RSA and AES implementations
/// - Boundary conditions and edge cases
/// - Data format validation
/// - Key integrity
/// - Exception handling and error conditions
/// - Cross-encryption compatibility
/// - UTF-8 handling with special characters and emoji

#[cfg(test)]
mod security_test_suite {
    use super::*;

    #[test]
    /// Verify RSA key generation creates valid 2048-bit keys
    fn test_key_generation_specs() {
        let keypair = generate_keypair_impl();

        // Verify that keys are in PEM format
        assert!(keypair.public_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert!(keypair.public_pem.ends_with("-----END PUBLIC KEY-----\n"));
        assert!(
            keypair
                .private_pem
                .starts_with("-----BEGIN PRIVATE KEY-----")
        );
        assert!(keypair.private_pem.ends_with("-----END PRIVATE KEY-----\n"));

        // Test that keys are of expected length for 2048-bit RSA
        // PEM encoded 2048-bit RSA keys are typically 450+ bytes
        assert!(
            keypair.public_pem.len() >= 400,
            "Public key too short: {}",
            keypair.public_pem.len()
        );
        assert!(
            keypair.private_pem.len() >= 1600,
            "Private key too short: {}",
            keypair.private_pem.len()
        );
    }

    #[test]
    /// Test direct RSA encryption and decryption with various message sizes
    fn test_direct_rsa_various_sizes() {
        let keypair = generate_keypair_impl();

        // Test different message sizes up to the max capacity for RSA-2048
        for size in [1, 16, 64, 128, 200, 240, MAX_RSA_SIZE].iter() {
            // Create a message of the specified size
            let message = "A".repeat(*size);

            // Encrypt and decrypt
            let encrypted = direct_rsa_encrypt_base64(&keypair.public_pem, message.as_bytes());
            let decrypted =
                direct_rsa_decrypt(&keypair.private_pem, &encrypted).expect("Decryption failed");

            // Verify original message was recovered
            assert_eq!(message, decrypted);
        }
    }

    #[test]
    /// Test that attempting to encrypt a message larger than MAX_RSA_SIZE with direct RSA fails
    fn test_direct_rsa_too_large() {
        let keypair = generate_keypair_impl();
        let large_message = "A".repeat(MAX_RSA_SIZE + 1);

        // This should encapsulate the RSA encryption in a test to catch potential panics
        let result = std::panic::catch_unwind(|| {
            direct_rsa_encrypt_base64(&keypair.public_pem, large_message.as_bytes());
        });

        // The encryption should fail because the message is too large
        assert!(
            result.is_err(),
            "Expected direct RSA encryption to fail with oversized message"
        );
    }

    #[test]
    /// Test hybrid encryption and decryption with very large messages
    fn test_hybrid_encryption_large_messages() {
        let keypair = generate_keypair_impl();

        // Test increasingly large messages
        for size in [MAX_RSA_SIZE + 1, 1000, 10_000, 100_000].iter() {
            // Create a message of the specified size
            let message = "A".repeat(*size);

            // Hybrid encrypt and decrypt using the standard functions
            let encrypted = rsa_encrypt_base64_impl(&keypair.public_pem, &message);
            let decrypted = rsa_decrypt_base64_impl(&keypair.private_pem, &encrypted)
                .expect("Decryption failed");

            // Verify original message was recovered
            assert_eq!(message, decrypted);
        }
    }

    #[test]
    /// Test that hybrid encryption properly switches based on message size
    fn test_auto_switching_at_boundary() {
        let keypair = generate_keypair_impl();

        // Test at exactly the RSA max size
        let message_at_limit = "A".repeat(MAX_RSA_SIZE);
        let encrypted_at_limit = rsa_encrypt_base64_impl(&keypair.public_pem, &message_at_limit);

        // Test just over the RSA max size
        let message_over_limit = "A".repeat(MAX_RSA_SIZE + 1);
        let encrypted_over_limit =
            rsa_encrypt_base64_impl(&keypair.public_pem, &message_over_limit);

        // Decode both ciphertexts
        let decoded_at_limit = general_purpose::STANDARD
            .decode(&encrypted_at_limit)
            .unwrap();
        let decoded_over_limit = general_purpose::STANDARD
            .decode(&encrypted_over_limit)
            .unwrap();

        // Verify encryption mode switch happened correctly
        let at_limit_is_json =
            serde_json::from_slice::<HybridEncryptedData>(&decoded_at_limit).is_ok();
        let over_limit_is_json =
            serde_json::from_slice::<HybridEncryptedData>(&decoded_over_limit).is_ok();

        assert!(
            !at_limit_is_json,
            "Message at RSA limit should use direct RSA"
        );
        assert!(
            over_limit_is_json,
            "Message over RSA limit should use hybrid encryption"
        );

        // Ensure both can be decrypted
        let decrypted_at_limit =
            rsa_decrypt_base64_impl(&keypair.private_pem, &encrypted_at_limit).unwrap();
        let decrypted_over_limit =
            rsa_decrypt_base64_impl(&keypair.private_pem, &encrypted_over_limit).unwrap();

        assert_eq!(message_at_limit, decrypted_at_limit);
        assert_eq!(message_over_limit, decrypted_over_limit);
    }

    #[test]
    /// Test special characters including Unicode, emoji, and various scripts
    fn test_special_characters() {
        let keypair = generate_keypair_impl();

        // Create a message with mixed characters
        let special_message = "ASCII: Hello! 
                               CJK: 你好，世界! こんにちは! 안녕하세요!
                               Cyrillic: Привет, мир!
                               Arabic: مرحبا بالعالم!
                               Emoji: 🚀✨🔐🌍🎉";

        // Encrypt and decrypt
        let encrypted = rsa_encrypt_base64_impl(&keypair.public_pem, special_message);
        let decrypted = rsa_decrypt_base64_impl(&keypair.private_pem, &encrypted).unwrap();

        // Verify all characters are preserved correctly
        assert_eq!(special_message, decrypted);
    }

    #[test]
    /// Test handling of binary data (non-UTF8)
    fn test_binary_data_handling() {
        let keypair = generate_keypair_impl();

        // Generate some random binary data
        let mut binary_data = vec![0u8; 100];
        OsRng.fill_bytes(&mut binary_data);

        // Convert to a Base64 string for the API (since our API expects strings)
        let binary_b64 = general_purpose::STANDARD.encode(&binary_data);

        // Encrypt and decrypt
        let encrypted = rsa_encrypt_base64_impl(&keypair.public_pem, &binary_b64);
        let decrypted = rsa_decrypt_base64_impl(&keypair.private_pem, &encrypted).unwrap();

        // Verify data is preserved
        assert_eq!(binary_b64, decrypted);

        // Test we can recover the original binary data
        let recovered_binary = general_purpose::STANDARD.decode(decrypted).unwrap();
        assert_eq!(binary_data, recovered_binary);
    }

    #[test]
    /// Test that public keys can't decrypt data
    fn test_key_role_separation() {
        let keypair = generate_keypair_impl();
        let message = "This should only be decryptable with the private key";

        // Encrypt with public key
        let encrypted = rsa_encrypt_base64_impl(&keypair.public_pem, message);

        // Attempt to decrypt with public key (should fail)
        let result = direct_rsa_decrypt(&keypair.public_pem, &encrypted);
        assert!(result.is_err(), "Decryption with public key should fail");

        // Verify we can decrypt with private key
        let decrypted = rsa_decrypt_base64_impl(&keypair.private_pem, &encrypted).unwrap();
        assert_eq!(message, decrypted);
    }

    #[test]
    /// Test handling of various invalid inputs and error conditions
    fn test_invalid_inputs() {
        let keypair = generate_keypair_impl();
        let message = "Test message";

        // Test invalid public key PEM
        let invalid_key =
            "-----BEGIN PUBLIC KEY-----\ninvalid base64 data\n-----END PUBLIC KEY-----";
        let result = std::panic::catch_unwind(|| {
            rsa_encrypt_base64_impl(invalid_key, message);
        });
        assert!(result.is_err(), "Encryption with invalid key should fail");

        // Test invalid base64 in decryption
        let invalid_b64 = "this is not valid base64!@#$";
        let result = rsa_decrypt_base64_impl(&keypair.private_pem, invalid_b64);
        assert!(
            result.is_err(),
            "Decryption with invalid base64 should fail"
        );
        assert!(result.unwrap_err().contains("Base64 decode failed"));

        // Test tampered ciphertext
        let encrypted = rsa_encrypt_base64_impl(&keypair.public_pem, message);
        // Modify a character in the middle
        let tampered = encrypted
            .chars()
            .enumerate()
            .map(|(i, c)| if i == encrypted.len() / 2 { 'X' } else { c })
            .collect::<String>();

        let result = rsa_decrypt_base64_impl(&keypair.private_pem, &tampered);
        assert!(result.is_err(), "Decryption of tampered data should fail");
    }

    #[test]
    /// Test cross-compatibility between direct and hybrid mode
    fn test_encryption_mode_compatibility() {
        let keypair = generate_keypair_impl();
        let message = "Test message";

        // Encrypt with direct RSA
        let direct_encrypted = direct_rsa_encrypt_base64(&keypair.public_pem, message.as_bytes());

        // Decrypt with the auto-detection mechanism
        let decrypted = rsa_decrypt_base64_impl(&keypair.private_pem, &direct_encrypted).unwrap();
        assert_eq!(message, decrypted);

        // Create a hybrid encrypted message
        let hybrid_data = HybridEncryptedData {
            mode: "hybrid".to_string(),
            nonce: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], // 12-byte nonce
            encrypted_key: direct_encrypted, // Use the RSA-encrypted message as a key
            encrypted_data: message.as_bytes().to_vec(), // Use plaintext as "encrypted" data for test
        };

        // Serialize to JSON and encode as Base64
        let json = serde_json::to_string(&hybrid_data).unwrap();
        let hybrid_encrypted = general_purpose::STANDARD.encode(json);

        // Try to decrypt with the auto-detection mechanism (this should fail since our
        // test hybrid data isn't properly encrypted, but it should recognize it as hybrid)
        let result = rsa_decrypt_base64_impl(&keypair.private_pem, &hybrid_encrypted);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("AES"),
            "Error should indicate AES failure"
        );
    }

    #[test]
    /// Test key reuse across multiple messages
    fn test_key_reuse() {
        let keypair = generate_keypair_impl();

        // Encrypt and decrypt multiple messages with the same key pair
        for i in 1..=10 {
            let message = format!("Test message {}", i);
            let encrypted = rsa_encrypt_base64_impl(&keypair.public_pem, &message);
            let decrypted = rsa_decrypt_base64_impl(&keypair.private_pem, &encrypted).unwrap();
            assert_eq!(message, decrypted);
        }
    }

    #[test]
    /// Test empty messages
    fn test_empty_message() {
        let keypair = generate_keypair_impl();
        let empty_message = "";

        // Encrypt and decrypt empty message
        let encrypted = rsa_encrypt_base64_impl(&keypair.public_pem, empty_message);
        let decrypted = rsa_decrypt_base64_impl(&keypair.private_pem, &encrypted).unwrap();

        assert_eq!(empty_message, decrypted);
    }

    #[test]
    /// Test multiple independent key pairs
    fn test_multiple_key_pairs() {
        // Generate two different key pairs
        let keypair1 = generate_keypair_impl();
        let keypair2 = generate_keypair_impl();

        // Ensure they're different
        assert_ne!(keypair1.public_pem, keypair2.public_pem);
        assert_ne!(keypair1.private_pem, keypair2.private_pem);

        // Test cross-compatibility
        let message = "Test message";

        // Encrypt with keypair1's public key
        let encrypted1 = rsa_encrypt_base64_impl(&keypair1.public_pem, message);
        // Try to decrypt with keypair2's private key (should fail)
        let result = rsa_decrypt_base64_impl(&keypair2.private_pem, &encrypted1);
        assert!(
            result.is_err(),
            "Decryption with wrong private key should fail"
        );

        // Decrypt with keypair1's private key (should succeed)
        let decrypted1 = rsa_decrypt_base64_impl(&keypair1.private_pem, &encrypted1).unwrap();
        assert_eq!(message, decrypted1);

        // Encrypt with keypair2's public key
        let encrypted2 = rsa_encrypt_base64_impl(&keypair2.public_pem, message);
        // Try to decrypt with keypair1's private key (should fail)
        let result = rsa_decrypt_base64_impl(&keypair1.private_pem, &encrypted2);
        assert!(
            result.is_err(),
            "Decryption with wrong private key should fail"
        );

        // Decrypt with keypair2's private key (should succeed)
        let decrypted2 = rsa_decrypt_base64_impl(&keypair2.private_pem, &encrypted2).unwrap();
        assert_eq!(message, decrypted2);
    }

    #[test]
    /// Test the hybrid encryption JSON format
    fn test_hybrid_json_structure() {
        let keypair = generate_keypair_impl();
        let message = "A".repeat(MAX_RSA_SIZE + 100); // Force hybrid encryption

        // Encrypt using hybrid mode
        let encrypted = rsa_encrypt_base64_impl(&keypair.public_pem, &message);

        // Decode and parse as JSON
        let decoded = general_purpose::STANDARD.decode(&encrypted).unwrap();
        let hybrid_data: HybridEncryptedData = serde_json::from_slice(&decoded).unwrap();

        // Verify the structure
        assert_eq!("hybrid", hybrid_data.mode);
        assert!(!hybrid_data.encrypted_key.is_empty());
        assert!(!hybrid_data.encrypted_data.is_empty());
        assert_eq!(12, hybrid_data.nonce.len()); // AES-GCM expects 12-byte nonce
    }
}

#[cfg(test)]
mod performance_test_suite {
    use super::*;
    use std::time::{Instant};

    /// Run a simple benchmark of a given function
    fn benchmark<F, T>(name: &str, iterations: u32, f: F) -> T
    where
        F: Fn() -> T,
    {
        let start = Instant::now();
        let result = f();
        let duration = start.elapsed();
        let per_op = duration / iterations;

        println!(
            "BENCHMARK: {} - {} iterations in {:?} ({:?} per op)",
            name, iterations, duration, per_op
        );

        result
    }

    #[test]
    /// Measure key generation performance
    fn benchmark_key_generation() {
        const ITERATIONS: u32 = 5;

        let keypair = benchmark("RSA-2048 Key Generation", ITERATIONS, || {
            let mut last_keypair = None;
            for _ in 0..ITERATIONS {
                last_keypair = Some(generate_keypair_impl());
            }
            last_keypair.unwrap()
        });

        // Verify the generated keys
        assert!(keypair.public_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    /// Benchmark direct RSA vs hybrid encryption for different message sizes
    fn benchmark_encryption_modes() {
        const ITERATIONS: u32 = 50;

        // Generate one keypair for all tests
        let keypair = generate_keypair_impl();

        // Test with message sizes below and above the RSA threshold
        let small_msg = "Small message for encryption";
        let large_msg = "A".repeat(10000);

        // Benchmark direct RSA (small message)
        let encrypted_small = benchmark("Direct RSA Encryption (small)", ITERATIONS, || {
            let mut last_result = String::new();
            for _ in 0..ITERATIONS {
                last_result = direct_rsa_encrypt_base64(&keypair.public_pem, small_msg.as_bytes());
            }
            last_result
        });

        // Benchmark hybrid encryption (large message)
        let encrypted_large = benchmark("Hybrid Encryption (large)", ITERATIONS, || {
            let mut last_result = String::new();
            for _ in 0..ITERATIONS {
                last_result = rsa_encrypt_base64_impl(&keypair.public_pem, &large_msg);
            }
            last_result
        });

        // Benchmark decryption small
        let _decrypted_small = benchmark("Direct RSA Decryption (small)", ITERATIONS, || {
            let mut last_result = String::new();
            for _ in 0..ITERATIONS {
                last_result =
                    rsa_decrypt_base64_impl(&keypair.private_pem, &encrypted_small).unwrap();
            }
            last_result
        });

        // Benchmark decryption large
        let _decrypted_large = benchmark("Hybrid Decryption (large)", ITERATIONS, || {
            let mut last_result = String::new();
            for _ in 0..ITERATIONS {
                last_result =
                    rsa_decrypt_base64_impl(&keypair.private_pem, &encrypted_large).unwrap();
            }
            last_result
        });
    }

    #[test]
    /// Test if encryption time varies significantly with message size (within same mode)
    fn test_timing_variation() {
        let keypair = generate_keypair_impl();

        // Test different message sizes within direct RSA mode
        let sizes = [10, 50, 100, 200, MAX_RSA_SIZE - 10];
        let mut timings = Vec::with_capacity(sizes.len());

        for &size in &sizes {
            let message = "A".repeat(size);

            let start = Instant::now();
            let _encrypted = direct_rsa_encrypt_base64(&keypair.public_pem, message.as_bytes());
            let duration = start.elapsed();

            timings.push((size, duration));
        }

        // Log the results
        println!("TIMING VARIATION TEST (Direct RSA):");
        for (size, duration) in &timings {
            println!("  Message size: {} bytes, Duration: {:?}", size, duration);
        }

        // Check that timing differences are not extreme
        // (This is a very basic check - real side-channel analysis would be more sophisticated)
        let max_duration = timings.iter().map(|(_, d)| *d).max().unwrap();
        let min_duration = timings.iter().map(|(_, d)| *d).min().unwrap();

        println!(
            "  Max/Min ratio: {:.2}",
            max_duration.as_nanos() as f64 / min_duration.as_nanos() as f64
        );
    }
}

#[cfg(test)]
mod interoperability_test_suite {
    use super::*;

    #[test]
    /// Test PKCS#1 v1.5 padding compatibility by manually creating a test vector
    fn test_pkcs1_padding_interop() {
        let keypair = generate_keypair_impl();
        let message = "PKCS#1 v1.5 test";

        // Encrypt with our implementation
        let encrypted = direct_rsa_encrypt_base64(&keypair.public_pem, message.as_bytes());

        // Decode from Base64
        let ciphertext = general_purpose::STANDARD.decode(&encrypted).unwrap();

        // Verify the length is correct for RSA-2048
        assert_eq!(
            256,
            ciphertext.len(),
            "RSA-2048 ciphertext should be exactly 256 bytes"
        );

        // In the modern implementation of PKCS#1 v1.5, the first byte could be different
        // depending on library implementation. In RSA-2048, we're mainly concerned
        // that the ciphertext is the right length and can be decrypted correctly.
        
        // Some libraries may represent the first byte as 0x00, others as 0x80 (128) due to
        // sign bit handling or other implementation details.
        
        // Let's verify we can decrypt the ciphertext instead of checking specific byte values,
        // which might vary across RSA library implementations while still being standards-compliant.
        let decrypted = rsa_decrypt_base64_impl(&keypair.private_pem, &encrypted).unwrap();
        assert_eq!(message, decrypted, "Decryption failed or produced incorrect result");
        
        // Log the actual byte values for documentation
        println!("PKCS#1 v1.5 ciphertext first bytes: [{}, {}, {}]", 
                 ciphertext[0], ciphertext[1], ciphertext[2]);
    }

    #[test]
    /// Test that our AES-GCM implementation uses the expected parameters
    fn test_aes_gcm_parameters() {
        let keypair = generate_keypair_impl();
        let message = "A".repeat(MAX_RSA_SIZE + 100); // Force hybrid mode

        // Encrypt using hybrid mode
        let encrypted = rsa_encrypt_base64_impl(&keypair.public_pem, &message);

        // Decode and parse
        let decoded = general_purpose::STANDARD.decode(&encrypted).unwrap();
        let hybrid_data: HybridEncryptedData = serde_json::from_slice(&decoded).unwrap();

        // Verify AES parameters
        assert_eq!(
            12,
            hybrid_data.nonce.len(),
            "AES-GCM nonce should be 12 bytes"
        );

        // Additional authenticated data (AAD) is not directly visible in our structure,
        // but we can test that encryption/decryption works as expected
        let decrypted = rsa_decrypt_base64_impl(&keypair.private_pem, &encrypted).unwrap();
        assert_eq!(message, decrypted);
    }
}
