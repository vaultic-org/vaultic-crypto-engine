#[cfg(test)]
mod message_protection_tests {
    use base64::Engine;
    use base64::engine::general_purpose;
    use vaultic_crypto_engine::*;

    #[test]
    /// Test that basic encryption works and produces valid output structure
    fn test_basic_encryption() {
        let plaintext = "This is a test message";
        let passphrase = "test-passphrase-123";

        let result = protect_message(plaintext, passphrase);

        // Verify all parts are valid base64
        assert!(
            !result.ciphertext.is_empty(),
            "Ciphertext should not be empty"
        );
        assert!(!result.salt.is_empty(), "Salt should not be empty");
        assert!(!result.nonce.is_empty(), "Nonce should not be empty");

        assert!(
            general_purpose::STANDARD.decode(&result.ciphertext).is_ok(),
            "Ciphertext should be valid base64"
        );
        assert!(
            general_purpose::STANDARD.decode(&result.salt).is_ok(),
            "Salt should be valid base64"
        );
        assert!(
            general_purpose::STANDARD.decode(&result.nonce).is_ok(),
            "Nonce should be valid base64"
        );

        // Verify salt and nonce lengths
        let salt_bytes = general_purpose::STANDARD.decode(&result.salt).unwrap();
        let nonce_bytes = general_purpose::STANDARD.decode(&result.nonce).unwrap();

        assert_eq!(salt_bytes.len(), 16, "Salt should be 16 bytes");
        assert_eq!(nonce_bytes.len(), 12, "Nonce should be 12 bytes");
    }

    #[test]
    /// Test that the same plaintext and passphrase produces different outputs due to randomness
    fn test_randomness() {
        let plaintext = "This should be encrypted differently each time";
        let passphrase = "test-passphrase-456";

        let result1 = protect_message(plaintext, passphrase);
        let result2 = protect_message(plaintext, passphrase);

        // Verify ciphertexts are different
        assert_ne!(
            result1.ciphertext, result2.ciphertext,
            "Ciphertexts should be different due to random salt and nonce"
        );

        // Verify salts are different
        assert_ne!(
            result1.salt, result2.salt,
            "Salts should be different between encryptions"
        );

        // Verify nonces are different
        assert_ne!(
            result1.nonce, result2.nonce,
            "Nonces should be different between encryptions"
        );
    }

    #[test]
    /// Test encryption with various message sizes
    fn test_message_sizes() {
        let passphrase = "test-passphrase-789";

        // Test with various sizes
        let message_sizes = [0, 1, 100, 1000, 10000];

        for size in message_sizes.iter() {
            let plaintext = "A".repeat(*size);
            let result = protect_message(&plaintext, passphrase);

            // Verify we get a non-empty ciphertext
            assert!(
                !result.ciphertext.is_empty(),
                "Ciphertext should not be empty"
            );

            // Verify ciphertext size makes sense (should be at least as large as plaintext plus tag)
            let ciphertext = general_purpose::STANDARD
                .decode(&result.ciphertext)
                .unwrap();

            // AES-GCM adds a 16-byte authentication tag
            assert!(
                ciphertext.len() >= *size,
                "Ciphertext should be at least as large as plaintext"
            );
            if *size > 0 {
                assert!(
                    ciphertext.len() <= *size + 32,
                    "Ciphertext should not be excessively larger than plaintext"
                );
            }
        }
    }

    #[test]
    /// Test encryption with various types of plaintexts including special characters
    fn test_special_characters() {
        let passphrase = "test-passphrase-special";

        let special_texts = [
            "Empty string next:",
            "",
            "Special chars: !@#$%^&*()_+-=[]{}|;:'\",.<>?/~`",
            "Unicode: 你好，世界! こんにちは! 안녕하세요!",
            "Emoji: 🚀✨🔐🌍🎉",
            "Mixed:\nASCII, Unicode (你好), and Emoji (🔑) with\tTabs",
        ];

        for text in special_texts.iter() {
            let result = protect_message(text, passphrase);

            // Verify encryption works for all special texts
            assert!(
                !result.ciphertext.is_empty(),
                "Ciphertext should not be empty"
            );
        }
    }

    #[test]
    /// Test encryption with various types of passphrases
    fn test_passphrase_variations() {
        let plaintext = "Common plaintext for all passphrase tests";

        let passphrases = [
            "",                                   // Empty passphrase
            "a",                                  // Single character
            &"a".repeat(100),                     // Very long passphrase
            "!@#$%^&*()_+-=[]{}|;:,.<>?/~`",      // Special characters
            "你好，世界！",                       // Unicode characters
            "🚀✨🔐",                             // Emoji
            &format!("{}\n\t\r", "a".repeat(10)), // Whitespace
        ];

        for passphrase in passphrases.iter() {
            let result = protect_message(plaintext, passphrase);

            // Verify encryption works for all passphrase types
            assert!(
                !result.ciphertext.is_empty(),
                "Ciphertext should not be empty"
            );
        }
    }

    #[test]
    /// Test consistency of ciphertext length relationship to plaintext length
    fn test_ciphertext_size_relationship() {
        let passphrase = "test-passphrase-size";

        // Test with two different sizes to measure the overhead
        let small_text = "Small";
        let large_text = "A".repeat(1000);

        let small_result = protect_message(small_text, passphrase);
        let large_result = protect_message(&large_text, passphrase);

        let small_ciphertext = general_purpose::STANDARD
            .decode(&small_result.ciphertext)
            .unwrap();
        let large_ciphertext = general_purpose::STANDARD
            .decode(&large_result.ciphertext)
            .unwrap();

        // Calculate overhead (authentication tag + any padding)
        let small_overhead = small_ciphertext.len() - small_text.len();
        let large_overhead = large_ciphertext.len() - large_text.len();

        // Overhead should be consistent (primarily the 16-byte authentication tag)
        assert!(
            (small_overhead as i32 - large_overhead as i32).abs() <= 16,
            "Encryption overhead should be consistent regardless of plaintext size"
        );
    }
}
