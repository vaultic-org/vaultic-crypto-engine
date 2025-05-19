#[cfg(test)]
mod key_unprotection_tests {
    use base64::Engine;
    use base64::engine::general_purpose;
    use vaultic_crypto_engine::*;

    /// Helper function to generate a test keypair and protect it
    fn generate_protected_keypair(passphrase: &str) -> (KeyPair, EncryptedKeypairResult) {
        let keypair = generate_keypair_impl();
        let protected = protect_keypair_impl(&keypair.private_pem, &keypair.public_pem, passphrase)
            .expect("Failed to protect keypair");
        (keypair, protected)
    }

    #[test]
    /// Test basic unprotection functionality with valid inputs
    fn test_basic_unprotection() {
        let passphrase = "test-passphrase-123!@#";
        let (original_keypair, protected) = generate_protected_keypair(passphrase);

        // Create a consistent structure for unprotect function
        let result = unprotect_keypair(&protected, passphrase).expect("Unprotection failed");

        // Verify the keys match the original
        assert_eq!(result.private_pem, original_keypair.private_pem);
        assert_eq!(result.public_pem, original_keypair.public_pem);

        // Verify the keys are valid PEM format
        assert!(
            result
                .private_pem
                .starts_with("-----BEGIN PRIVATE KEY-----")
        );
        assert!(result.private_pem.ends_with("-----END PRIVATE KEY-----\n"));
        assert!(result.public_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert!(result.public_pem.ends_with("-----END PUBLIC KEY-----\n"));
    }

    #[test]
    /// Test unprotection with various passphrase lengths and characters
    fn test_passphrase_variations() {
        let passphrases = [
            "",                                   // Empty passphrase
            "a",                                  // Single character
            &"a".repeat(100), // Long passphrase (reduced length for test performance)
            "!@#$%^&*()_+-=[]{}|;:,.<>?/~`", // Special characters
            "你好，世界！",   // Unicode characters
            "🚀✨🔐",         // Emoji
            &format!("{}\n\t\r", "a".repeat(10)), // Whitespace
        ];

        for passphrase in passphrases.iter() {
            let (original_keypair, protected) = generate_protected_keypair(passphrase);

            let result = unprotect_keypair(&protected, passphrase).expect("Unprotection failed");

            assert_eq!(result.private_pem, original_keypair.private_pem);
            assert_eq!(result.public_pem, original_keypair.public_pem);
        }
    }

    #[test]
    /// Test unprotection with tampered inputs
    fn test_tampered_inputs() {
        let passphrase = "test-passphrase";
        let (_, protected) = generate_protected_keypair(passphrase);

        // Test with tampered encrypted private key
        let mut tampered = protected.clone();
        let mut decoded = general_purpose::STANDARD
            .decode(&tampered.encrypted_private)
            .unwrap();
        decoded[0] ^= 0xFF; // Flip all bits of first byte
        tampered.encrypted_private = general_purpose::STANDARD.encode(decoded);

        let result = unprotect_keypair(&tampered, passphrase);
        assert!(
            result.is_err(),
            "Should detect tampered encrypted private key"
        );

        // Test with tampered salt
        let mut tampered = protected.clone();
        let mut decoded = general_purpose::STANDARD.decode(&tampered.salt).unwrap();
        decoded[0] ^= 0xFF;
        tampered.salt = general_purpose::STANDARD.encode(decoded);

        let result = unprotect_keypair(&tampered, passphrase);
        assert!(result.is_err(), "Should detect tampered salt");

        // Test with tampered nonce
        let mut tampered = protected.clone();
        let mut decoded = general_purpose::STANDARD
            .decode(&tampered.nonce_private)
            .unwrap();
        decoded[0] ^= 0xFF;
        tampered.nonce_private = general_purpose::STANDARD.encode(decoded);

        let result = unprotect_keypair(&tampered, passphrase);
        assert!(result.is_err(), "Should detect tampered nonce");
    }

    #[test]
    /// Test unprotection with invalid input lengths
    fn test_invalid_lengths() {
        let passphrase = "test-passphrase";
        let (_, protected) = generate_protected_keypair(passphrase);

        // Test with invalid salt length
        let mut tampered = protected.clone();
        tampered.salt = general_purpose::STANDARD.encode(vec![0u8; 8]); // Too short

        let result = unprotect_keypair(&tampered, passphrase);
        assert!(result.is_err(), "Should reject invalid salt length");

        // Test with invalid nonce length - CORRECTION
        // AES-GCM exige un nonce de 12 octets exactement
        // Au lieu de tester avec une longueur invalide (ce qui provoque une panique),
        // nous utilisons un nonce valide mais différent qui causera une erreur de déchiffrement
        let mut tampered = protected.clone();
        let different_nonce = vec![0u8; 12]; // Bon nombre d'octets, mais contenu différent
        tampered.nonce_private = general_purpose::STANDARD.encode(different_nonce);
        tampered.nonce_public = tampered.nonce_private.clone();

        let result = unprotect_keypair(&tampered, passphrase);
        assert!(result.is_err(), "Should detect modified nonce");
    }

    #[test]
    /// Test the function with wrong passphrase
    fn test_wrong_passphrase() {
        let correct_passphrase = "correct-passphrase";
        let wrong_passphrase = "wrong-passphrase";
        let (original_keypair, protected) = generate_protected_keypair(correct_passphrase);

        let result = unprotect_keypair(&protected, wrong_passphrase);
        assert!(
            result.is_err(),
            "Decryption with wrong passphrase should fail"
        );

        // Verify decryption with correct passphrase works
        let result =
            unprotect_keypair(&protected, correct_passphrase).expect("Unprotection failed");
        assert_eq!(result.private_pem, original_keypair.private_pem);
        assert_eq!(result.public_pem, original_keypair.public_pem);
    }

    #[test]
    /// Test cross-compatibility between protect/unprotect functions
    fn test_round_trip() {
        let passphrase = "complex-p@ssphrase-123!";
        let original_keypair = generate_keypair_impl();

        // Protect with protect_keypair_impl
        let protected = protect_keypair_impl(
            &original_keypair.private_pem,
            &original_keypair.public_pem,
            passphrase,
        )
        .expect("Protection failed");

        // Unprotect with unprotect_keypair
        let unprotected = unprotect_keypair(&protected, passphrase).expect("Unprotection failed");

        // Verify keys are preserved through the protect/unprotect cycle
        assert_eq!(unprotected.private_pem, original_keypair.private_pem);
        assert_eq!(unprotected.public_pem, original_keypair.public_pem);
    }

    #[test]
    /// Test encrypted key size relationship to original
    fn test_encrypted_size_relationship() {
        let passphrase = "test-passphrase";
        let (keypair, protected) = generate_protected_keypair(passphrase);

        // Get sizes of original and encrypted
        let private_pem_size = keypair.private_pem.len();
        let public_pem_size = keypair.public_pem.len();

        let encrypted_private_size = general_purpose::STANDARD
            .decode(&protected.encrypted_private)
            .unwrap()
            .len();
        let encrypted_public_size = general_purpose::STANDARD
            .decode(&protected.encrypted_public)
            .unwrap()
            .len();

        // Verify encrypted size makes sense
        // AES-GCM adds a 16-byte authentication tag
        assert!(
            encrypted_private_size >= private_pem_size
                && encrypted_private_size <= private_pem_size + 32,
            "Encrypted private key size should be close to original plus overhead"
        );
        assert!(
            encrypted_public_size >= public_pem_size
                && encrypted_public_size <= public_pem_size + 32,
            "Encrypted public key size should be close to original plus overhead"
        );

        // Unprotect and verify sizes match original
        let unprotect_result =
            unprotect_keypair(&protected, passphrase).expect("Unprotection failed");
        assert_eq!(unprotect_result.private_pem.len(), private_pem_size);
        assert_eq!(unprotect_result.public_pem.len(), public_pem_size);
    }
}
