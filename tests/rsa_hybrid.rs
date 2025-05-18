#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose;
    use vaultic_crypto_engine::*;

    #[test]
    fn test_small_data_direct_rsa() {
        // Generate a RSA key pair
        let keypair = generate_keypair_impl();

        // A small message that should use direct RSA encryption
        let small_message = "This is a small message";

        // Encrypt the message
        let encrypted = rsa_encrypt_base64_impl(&keypair.public_pem, small_message);

        // Decrypt the message
        let decrypted = rsa_decrypt_base64_impl(&keypair.private_pem, &encrypted).unwrap();

        // Verify that the original message is recovered
        assert_eq!(small_message, decrypted);

        // Verify that it's direct RSA encryption (not hybrid)
        // - Try to decode the message as JSON -> should fail
        let decoded = general_purpose::STANDARD.decode(&encrypted).unwrap();
        assert!(serde_json::from_slice::<HybridEncryptedData>(&decoded).is_err());
    }

    #[test]
    fn test_large_data_hybrid_rsa_aes() {
        // Generate a RSA key pair
        let keypair = generate_keypair_impl();

        // A large message that should force the use of hybrid RSA+AES encryption
        // - 500 characters, well beyond the RSA limit of 245 bytes
        let large_message = "A".repeat(500);

        // Encrypt the message
        let encrypted = rsa_encrypt_base64_impl(&keypair.public_pem, &large_message);

        // Decrypt the message
        let decrypted = rsa_decrypt_base64_impl(&keypair.private_pem, &encrypted).unwrap();

        // Verify that the original message is recovered
        assert_eq!(large_message, decrypted);

        // Verify that it's hybrid RSA+AES encryption
        // - Decode the message as JSON -> should succeed
        let decoded = general_purpose::STANDARD.decode(&encrypted).unwrap();
        let hybrid_data = serde_json::from_slice::<HybridEncryptedData>(&decoded).unwrap();
        assert_eq!(hybrid_data.mode, "hybrid");
    }

    #[test]
    fn test_compatibility_with_previous_version() {
        // Simulate a message encrypted with the previous version (direct RSA)
        let keypair = generate_keypair_impl();
        let message = "Message compatible with the previous version";

        // Explicitly use the old encryption mechanism
        let legacy_encrypted = direct_rsa_encrypt_base64(&keypair.public_pem, message.as_bytes());

        // Verify that the new decryption can still read it
        let decrypted = rsa_decrypt_base64_impl(&keypair.private_pem, &legacy_encrypted).unwrap();
        assert_eq!(message, decrypted);
    }

    #[test]
    fn test_unicode_characters() {
        // Test with Unicode characters that take more bytes in UTF-8
        let keypair = generate_keypair_impl();
        let unicode_message = "Привет, мир! 你好，世界! こんにちは世界!";

        // Encrypt and decrypt
        let encrypted = rsa_encrypt_base64_impl(&keypair.public_pem, unicode_message);
        let decrypted = rsa_decrypt_base64_impl(&keypair.private_pem, &encrypted).unwrap();

        // Verify that Unicode characters are preserved
        assert_eq!(unicode_message, decrypted);
    }

    #[test]
    fn test_hybrid_encryption_boundary() {
        // Test exactly at the boundary between direct RSA and hybrid
        let keypair = generate_keypair_impl();

        // Create a message exactly at the limit (245 bytes)
        let boundary_message = "A".repeat(MAX_RSA_SIZE);
        assert_eq!(boundary_message.len(), MAX_RSA_SIZE);

        // Encrypt and decrypt
        let encrypted = rsa_encrypt_base64_impl(&keypair.public_pem, &boundary_message);
        let decrypted = rsa_decrypt_base64_impl(&keypair.private_pem, &encrypted).unwrap();

        // Verify the message
        assert_eq!(boundary_message, decrypted);

        // Now, test with one more byte (should use hybrid)
        let over_boundary = boundary_message + "X";
        assert_eq!(over_boundary.len(), MAX_RSA_SIZE + 1);

        let encrypted_large = rsa_encrypt_base64_impl(&keypair.public_pem, &over_boundary);
        let decrypted_large =
            rsa_decrypt_base64_impl(&keypair.private_pem, &encrypted_large).unwrap();

        assert_eq!(over_boundary, decrypted_large);

        // Verify that the first is direct RSA, the second is hybrid
        let decoded1 = general_purpose::STANDARD.decode(&encrypted).unwrap();
        let decoded2 = general_purpose::STANDARD.decode(&encrypted_large).unwrap();

        assert!(serde_json::from_slice::<HybridEncryptedData>(&decoded1).is_err());
        assert!(serde_json::from_slice::<HybridEncryptedData>(&decoded2).is_ok());
    }
}
