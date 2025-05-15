#[cfg(test)]
mod rsa_tests {
    use vaultic_crypto_engine::{generate_rsa_keypair_pem, rsa_decrypt_base64, rsa_encrypt_base64};

    #[test]
    fn test_key_generation() {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let keypair = generate_rsa_keypair_pem();

            assert!(
                keypair.public_pem.contains("-----BEGIN PUBLIC KEY-----"),
                "Public key PEM format is incorrect: {}",
                keypair.public_pem
            );
            assert!(
                keypair.public_pem.contains("-----END PUBLIC KEY-----"),
                "Public key PEM format is incorrect: {}",
                keypair.public_pem
            );
            assert!(
                keypair.private_pem.contains("-----BEGIN PRIVATE KEY-----"),
                "Private key PEM format is incorrect: {}",
                keypair.private_pem
            );
            assert!(
                keypair.private_pem.contains("-----END PRIVATE KEY-----"),
                "Private key PEM format is incorrect: {}",
                keypair.private_pem
            );
        }
    }

    #[test]
    fn test_encrypt_decrypt_cycle() {
        #[cfg(not(target_arch = "wasm32"))]
        {
            // Generate key pair
            let keypair = generate_rsa_keypair_pem();

            // Original plaintext to encrypt
            let original_text = "This is a secret message";

            // Encrypt using public key
            let encrypted = rsa_encrypt_base64(&keypair.public_pem, original_text);

            // Verify encryption produces non-empty result
            assert!(!encrypted.is_empty());
            assert_ne!(encrypted, original_text);

            // Decrypt using private key
            let decrypted = rsa_decrypt_base64(&keypair.private_pem, &encrypted);

            // Verify decryption returns original text
            assert_eq!(decrypted, original_text);
        }
    }

    #[test]
    fn test_encrypt_decrypt_with_special_characters() {
        #[cfg(not(target_arch = "wasm32"))]
        {
            // Generate key pair
            let keypair = generate_rsa_keypair_pem();

            // Original plaintext with special characters
            let original_text = "Special characters: !@#$%^&*()_+-=[]{};':\",./<>?`~";

            // Encrypt using public key
            let encrypted = rsa_encrypt_base64(&keypair.public_pem, original_text);

            // Decrypt using private key
            let decrypted = rsa_decrypt_base64(&keypair.private_pem, &encrypted);

            // Verify decryption returns original text
            assert_eq!(decrypted, original_text);
        }
    }

    #[test]
    fn test_encrypt_decrypt_with_unicode() {
        #[cfg(not(target_arch = "wasm32"))]
        {
            // Generate key pair
            let keypair = generate_rsa_keypair_pem();

            // Original plaintext with Unicode characters
            let original_text = "Unicode: 你好, こんにちは, مرحبا, привет";

            // Encrypt using public key
            let encrypted = rsa_encrypt_base64(&keypair.public_pem, original_text);

            // Decrypt using private key
            let decrypted = rsa_decrypt_base64(&keypair.private_pem, &encrypted);

            // Verify decryption returns original text
            assert_eq!(decrypted, original_text);
        }
    }

    #[test]
    fn test_different_keys_cannot_decrypt() {
        #[cfg(not(target_arch = "wasm32"))]
        {
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

    #[test]
    fn test_empty_string_encrypt_decrypt() {
        #[cfg(not(target_arch = "wasm32"))]
        {
            // Generate key pair
            let keypair = generate_rsa_keypair_pem();

            // Empty string
            let original_text = "";

            // Encrypt using public key
            let encrypted = rsa_encrypt_base64(&keypair.public_pem, original_text);

            // Verify encryption produces non-empty result even for empty input
            assert!(!encrypted.is_empty());

            // Decrypt using private key
            let decrypted = rsa_decrypt_base64(&keypair.private_pem, &encrypted);

            // Verify decryption returns original empty string
            assert_eq!(decrypted, original_text);
        }
    }
}
