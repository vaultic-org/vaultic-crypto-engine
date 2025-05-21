use std::fs;
// use vaultic_crypto_engine::unprotect_message_obj;
use serde_json::Value;
use vaultic_crypto_engine::ProtectedMessage;

#[cfg(test)]
mod raw_message_unprotection_tests {

    #[cfg(feature = "wasm")]
    // Test helper function to encrypt a message and get its raw components
    fn encrypt_message_get_raw(plaintext: &str, passphrase: &str) -> (String, String, String) {
        // Encrypt the message using the standard function
        let protected = protect_message(plaintext, passphrase);

        // Return raw components: ciphertext, salt, nonce
        (
            protected.ciphertext.clone(),
            protected.salt.clone(),
            protected.nonce.clone(),
        )
    }

    #[test]
    /// Test basic decryption with raw parameters
    fn test_basic_raw_decryption() {
        // This test requires WASM feature enabled
        #[cfg(feature = "wasm")]
        {
            let plaintext = "This is a test message for raw unprotect";
            let passphrase = "test-passphrase-raw-123";

            // Encrypt and get raw components
            let (ciphertext, salt, nonce) = encrypt_message_get_raw(plaintext, passphrase);

            // Decrypt with raw parameters
            let decrypted = unprotect_message(&ciphertext, passphrase, &salt, &nonce)
                .expect("Decryption failed");

            // Verify the decrypted message matches original plaintext
            assert_eq!(decrypted, plaintext);
        }
    }

    #[test]
    /// Test decryption with wrong passphrase
    fn test_wrong_passphrase() {
        // This test requires WASM feature enabled
        #[cfg(feature = "wasm")]
        {
            let plaintext = "Message with wrong passphrase test";
            let correct_passphrase = "correct-passphrase";
            let wrong_passphrase = "wrong-passphrase";

            // Encrypt with correct passphrase
            let (ciphertext, salt, nonce) = encrypt_message_get_raw(plaintext, correct_passphrase);

            // Try to decrypt with wrong passphrase
            let result = unprotect_message(&ciphertext, wrong_passphrase, &salt, &nonce);

            // Should fail
            assert!(result.is_err());

            // Verify decryption works with correct passphrase
            let decrypted = unprotect_message(&ciphertext, correct_passphrase, &salt, &nonce)
                .expect("Decryption with correct passphrase failed");
            assert_eq!(decrypted, plaintext);
        }
    }

    #[test]
    /// Test decryption with tampered ciphertext
    fn test_tampered_ciphertext() {
        // This test requires WASM feature enabled
        #[cfg(feature = "wasm")]
        {
            let plaintext = "Message to test tampered ciphertext";
            let passphrase = "passphrase-tamper-test";

            // Encrypt and get raw components
            let (ciphertext, salt, nonce) = encrypt_message_get_raw(plaintext, passphrase);

            // Tamper with ciphertext
            let mut decoded = general_purpose::STANDARD.decode(&ciphertext).unwrap();
            if !decoded.is_empty() {
                decoded[0] ^= 0xFF; // Flip bits of first byte
            }
            let tampered_ciphertext = general_purpose::STANDARD.encode(decoded);

            // Decryption should fail with tampered ciphertext
            let result = unprotect_message(&tampered_ciphertext, passphrase, &salt, &nonce);
            assert!(result.is_err());
        }
    }

    #[test]
    /// Test decryption with tampered salt
    fn test_tampered_salt() {
        // This test requires WASM feature enabled
        #[cfg(feature = "wasm")]
        {
            let plaintext = "Message to test tampered salt";
            let passphrase = "passphrase-salt-tamper";

            // Encrypt and get raw components
            let (ciphertext, salt, nonce) = encrypt_message_get_raw(plaintext, passphrase);

            // Tamper with salt
            let mut decoded = general_purpose::STANDARD.decode(&salt).unwrap();
            decoded[0] ^= 0xFF; // Flip bits of first byte
            let tampered_salt = general_purpose::STANDARD.encode(decoded);

            // Decryption should fail with tampered salt
            let result = unprotect_message(&ciphertext, passphrase, &tampered_salt, &nonce);
            assert!(result.is_err());
        }
    }

    #[test]
    /// Test decryption with tampered nonce
    fn test_tampered_nonce() {
        // This test requires WASM feature enabled
        #[cfg(feature = "wasm")]
        {
            let plaintext = "Message to test tampered nonce";
            let passphrase = "passphrase-nonce-tamper";

            // Encrypt and get raw components
            let (ciphertext, salt, nonce) = encrypt_message_get_raw(plaintext, passphrase);

            // Tamper with nonce
            let mut decoded = general_purpose::STANDARD.decode(&nonce).unwrap();
            decoded[0] ^= 0xFF; // Flip bits of first byte
            let tampered_nonce = general_purpose::STANDARD.encode(decoded);

            // Decryption should fail with tampered nonce
            let result = unprotect_message(&ciphertext, passphrase, &salt, &tampered_nonce);
            assert!(result.is_err());
        }
    }

    #[test]
    /// Test with various message sizes
    fn test_various_message_sizes() {
        // This test requires WASM feature enabled
        #[cfg(feature = "wasm")]
        {
            let passphrase = "size-test-passphrase";

            // Test various sizes
            let sizes = [0, 1, 10, 100, 1000];

            for size in sizes.iter() {
                let plaintext = "A".repeat(*size);

                // Encrypt and get raw components
                let (ciphertext, salt, nonce) = encrypt_message_get_raw(&plaintext, passphrase);

                // Decrypt and verify
                let decrypted = unprotect_message(&ciphertext, passphrase, &salt, &nonce)
                    .expect("Decryption failed");

                assert_eq!(decrypted, plaintext);
            }
        }
    }

    #[test]
    /// Test with special characters in plaintext
    fn test_special_chars() {
        // This test requires WASM feature enabled
        #[cfg(feature = "wasm")]
        {
            let passphrase = "special-chars-passphrase";

            let special_texts = [
                "Empty string next:",
                "",
                "Special chars: !@#$%^&*()_+-=[]{}|;:'\",.<>?/~`",
                "Unicode: 你好，世界! こんにちは! 안녕하세요!",
                "Emoji: 🚀✨🔐🌍🎉",
                "Mixed:\nASCII, Unicode (你好), and Emoji (🔑) with\tTabs",
            ];

            for text in special_texts.iter() {
                // Encrypt and get raw components
                let (ciphertext, salt, nonce) = encrypt_message_get_raw(text, passphrase);

                // Decrypt and verify
                let decrypted = unprotect_message(&ciphertext, passphrase, &salt, &nonce)
                    .expect("Decryption failed");

                assert_eq!(&decrypted, text);
            }
        }
    }

    #[test]
    /// Test round-trip encryption/decryption with protect_message and unprotect_message
    fn test_round_trip() {
        // This test requires WASM feature enabled
        #[cfg(feature = "wasm")]
        {
            let plaintext = "This is a message for round-trip testing";
            let passphrase = "round-trip-passphrase";

            // First, encrypt with protect_message
            let protected = protect_message(plaintext, passphrase);

            // Extract components
            let ciphertext = protected.ciphertext.clone();
            let salt = protected.salt.clone();
            let nonce = protected.nonce.clone();

            // Decrypt with unprotect_message using raw parameters
            let decrypted = unprotect_message(&ciphertext, passphrase, &salt, &nonce)
                .expect("Round-trip decryption failed");

            // Verify round-trip works correctly
            assert_eq!(decrypted, plaintext);
        }
    }
}
