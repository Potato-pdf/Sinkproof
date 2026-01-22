use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use sha2::{Sha256, Digest};

const VERIFICATION_PHRASE: &str = "No vendo cigarros sueltos";

/// Encrypt the verification phrase using AES-256-GCM
/// 
/// # Arguments
/// * `key` - 32-byte encryption key derived from thread outputs
/// 
/// # Returns
/// Encrypted data as bytes (nonce + ciphertext + tag all combined)
pub fn encrypt_phrase(key: &[u8]) -> Result<Vec<u8>, String> {
    // Ensure key is exactly 32 bytes
    let key = if key.len() > 32 {
        &key[..32]
    } else if key.len() < 32 {
        // Hash the key to get exactly 32 bytes
        let mut hasher = Sha256::new();
        hasher.update(key);
        return encrypt_phrase(&hasher.finalize());
    } else {
        key
    };

    // Create cipher
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("Failed to create cipher: {}", e))?;

    // Generate random nonce (12 bytes for GCM)
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Encrypt the phrase
    let ciphertext = cipher
        .encrypt(&nonce, VERIFICATION_PHRASE.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // Combine nonce + ciphertext
    let mut result = Vec::new();
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt the verification phrase
/// 
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `encrypted_data` - Combined nonce + ciphertext
/// 
/// # Returns
/// Decrypted phrase as String
pub fn decrypt_phrase(key: &[u8], encrypted_data: &[u8]) -> Result<String, String> {
    // Ensure key is exactly 32 bytes
    let key = if key.len() > 32 {
        &key[..32]
    } else if key.len() < 32 {
        // Hash the key to get exactly 32 bytes
        let mut hasher = Sha256::new();
        hasher.update(key);
        let hashed = hasher.finalize();
        return decrypt_phrase(&hashed, encrypted_data);
    } else {
        key
    };

    if encrypted_data.len() < 12 {
        return Err("Encrypted data too short".to_string());
    }

    // Split nonce and ciphertext
    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Create cipher
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("Failed to create cipher: {}", e))?;

    // Decrypt
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))?;

    String::from_utf8(plaintext)
        .map_err(|e| format!("Invalid UTF-8: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = b"this_is_a_32_byte_key_for_aes!!";
        
        let encrypted = encrypt_phrase(key).expect("Encryption failed");
        assert!(!encrypted.is_empty());
        
        let decrypted = decrypt_phrase(key, &encrypted).expect("Decryption failed");
        assert_eq!(decrypted, VERIFICATION_PHRASE);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = b"this_is_a_32_byte_key_for_aes!!";
        let key2 = b"different_32_byte_key_for_aes!!";
        
        let encrypted = encrypt_phrase(key1).expect("Encryption failed");
        
        // Decryption with wrong key should fail
        let result = decrypt_phrase(key2, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_encryptions_produce_different_ciphertexts() {
        let key = b"this_is_a_32_byte_key_for_aes!!";
        
        let encrypted1 = encrypt_phrase(key).expect("Encryption failed");
        let encrypted2 = encrypt_phrase(key).expect("Encryption failed");
        
        // Different nonces should produce different ciphertexts
        assert_ne!(encrypted1, encrypted2);
        
        // But both should decrypt correctly
        let decrypted1 = decrypt_phrase(key, &encrypted1).expect("Decryption failed");
        let decrypted2 = decrypt_phrase(key, &encrypted2).expect("Decryption failed");
        
        assert_eq!(decrypted1, VERIFICATION_PHRASE);
        assert_eq!(decrypted2, VERIFICATION_PHRASE);
    }

    #[test]
    fn test_short_key_handling() {
        let short_key = b"short";
        
        // Should still work by hashing the key
        let encrypted = encrypt_phrase(short_key).expect("Encryption failed");
        let decrypted = decrypt_phrase(short_key, &encrypted).expect("Decryption failed");
        
        assert_eq!(decrypted, VERIFICATION_PHRASE);
    }
}
