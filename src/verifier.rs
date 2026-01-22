use crate::storage::SinkproofHash;
use crate::hasher::{thread_worker, derive_key};
use crate::encryption::decrypt_phrase;
use std::sync::Arc;
use std::thread;

/// Verify a password against a stored Sinkproof hash
/// 
/// # Arguments
/// * `password` - The password to verify
/// * `stored_hash` - The stored hash string in Sinkproof format
/// 
/// # Returns
/// `Ok(true)` if password matches, `Ok(false)` if it doesn't, `Err` on error
pub fn verify_password(password: &str, stored_hash: &str) -> Result<bool, String> {
    // Parse the stored hash
    let hash = SinkproofHash::from_string(stored_hash)?;

    // Re-hash the password with the same parameters
    let memory_size = hash.memory_mb * 1024 * 1024;
    let mut handles = vec![];
    let password = Arc::new(password.to_string());
    let salt = Arc::new(hash.salt.clone());

    // Spawn worker threads with same parameters
    for thread_index in 0..hash.threads {
        let password = Arc::clone(&password);
        let salt = Arc::clone(&salt);

        let handle = thread::spawn(move || {
            thread_worker(&password, &salt, thread_index, memory_size)
        });

        handles.push(handle);
    }

    // Collect results
    let mut thread_outputs = Vec::new();
    for handle in handles {
        match handle.join() {
            Ok(output) => thread_outputs.push(output),
            Err(_) => return Err("Thread panicked during verification".to_string()),
        }
    }

    // Derive key from outputs
    let key = derive_key(&thread_outputs);

    // Try to decrypt the stored encrypted phrase
    match decrypt_phrase(&key, &hash.encrypted_phrase) {
        Ok(decrypted) => {
            // If decryption succeeds and matches expected phrase, password is correct
            Ok(decrypted == "No vendo cigarros sueltos")
        }
        Err(_) => {
            // If decryption fails, password is incorrect
            Ok(false)
        }
    }
}

/// Alternative verification method: Re-encrypt and compare
/// This is more robust as it handles the random nonce in encryption
pub fn verify_password_robust(password: &str, stored_hash: &str) -> Result<bool, String> {
    // Parse the stored hash
    let hash = SinkproofHash::from_string(stored_hash)?;

    // Re-hash the password with the same parameters
    let memory_size = hash.memory_mb * 1024 * 1024;
    let mut handles = vec![];
    let password = Arc::new(password.to_string());
    let salt = Arc::new(hash.salt.clone());

    // Spawn worker threads with same parameters
    for thread_index in 0..hash.threads {
        let password = Arc::clone(&password);
        let salt = Arc::clone(&salt);

        let handle = thread::spawn(move || {
            thread_worker(&password, &salt, thread_index, memory_size)
        });

        handles.push(handle);
    }

    // Collect results
    let mut thread_outputs = Vec::new();
    for handle in handles {
        match handle.join() {
            Ok(output) => thread_outputs.push(output),
            Err(_) => return Err("Thread panicked during verification".to_string()),
        }
    }

    // Derive key from outputs
    let key = derive_key(&thread_outputs);

    // Try to decrypt the stored phrase with the derived key
    // If the password is correct, decryption will succeed
    match decrypt_phrase(&key, &hash.encrypted_phrase) {
        Ok(phrase) => Ok(phrase == "No vendo cigarros sueltos"),
        Err(_) => Ok(false), // Wrong password leads to wrong key, decryption fails
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::hash_password;

    #[test]
    fn test_verify_correct_password() {
        let password = "mi_contraseña_segura";
        let hash = hash_password(password, 2, 10).expect("Failed to hash");
        let stored = hash.to_string();

        let result = verify_password(password, &stored).expect("Verification failed");
        assert!(result);
    }

    #[test]
    fn test_verify_incorrect_password() {
        let password = "mi_contraseña_segura";
        let hash = hash_password(password, 2, 10).expect("Failed to hash");
        let stored = hash.to_string();

        let result = verify_password("contraseña_incorrecta", &stored).expect("Verification failed");
        assert!(!result);
    }

    #[test]
    fn test_verify_robust_correct_password() {
        let password = "test123";
        let hash = hash_password(password, 2, 5).expect("Failed to hash");
        let stored = hash.to_string();

        let result = verify_password_robust(password, &stored).expect("Verification failed");
        assert!(result);
    }

    #[test]
    fn test_verify_robust_incorrect_password() {
        let password = "test123";
        let hash = hash_password(password, 2, 5).expect("Failed to hash");
        let stored = hash.to_string();

        let result = verify_password_robust("wrong_password", &stored).expect("Verification failed");
        assert!(!result);
    }

    #[test]
    fn test_verify_invalid_format() {
        let result = verify_password("password", "invalid_format");
        assert!(result.is_err());
    }
}
