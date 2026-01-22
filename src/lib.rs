/// Sinkproof v1 - Custom Password Hashing System
/// 
/// A memory-hard password hashing algorithm that uses multi-threading,
/// complex mathematical operations, and encryption for password security.

pub mod hasher;
pub mod encryption;
pub mod storage;
pub mod verifier;

// Re-export main public API
pub use hasher::hash_password;
pub use verifier::verify_password;
pub use storage::SinkproofHash;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify() {
        let password = "mi_contraseña_segura";
        let hash = hash_password(password, 2, 10).expect("Failed to hash password");
        
        // Verify correct password
        assert!(verify_password(password, &hash.to_string()).expect("Failed to verify"));
        
        // Verify incorrect password
        assert!(!verify_password("contraseña_incorrecta", &hash.to_string()).expect("Failed to verify"));
    }

    #[test]
    fn test_different_salts() {
        let password = "test123";
        let hash1 = hash_password(password, 2, 10).expect("Failed to hash");
        let hash2 = hash_password(password, 2, 10).expect("Failed to hash");
        
        // Same password should produce different hashes due to random salt
        assert_ne!(hash1.to_string(), hash2.to_string());
        
        // But both should verify correctly
        assert!(verify_password(password, &hash1.to_string()).expect("Failed to verify"));
        assert!(verify_password(password, &hash2.to_string()).expect("Failed to verify"));
    }

    #[test]
    fn test_storage_format() {
        let password = "test_password";
        let hash = hash_password(password, 4, 50).expect("Failed to hash");
        let stored = hash.to_string();
        
        // Check format starts with Sinkproof:v1:
        assert!(stored.starts_with("Sinkproof:v1:"));
        
        // Parse it back
        let parsed = SinkproofHash::from_string(&stored).expect("Failed to parse");
        assert_eq!(parsed.threads, 4);
        assert_eq!(parsed.memory_mb, 50);
    }
}
