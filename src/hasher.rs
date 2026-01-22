use rand::RngCore;
use sha2::{Sha256, Digest};
use std::thread;
use std::sync::Arc;
use crate::storage::SinkproofHash;
use crate::encryption::encrypt_phrase;

/// Generate a cryptographically secure random salt
pub fn generate_salt() -> Vec<u8> {
    let mut salt = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Hash a password using the Sinkproof algorithm
/// 
/// # Arguments
/// * `password` - The password to hash
/// * `threads` - Number of threads to use (must be > 0)
/// * `memory_mb` - Amount of memory to fill per thread in MB (must be > 0)
/// 
/// # Returns
/// A SinkproofHash containing all parameters and the encrypted verification phrase
pub fn hash_password(password: &str, threads: usize, memory_mb: usize) -> Result<SinkproofHash, String> {
    if threads == 0 {
        return Err("Number of threads must be greater than 0".to_string());
    }
    if memory_mb == 0 {
        return Err("Memory size must be greater than 0".to_string());
    }

    // Generate random salt
    let salt = generate_salt();
    
    // Calculate memory size per thread in bytes
    let memory_size = memory_mb * 1024 * 1024;
    
    // Create thread handles
    let mut handles = vec![];
    let password = Arc::new(password.to_string());
    let salt = Arc::new(salt.clone());
    
    // Spawn worker threads
    for thread_index in 0..threads {
        let password = Arc::clone(&password);
        let salt = Arc::clone(&salt);
        
        let handle = thread::spawn(move || {
            thread_worker(&password, &salt, thread_index, memory_size)
        });
        
        handles.push(handle);
    }
    
    // Collect results from all threads
    let mut thread_outputs = Vec::new();
    for handle in handles {
        match handle.join() {
            Ok(output) => thread_outputs.push(output),
            Err(_) => return Err("Thread panicked during execution".to_string()),
        }
    }
    
    // Derive encryption key from thread outputs
    let key = derive_key(&thread_outputs);
    
    // Encrypt verification phrase
    let encrypted_phrase = encrypt_phrase(&key)?;
    
    Ok(SinkproofHash {
        version: "v1".to_string(),
        threads,
        memory_mb,
        salt: (*salt).clone(),
        encrypted_phrase,
    })
}

/// Worker function executed by each thread
/// Fills memory with complex mathematical operations and returns last 512 bytes
pub fn thread_worker(password: &str, salt: &[u8], thread_index: usize, memory_size: usize) -> Vec<u8> {
    // Create initial input: password || salt || thread_index
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);
    hasher.update(thread_index.to_le_bytes());
    let mut current_hash = hasher.finalize().to_vec();
    
    // Calculate number of iterations to fill memory
    // Each iteration produces 32 bytes (SHA-256 output)
    let iterations = memory_size / 32;
    
    // Memory buffer to store intermediate results
    let mut memory: Vec<Vec<u8>> = Vec::with_capacity(iterations);
    
    // Fill memory with complex operations
    for i in 0..iterations {
        // SHA-256 chaining
        let mut hasher = Sha256::new();
        hasher.update(&current_hash);
        hasher.update(i.to_le_bytes());
        current_hash = hasher.finalize().to_vec();
        
        // XOR mixing with previous data (if available)
        if i > 0 {
            let prev_index = i % memory.len();
            for (j, byte) in current_hash.iter_mut().enumerate() {
                *byte ^= memory[prev_index][j % 32];
            }
        }
        
        // Byte rotation for additional complexity
        if i % 100 == 0 {
            current_hash.rotate_left((i % 16) + 1);
        }
        
        // Store in memory
        memory.push(current_hash.clone());
        
        // Periodic mixing with distant memory locations
        if i > 1000 && i % 500 == 0 {
            let distant_index = (i / 2) % memory.len();
            let mut hasher = Sha256::new();
            hasher.update(&current_hash);
            hasher.update(&memory[distant_index]);
            current_hash = hasher.finalize().to_vec();
        }
    }
    
    // Return last 512 bytes
    // We take the last 16 entries (16 * 32 = 512 bytes)
    let mut result = Vec::with_capacity(512);
    let start_index = if memory.len() > 16 { memory.len() - 16 } else { 0 };
    
    for chunk in &memory[start_index..] {
        result.extend_from_slice(chunk);
    }
    
    // Pad with final hash if needed
    while result.len() < 512 {
        result.extend_from_slice(&current_hash);
    }
    
    result.truncate(512);
    result
}

/// Derive encryption key from thread outputs
/// Combines all thread outputs and hashes them to create a 32-byte key
pub fn derive_key(thread_outputs: &[Vec<u8>]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    
    // Hash all thread outputs together
    for output in thread_outputs {
        hasher.update(output);
    }
    
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_salt_generation() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        
        assert_eq!(salt1.len(), 32);
        assert_eq!(salt2.len(), 32);
        assert_ne!(salt1, salt2); // Should be different
    }

    #[test]
    fn test_thread_worker_deterministic() {
        let password = "test";
        let salt = vec![1, 2, 3, 4];
        let memory_size = 1024; // 1 KB
        
        let output1 = thread_worker(password, &salt, 0, memory_size);
        let output2 = thread_worker(password, &salt, 0, memory_size);
        
        assert_eq!(output1.len(), 512);
        assert_eq!(output1, output2); // Same inputs should produce same output
    }

    #[test]
    fn test_different_thread_index_produces_different_output() {
        let password = "test";
        let salt = vec![1, 2, 3, 4];
        let memory_size = 1024;
        
        let output1 = thread_worker(password, &salt, 0, memory_size);
        let output2 = thread_worker(password, &salt, 1, memory_size);
        
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_hash_password_success() {
        let result = hash_password("test_password", 2, 5);
        assert!(result.is_ok());
        
        let hash = result.unwrap();
        assert_eq!(hash.threads, 2);
        assert_eq!(hash.memory_mb, 5);
        assert_eq!(hash.salt.len(), 32);
        assert!(!hash.encrypted_phrase.is_empty());
    }

    #[test]
    fn test_hash_password_invalid_params() {
        assert!(hash_password("test", 0, 5).is_err());
        assert!(hash_password("test", 2, 0).is_err());
    }
}
