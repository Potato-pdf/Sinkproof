use base64::{Engine as _, engine::general_purpose};

/// Represents a complete Sinkproof hash with all parameters
#[derive(Debug, Clone)]
pub struct SinkproofHash {
    pub version: String,
    pub threads: usize,
    pub memory_mb: usize,
    pub salt: Vec<u8>,
    pub encrypted_phrase: Vec<u8>,
}

impl SinkproofHash {
    /// Serialize the hash to storage format
    /// Format: Sinkproof:v1:threads:memory:salt_base64:encrypted_phrase_base64
    pub fn to_string(&self) -> String {
        let salt_b64 = general_purpose::STANDARD.encode(&self.salt);
        let phrase_b64 = general_purpose::STANDARD.encode(&self.encrypted_phrase);
        
        format!(
            "Sinkproof:{}:{}:{}:{}:{}",
            self.version,
            self.threads,
            self.memory_mb,
            salt_b64,
            phrase_b64
        )
    }

    /// Parse a hash from storage format
    pub fn from_string(hash_str: &str) -> Result<Self, String> {
        let parts: Vec<&str> = hash_str.split(':').collect();
        
        if parts.len() != 6 {
            return Err(format!("Invalid hash format: expected 6 parts, got {}", parts.len()));
        }

        if parts[0] != "Sinkproof" {
            return Err(format!("Invalid hash name: expected 'Sinkproof', got '{}'", parts[0]));
        }

        let version = parts[1].to_string();
        
        let threads = parts[2]
            .parse::<usize>()
            .map_err(|e| format!("Invalid threads value: {}", e))?;

        let memory_mb = parts[3]
            .parse::<usize>()
            .map_err(|e| format!("Invalid memory value: {}", e))?;

        let salt = general_purpose::STANDARD
            .decode(parts[4])
            .map_err(|e| format!("Invalid salt encoding: {}", e))?;

        let encrypted_phrase = general_purpose::STANDARD
            .decode(parts[5])
            .map_err(|e| format!("Invalid encrypted phrase encoding: {}", e))?;

        Ok(SinkproofHash {
            version,
            threads,
            memory_mb,
            salt,
            encrypted_phrase,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialization_roundtrip() {
        let original = SinkproofHash {
            version: "v1".to_string(),
            threads: 4,
            memory_mb: 100,
            salt: vec![1, 2, 3, 4, 5, 6, 7, 8],
            encrypted_phrase: vec![10, 20, 30, 40, 50],
        };

        let serialized = original.to_string();
        let deserialized = SinkproofHash::from_string(&serialized)
            .expect("Failed to deserialize");

        assert_eq!(original.version, deserialized.version);
        assert_eq!(original.threads, deserialized.threads);
        assert_eq!(original.memory_mb, deserialized.memory_mb);
        assert_eq!(original.salt, deserialized.salt);
        assert_eq!(original.encrypted_phrase, deserialized.encrypted_phrase);
    }

    #[test]
    fn test_format_structure() {
        let hash = SinkproofHash {
            version: "v1".to_string(),
            threads: 2,
            memory_mb: 50,
            salt: vec![1, 2, 3],
            encrypted_phrase: vec![4, 5, 6],
        };

        let serialized = hash.to_string();
        
        assert!(serialized.starts_with("Sinkproof:v1:2:50:"));
        
        let parts: Vec<&str> = serialized.split(':').collect();
        assert_eq!(parts.len(), 6);
        assert_eq!(parts[0], "Sinkproof");
        assert_eq!(parts[1], "v1");
        assert_eq!(parts[2], "2");
        assert_eq!(parts[3], "50");
    }

    #[test]
    fn test_invalid_format() {
        assert!(SinkproofHash::from_string("invalid").is_err());
        assert!(SinkproofHash::from_string("Sinkproof:v1:2:50").is_err());
        assert!(SinkproofHash::from_string("WrongName:v1:2:50:AQID:BAUG").is_err());
    }

    #[test]
    fn test_invalid_numbers() {
        assert!(SinkproofHash::from_string("Sinkproof:v1:abc:50:AQID:BAUG").is_err());
        assert!(SinkproofHash::from_string("Sinkproof:v1:2:xyz:AQID:BAUG").is_err());
    }

    #[test]
    fn test_invalid_base64() {
        assert!(SinkproofHash::from_string("Sinkproof:v1:2:50:!!!:BAUG").is_err());
        assert!(SinkproofHash::from_string("Sinkproof:v1:2:50:AQID:!!!").is_err());
    }
}
