use crate::{
    error::{BpError, BpResult},
    types::{Bundle, Eid},
};
use bytes::Bytes;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use ring::{aead, hmac, rand::{SecureRandom, SystemRandom}};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecurityOperation {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityBlock {
    pub operation: SecurityOperation,
    pub algorithm: String,
    pub key_id: String,
    pub data: Bytes,
}

impl SecurityBlock {
    pub fn new(operation: SecurityOperation, algorithm: &str, key_id: &str) -> Self {
        Self {
            operation,
            algorithm: algorithm.to_string(),
            key_id: key_id.to_string(),
            data: Bytes::new(),
        }
    }

    pub fn with_data(mut self, data: Bytes) -> Self {
        self.data = data;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    pub name: String,
    pub operation: SecurityOperation,
    pub algorithm: String,
    pub key_id: String,
    pub target_eids: Vec<Eid>,
    pub enabled: bool,
}

impl SecurityPolicy {
    pub fn new(name: &str, operation: SecurityOperation) -> Self {
        Self {
            name: name.to_string(),
            operation,
            algorithm: "AES-256-GCM".to_string(),
            key_id: "default".to_string(),
            target_eids: Vec::new(),
            enabled: true,
        }
    }

    pub fn with_algorithm(mut self, algorithm: &str) -> Self {
        self.algorithm = algorithm.to_string();
        self
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = key_id.to_string();
        self
    }

    pub fn with_target_eid(mut self, eid: Eid) -> Self {
        self.target_eids.push(eid);
        self
    }

    pub fn applies_to(&self, eid: &Eid) -> bool {
        self.enabled && (self.target_eids.is_empty() || self.target_eids.contains(eid))
    }
}

pub struct BpsecManager {
    policies: RwLock<HashMap<String, SecurityPolicy>>,
    keys: RwLock<HashMap<String, Bytes>>,
    rng: SystemRandom,
}

impl BpsecManager {
    pub fn new() -> Self {
        Self {
            policies: RwLock::new(HashMap::new()),
            keys: RwLock::new(HashMap::new()),
            rng: SystemRandom::new(),
        }
    }

    pub fn add_policy(&self, policy: SecurityPolicy) -> BpResult<()> {
        let mut policies = self.policies.write();
        if policies.contains_key(&policy.name) {
            return Err(BpError::Duplicate);
        }
        policies.insert(policy.name.clone(), policy);
        Ok(())
    }

    pub fn remove_policy(&self, name: &str) -> BpResult<()> {
        self.policies.write().remove(name).ok_or(BpError::NotFound)?;
        Ok(())
    }

    pub fn get_policy(&self, name: &str) -> Option<SecurityPolicy> {
        self.policies.read().get(name).cloned()
    }

    pub fn list_policies(&self) -> Vec<SecurityPolicy> {
        self.policies.read().values().cloned().collect()
    }

    pub fn add_key(&self, key_id: &str, key: Bytes) -> BpResult<()> {
        let mut keys = self.keys.write();
        if keys.contains_key(key_id) {
            return Err(BpError::Duplicate);
        }
        keys.insert(key_id.to_string(), key);
        Ok(())
    }

    pub fn remove_key(&self, key_id: &str) -> BpResult<()> {
        self.keys.write().remove(key_id).ok_or(BpError::NotFound)?;
        Ok(())
    }

    pub fn apply_security(&self, bundle: &Bundle) -> BpResult<Bundle> {
        let policies = self.policies.read();
        let applicable_policies: Vec<_> = policies.values()
            .filter(|p| p.applies_to(&bundle.dest_eid))
            .collect();

        if applicable_policies.is_empty() {
            return Ok(bundle.clone());
        }

        let mut secured_bundle = bundle.clone();
        
        for policy in applicable_policies {
            secured_bundle = self.apply_policy(&secured_bundle, policy)?;
        }

        Ok(secured_bundle)
    }

    fn apply_policy(&self, bundle: &Bundle, policy: &SecurityPolicy) -> BpResult<Bundle> {
        let keys = self.keys.read();
        let key = keys.get(&policy.key_id).ok_or(BpError::NotFound)?;

        match policy.operation {
            SecurityOperation::Encrypt => self.encrypt_bundle(bundle, key, &policy.algorithm),
            SecurityOperation::Sign => self.sign_bundle(bundle, key, &policy.algorithm),
            _ => Err(BpError::Protocol("Unsupported operation".to_string())),
        }
    }

    fn encrypt_bundle(&self, bundle: &Bundle, key: &Bytes, algorithm: &str) -> BpResult<Bundle> {
        let encrypted_payload = self.encrypt_data(&bundle.payload, key, algorithm)?;
        let mut secured_bundle = bundle.clone();
        secured_bundle.payload = encrypted_payload;
        secured_bundle.metadata.insert("security_applied".to_string(), "encryption".to_string());
        secured_bundle.metadata.insert("encryption_algorithm".to_string(), algorithm.to_string());
        Ok(secured_bundle)
    }

    fn sign_bundle(&self, bundle: &Bundle, key: &Bytes, algorithm: &str) -> BpResult<Bundle> {
        let signature = self.sign_data(&bundle.payload, key, algorithm)?;
        let mut secured_bundle = bundle.clone();
        secured_bundle.metadata.insert("security_applied".to_string(), "signature".to_string());
        secured_bundle.metadata.insert("signature_algorithm".to_string(), algorithm.to_string());
        secured_bundle.metadata.insert("signature".to_string(), hex::encode(signature));
        Ok(secured_bundle)
    }

    fn encrypt_data(&self, data: &Bytes, key: &Bytes, algorithm: &str) -> BpResult<Bytes> {
        match algorithm {
            "AES-256-GCM" => {
                if key.len() != 32 {
                    return Err(BpError::Security("Invalid key length for AES-256".to_string()));
                }

                let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, key)
                    .map_err(|_| BpError::Security("Invalid key".to_string()))?;
                
                let mut nonce_bytes = [0u8; 12];
                self.rng.fill(&mut nonce_bytes)
                    .map_err(|_| BpError::Security("RNG failure".to_string()))?;

                let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
                let sealing_key = aead::LessSafeKey::new(unbound_key);

                let mut in_out = data.to_vec();
                sealing_key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
                    .map_err(|_| BpError::Security("Encryption failed".to_string()))?;

                let mut result = Vec::with_capacity(12 + in_out.len());
                result.extend_from_slice(&nonce_bytes);
                result.extend_from_slice(&in_out);

                Ok(Bytes::from(result))
            }
            _ => Err(BpError::Protocol(format!("Unsupported encryption algorithm: {}", algorithm))),
        }
    }

    fn sign_data(&self, data: &Bytes, key: &Bytes, algorithm: &str) -> BpResult<Bytes> {
        match algorithm {
            "HMAC-SHA256" => {
                let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key);
                let signature = hmac::sign(&signing_key, data);
                Ok(Bytes::from(signature.as_ref().to_vec()))
            }
            _ => Err(BpError::Protocol(format!("Unsupported signature algorithm: {}", algorithm))),
        }
    }

    pub fn verify_bundle(&self, bundle: &Bundle) -> BpResult<bool> {
        if !bundle.metadata.contains_key("security_applied") {
            return Ok(true);
        }

        let security_type = bundle.metadata.get("security_applied").unwrap();
        match security_type.as_str() {
            "signature" => self.verify_signature(bundle),
            _ => Ok(true),
        }
    }

    fn verify_signature(&self, bundle: &Bundle) -> BpResult<bool> {
        let signature_hex = bundle.metadata.get("signature")
            .ok_or_else(|| BpError::Protocol("Missing signature".to_string()))?;
        let signature = hex::decode(signature_hex)
            .map_err(|_| BpError::Protocol("Invalid signature format".to_string()))?;
        
        let default_algo = "HMAC-SHA256".to_string();
        let algorithm = bundle.metadata.get("signature_algorithm").unwrap_or(&default_algo);
        
        let keys = self.keys.read();
        for key in keys.values() {
            if let Ok(computed_signature) = self.sign_data(&bundle.payload, key, algorithm) {
                if computed_signature == signature {
                    return Ok(true);
                }
            }
        }
        
        Ok(false)
    }

    pub fn decrypt_bundle(&self, bundle: &Bundle) -> BpResult<Bundle> {
        if !bundle.metadata.contains_key("security_applied") {
            return Ok(bundle.clone());
        }

        let security_type = bundle.metadata.get("security_applied").unwrap();
        if security_type != "encryption" {
            return Ok(bundle.clone());
        }

        let algorithm = bundle.metadata.get("encryption_algorithm")
            .map(|s| s.as_str())
            .unwrap_or("AES-256-GCM");

        let keys = self.keys.read();
        for key in keys.values() {
            if let Ok(decrypted_payload) = self.decrypt_data(&bundle.payload, key, algorithm) {
                let mut decrypted_bundle = bundle.clone();
                decrypted_bundle.payload = decrypted_payload;
                decrypted_bundle.metadata.remove("security_applied");
                decrypted_bundle.metadata.remove("encryption_algorithm");
                return Ok(decrypted_bundle);
            }
        }

        Err(BpError::Security("Failed to decrypt bundle".to_string()))
    }

    fn decrypt_data(&self, data: &Bytes, key: &Bytes, algorithm: &str) -> BpResult<Bytes> {
        match algorithm {
            "AES-256-GCM" => {
                if data.len() < 12 {
                    return Err(BpError::Security("Invalid encrypted data length".to_string()));
                }

                let (nonce_bytes, ciphertext) = data.split_at(12);
                let nonce = aead::Nonce::try_assume_unique_for_key(nonce_bytes)
                    .map_err(|_| BpError::Security("Invalid nonce".to_string()))?;

                let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, key)
                    .map_err(|_| BpError::Security("Invalid key".to_string()))?;
                
                let opening_key = aead::LessSafeKey::new(unbound_key);
                let mut in_out = ciphertext.to_vec();

                opening_key.open_in_place(nonce, aead::Aad::empty(), &mut in_out)
                    .map_err(|_| BpError::Security("Decryption failed".to_string()))?;

                in_out.truncate(in_out.len() - 16);
                Ok(Bytes::from(in_out))
            }
            _ => Err(BpError::Protocol(format!("Unsupported decryption algorithm: {}", algorithm))),
        }
    }
}

impl Default for BpsecManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Bundle, Eid, Priority, BpTimestamp};
    use std::collections::HashMap;
    use std::time::Duration;
    use uuid::Uuid;

    fn create_test_bundle() -> Bundle {
        Bundle {
            id: Uuid::new_v4(),
            source_eid: Eid::new("ipn:1.1").unwrap(),
            dest_eid: Eid::new("ipn:2.1").unwrap(),
            report_to_eid: None,
            creation_time: BpTimestamp::now(),
            ttl: Duration::from_secs(3600),
            priority: Priority::Standard,
            custody: crate::types::Custody::None,
            payload: Bytes::from("Hello, BPSEC!"),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_bpsec_manager_creation() {
        let manager = BpsecManager::new();
        assert_eq!(manager.list_policies().len(), 0);
    }

    #[test]
    fn test_policy_management() {
        let manager = BpsecManager::new();
        
        let policy = SecurityPolicy::new("test-policy", SecurityOperation::Encrypt)
            .with_algorithm("AES-256-GCM")
            .with_key_id("test-key")
            .with_target_eid(Eid::new("ipn:2.1").unwrap());

        assert!(manager.add_policy(policy.clone()).is_ok());
        assert_eq!(manager.list_policies().len(), 1);
        
        assert!(manager.add_policy(policy).is_err());
        
        let retrieved = manager.get_policy("test-policy");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().algorithm, "AES-256-GCM");
        
        assert!(manager.remove_policy("test-policy").is_ok());
        assert_eq!(manager.list_policies().len(), 0);
    }

    #[test]
    fn test_key_management() {
        let manager = BpsecManager::new();
        let key = Bytes::from(vec![0u8; 32]);
        
        assert!(manager.add_key("test-key", key.clone()).is_ok());
        assert!(manager.add_key("test-key", key).is_err());
        assert!(manager.remove_key("test-key").is_ok());
        assert!(manager.remove_key("nonexistent").is_err());
    }

    #[test]
    fn test_encryption_decryption() {
        let manager = BpsecManager::new();
        let key = Bytes::from(vec![1u8; 32]);
        let test_data = Bytes::from("Test encryption data");
        
        manager.add_key("test-key", key).unwrap();
        
        let encrypted = manager.encrypt_data(&test_data, &Bytes::from(vec![1u8; 32]), "AES-256-GCM").unwrap();
        assert_ne!(encrypted, test_data);
        assert!(encrypted.len() > test_data.len());
        
        let decrypted = manager.decrypt_data(&encrypted, &Bytes::from(vec![1u8; 32]), "AES-256-GCM").unwrap();
        assert_eq!(decrypted, test_data);
    }

    #[test]
    fn test_signing_verification() {
        let manager = BpsecManager::new();
        let key = Bytes::from(vec![2u8; 32]);
        let test_data = Bytes::from("Test signing data");
        
        let signature = manager.sign_data(&test_data, &key, "HMAC-SHA256").unwrap();
        assert!(!signature.is_empty());
        
        let same_signature = manager.sign_data(&test_data, &key, "HMAC-SHA256").unwrap();
        assert_eq!(signature, same_signature);
        
        let different_data = Bytes::from("Different data");
        let different_signature = manager.sign_data(&different_data, &key, "HMAC-SHA256").unwrap();
        assert_ne!(signature, different_signature);
    }

    #[test]
    fn test_bundle_encryption() {
        let manager = BpsecManager::new();
        let key = Bytes::from(vec![3u8; 32]);
        manager.add_key("test-key", key).unwrap();
        
        let policy = SecurityPolicy::new("encrypt-policy", SecurityOperation::Encrypt)
            .with_algorithm("AES-256-GCM")
            .with_key_id("test-key");
        
        manager.add_policy(policy).unwrap();
        
        let bundle = create_test_bundle();
        let original_payload = bundle.payload.clone();
        
        let secured_bundle = manager.apply_security(&bundle).unwrap();
        assert_ne!(secured_bundle.payload, original_payload);
        assert_eq!(secured_bundle.metadata.get("security_applied"), Some(&"encryption".to_string()));
        
        let decrypted_bundle = manager.decrypt_bundle(&secured_bundle).unwrap();
        assert_eq!(decrypted_bundle.payload, original_payload);
        assert!(!decrypted_bundle.metadata.contains_key("security_applied"));
    }

    #[test]
    fn test_bundle_signing() {
        let manager = BpsecManager::new();
        let key = Bytes::from(vec![4u8; 32]);
        manager.add_key("test-key", key).unwrap();
        
        let policy = SecurityPolicy::new("sign-policy", SecurityOperation::Sign)
            .with_algorithm("HMAC-SHA256")
            .with_key_id("test-key");
        
        manager.add_policy(policy).unwrap();
        
        let bundle = create_test_bundle();
        let secured_bundle = manager.apply_security(&bundle).unwrap();
        
        assert_eq!(secured_bundle.metadata.get("security_applied"), Some(&"signature".to_string()));
        assert!(secured_bundle.metadata.contains_key("signature"));
        
        assert!(manager.verify_bundle(&secured_bundle).unwrap());
        
        let mut tampered_bundle = secured_bundle.clone();
        tampered_bundle.payload = Bytes::from("Tampered data");
        assert!(!manager.verify_bundle(&tampered_bundle).unwrap());
    }

    #[test]
    fn test_policy_application_conditions() {
        let manager = BpsecManager::new();
        
        let policy = SecurityPolicy::new("selective-policy", SecurityOperation::Sign)
            .with_target_eid(Eid::new("ipn:3.1").unwrap());
        
        manager.add_policy(policy).unwrap();
        
        let bundle = create_test_bundle();
        let result = manager.apply_security(&bundle).unwrap();
        
        assert!(!result.metadata.contains_key("security_applied"));
    }

    #[test]
    fn test_invalid_algorithms() {
        let manager = BpsecManager::new();
        let key = Bytes::from(vec![5u8; 32]);
        let data = Bytes::from("test data");
        
        assert!(manager.encrypt_data(&data, &key, "INVALID-ALGO").is_err());
        assert!(manager.sign_data(&data, &key, "INVALID-ALGO").is_err());
    }

    #[test]
    fn test_invalid_key_lengths() {
        let manager = BpsecManager::new();
        let short_key = Bytes::from(vec![6u8; 16]);
        let data = Bytes::from("test data");
        
        assert!(manager.encrypt_data(&data, &short_key, "AES-256-GCM").is_err());
    }
} 