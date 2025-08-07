//! SASL (Simple Authentication and Security Layer) support for IRC
//!
//! This module provides SASL authentication mechanisms commonly used in IRCv3.

use crate::error::{IronError, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use rand::RngCore;
use sha2::{Sha256, Digest};

type HmacSha256 = Hmac<Sha256>;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// SASL authentication mechanisms
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum SaslMechanism {
    /// PLAIN mechanism (username/password)
    Plain,
    /// EXTERNAL mechanism (client certificate)
    External,
    /// SCRAM-SHA-256 mechanism
    ScramSha256,
}

impl SaslMechanism {
    /// Parse mechanism from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "PLAIN" => Some(SaslMechanism::Plain),
            "EXTERNAL" => Some(SaslMechanism::External),
            "SCRAM-SHA-256" => Some(SaslMechanism::ScramSha256),
            _ => None,
        }
    }

    /// Get mechanism name as string
    pub fn as_str(&self) -> &str {
        match self {
            SaslMechanism::Plain => "PLAIN",
            SaslMechanism::External => "EXTERNAL",
            SaslMechanism::ScramSha256 => "SCRAM-SHA-256",
        }
    }

    /// Check if this mechanism is considered secure
    pub fn is_secure(&self) -> bool {
        match self {
            SaslMechanism::Plain => false, // Only secure over TLS
            SaslMechanism::External => true,
            SaslMechanism::ScramSha256 => true,
        }
    }

    /// Get security strength (higher is better)
    pub fn security_strength(&self) -> u8 {
        match self {
            SaslMechanism::Plain => 1,
            SaslMechanism::External => 3,
            SaslMechanism::ScramSha256 => 2,
        }
    }
}

/// SASL authentication context
pub struct SaslAuth {
    mechanism: SaslMechanism,
    username: String,
    password: Option<String>,
    client_nonce: Option<String>,
    server_nonce: Option<String>,
    salt: Option<Vec<u8>>,
    iterations: Option<u32>,
    state: SaslState,
}

/// SASL authentication state
#[derive(Debug, Clone, PartialEq)]
enum SaslState {
    Initial,
    Authenticating,
    Success,
    Failed,
}

impl SaslAuth {
    /// Create new SASL authentication context
    pub fn new(mechanism: SaslMechanism, username: String, password: Option<String>) -> Self {
        Self {
            mechanism,
            username,
            password,
            client_nonce: None,
            server_nonce: None,
            salt: None,
            iterations: None,
            state: SaslState::Initial,
        }
    }

    /// Generate initial authentication message
    pub fn generate_initial_response(&mut self) -> Result<String> {
        match self.mechanism {
            SaslMechanism::Plain => self.generate_plain_response(),
            SaslMechanism::External => Ok(BASE64.encode("")), // Empty for EXTERNAL
            SaslMechanism::ScramSha256 => self.generate_scram_initial(),
        }
    }

    /// Process server challenge and generate response
    pub fn process_challenge(&mut self, challenge: &str) -> Result<String> {
        let challenge_data = BASE64.decode(challenge)
            .map_err(|_| IronError::Sasl("Invalid base64 in challenge".to_string()))?;
        
        let challenge_str = String::from_utf8(challenge_data)
            .map_err(|_| IronError::Sasl("Invalid UTF-8 in challenge".to_string()))?;

        match self.mechanism {
            SaslMechanism::Plain => {
                // PLAIN doesn't typically use challenges
                Err(IronError::Sasl("PLAIN doesn't use challenges".to_string()))
            }
            SaslMechanism::External => {
                // EXTERNAL doesn't use challenges
                Err(IronError::Sasl("EXTERNAL doesn't use challenges".to_string()))
            }
            SaslMechanism::ScramSha256 => self.process_scram_challenge(&challenge_str),
        }
    }

    /// Check if authentication is complete
    pub fn is_complete(&self) -> bool {
        matches!(self.state, SaslState::Success | SaslState::Failed)
    }

    /// Check if authentication succeeded
    pub fn is_success(&self) -> bool {
        matches!(self.state, SaslState::Success)
    }

    /// Mark authentication as successful
    pub fn mark_success(&mut self) {
        self.state = SaslState::Success;
    }

    /// Mark authentication as failed
    pub fn mark_failed(&mut self) {
        self.state = SaslState::Failed;
    }

    /// Generate PLAIN mechanism response
    fn generate_plain_response(&self) -> Result<String> {
        let password = self.password.as_ref()
            .ok_or_else(|| IronError::Sasl("Password required for PLAIN".to_string()))?;

        // PLAIN format: \0username\0password
        let auth_string = format!("\0{}\0{}", self.username, password);
        Ok(BASE64.encode(auth_string.as_bytes()))
    }

    /// Generate SCRAM-SHA-256 initial message
    fn generate_scram_initial(&mut self) -> Result<String> {
        // Generate client nonce
        let mut nonce_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let client_nonce = BASE64.encode(&nonce_bytes);
        
        self.client_nonce = Some(client_nonce.clone());
        self.state = SaslState::Authenticating;

        // Initial message: n,,n=username,r=clientnonce
        let initial_message = format!("n,,n={},r={}", self.username, client_nonce);
        Ok(BASE64.encode(initial_message.as_bytes()))
    }

    /// Process SCRAM-SHA-256 server challenge
    fn process_scram_challenge(&mut self, challenge: &str) -> Result<String> {
        let password = self.password.as_ref()
            .ok_or_else(|| IronError::Sasl("Password required for SCRAM".to_string()))?;

        let client_nonce = self.client_nonce.as_ref()
            .ok_or_else(|| IronError::Sasl("Client nonce not set".to_string()))?;

        // Parse server challenge: r=servernonce,s=salt,i=iterations
        let mut server_nonce = None;
        let mut salt = None;
        let mut iterations = None;

        for part in challenge.split(',') {
            if let Some(value) = part.strip_prefix("r=") {
                if !value.starts_with(client_nonce) {
                    return Err(IronError::Sasl("Server nonce doesn't start with client nonce".to_string()));
                }
                server_nonce = Some(value.to_string());
            } else if let Some(value) = part.strip_prefix("s=") {
                salt = Some(BASE64.decode(value)
                    .map_err(|_| IronError::Sasl("Invalid salt encoding".to_string()))?);
            } else if let Some(value) = part.strip_prefix("i=") {
                iterations = Some(value.parse()
                    .map_err(|_| IronError::Sasl("Invalid iteration count".to_string()))?);
            }
        }

        let server_nonce = server_nonce
            .ok_or_else(|| IronError::Sasl("Missing server nonce".to_string()))?;
        let salt = salt
            .ok_or_else(|| IronError::Sasl("Missing salt".to_string()))?;
        let iterations = iterations
            .ok_or_else(|| IronError::Sasl("Missing iteration count".to_string()))?;

        // Store for potential future verification
        self.server_nonce = Some(server_nonce.clone());
        self.salt = Some(salt.clone());
        self.iterations = Some(iterations);

        // Generate salted password
        let salted_password = self.pbkdf2_sha256(password.as_bytes(), &salt, iterations)?;

        // Generate client key
        let client_key = self.hmac_sha256(&salted_password, b"Client Key")?;
        let stored_key = Sha256::digest(&client_key);

        // Create auth message
        let auth_message = format!("n={},r={},r={},s={},i={},c=biws,r={}",
            self.username, client_nonce, server_nonce, 
            BASE64.encode(&salt), iterations, server_nonce);

        // Generate client signature and proof
        let client_signature = self.hmac_sha256(&stored_key, auth_message.as_bytes())?;
        let client_proof: Vec<u8> = client_key.iter().zip(client_signature.iter())
            .map(|(a, b)| a ^ b)
            .collect();

        // Format final response
        let response = format!("c=biws,r={},p={}", server_nonce, BASE64.encode(&client_proof));
        Ok(BASE64.encode(response.as_bytes()))
    }

    /// PBKDF2-SHA256 key derivation
    fn pbkdf2_sha256(&self, password: &[u8], salt: &[u8], iterations: u32) -> Result<Vec<u8>> {
        let mut result = vec![0u8; 32]; // SHA-256 output size
        pbkdf2::<HmacSha256>(password, salt, iterations, &mut result)
            .map_err(|_| IronError::Sasl("PBKDF2 failed".to_string()))?;
        Ok(result)
    }

    /// HMAC-SHA256
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|_| IronError::Sasl("HMAC key error".to_string()))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

/// Choose the best SASL mechanism from available options
pub fn choose_best_mechanism(available: &[String], tls_enabled: bool) -> Option<SaslMechanism> {
    let mut mechanisms: Vec<SaslMechanism> = available
        .iter()
        .filter_map(|s| SaslMechanism::from_str(s))
        .collect();

    // Sort by security strength (descending)
    mechanisms.sort_by(|a, b| b.security_strength().cmp(&a.security_strength()));

    // If TLS is not enabled, prefer secure mechanisms
    if !tls_enabled {
        mechanisms.retain(|m| m.is_secure());
    }

    mechanisms.into_iter().next()
}

/// Validate SASL mechanism list from server
pub fn validate_mechanism_list(mechanisms: &str) -> Result<Vec<String>> {
    let mechs: Vec<String> = mechanisms
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if mechs.is_empty() {
        return Err(IronError::Sasl("No SASL mechanisms available".to_string()));
    }

    // Validate each mechanism name
    for mech in &mechs {
        if mech.len() > 32 || !mech.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(IronError::Sasl(
                format!("Invalid mechanism name: {}", mech)
            ));
        }
    }

    Ok(mechs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mechanism_parsing() {
        assert_eq!(SaslMechanism::from_str("PLAIN"), Some(SaslMechanism::Plain));
        assert_eq!(SaslMechanism::from_str("plain"), Some(SaslMechanism::Plain));
        assert_eq!(SaslMechanism::from_str("SCRAM-SHA-256"), Some(SaslMechanism::ScramSha256));
        assert_eq!(SaslMechanism::from_str("UNKNOWN"), None);
    }

    #[test]
    fn test_mechanism_security() {
        assert!(!SaslMechanism::Plain.is_secure());
        assert!(SaslMechanism::External.is_secure());
        assert!(SaslMechanism::ScramSha256.is_secure());
    }

    #[test]
    fn test_plain_authentication() {
        let mut auth = SaslAuth::new(
            SaslMechanism::Plain,
            "testuser".to_string(),
            Some("testpass".to_string())
        );

        let response = auth.generate_initial_response().unwrap();
        let decoded = BASE64.decode(&response).unwrap();
        let auth_string = String::from_utf8(decoded).unwrap();
        
        assert_eq!(auth_string, "\0testuser\0testpass");
    }

    #[test]
    fn test_external_authentication() {
        let mut auth = SaslAuth::new(
            SaslMechanism::External,
            "testuser".to_string(),
            None
        );

        let response = auth.generate_initial_response().unwrap();
        assert_eq!(response, BASE64.encode(""));
    }

    #[test]
    fn test_mechanism_selection() {
        let available = vec!["PLAIN".to_string(), "SCRAM-SHA-256".to_string(), "EXTERNAL".to_string()];
        
        // With TLS, should prefer EXTERNAL (highest security strength)
        let best = choose_best_mechanism(&available, true).unwrap();
        assert_eq!(best, SaslMechanism::External);
        
        // Without TLS, should exclude PLAIN and prefer EXTERNAL
        let best_no_tls = choose_best_mechanism(&available, false).unwrap();
        assert_eq!(best_no_tls, SaslMechanism::External);
    }

    #[test]
    fn test_mechanism_validation() {
        assert!(validate_mechanism_list("PLAIN,SCRAM-SHA-256").is_ok());
        assert!(validate_mechanism_list("PLAIN, EXTERNAL , SCRAM-SHA-256").is_ok());
        assert!(validate_mechanism_list("").is_err());
        assert!(validate_mechanism_list("INVALID@MECH").is_err());
    }

    #[test]
    fn test_sasl_state_management() {
        let mut auth = SaslAuth::new(
            SaslMechanism::Plain,
            "user".to_string(),
            Some("pass".to_string())
        );

        assert!(!auth.is_complete());
        assert!(!auth.is_success());

        auth.mark_success();
        assert!(auth.is_complete());
        assert!(auth.is_success());

        auth.mark_failed();
        assert!(auth.is_complete());
        assert!(!auth.is_success());
    }
}