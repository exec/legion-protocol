//! IRCv3 capability negotiation and management
//!
//! This module provides comprehensive support for IRCv3 capability negotiation,
//! including both stable and bleeding-edge capabilities from the 2024-2025 specifications.

use crate::error::{IronError, Result};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Represents an IRCv3 capability
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Capability {
    // Core IRCv3 capabilities (Ratified)
    MessageTags,
    ServerTime,
    AccountNotify,
    AccountTag,
    AwayNotify,
    Batch,
    CapNotify,
    ChgHost,
    EchoMessage,
    ExtendedJoin,
    InviteNotify,
    LabeledResponse,
    Monitor,
    MultiPrefix,
    Sasl,
    Setname,
    StandardReplies,
    UserhostInNames,
    BotMode,
    UTF8Only,
    StrictTransportSecurity,
    WebIRC,
    Chathistory,
    
    // 2024 Bleeding-edge capabilities
    MessageRedaction,      // April 2024 - Message deletion/redaction
    AccountExtban,         // July 2024 - Account-based bans
    Metadata2,             // September 2024 - User metadata v2
    
    // Draft capabilities (Work in Progress)
    MessageTagsUnlimited,
    Multiline,             // Multi-line messages with batching
    NoImplicitNames,
    PreAway,               // Away status during registration
    ReadMarker,            // Read receipt tracking
    RelayMsg,              // Bot message relaying
    ReplyDrafts,
    TypingClient,          // Typing indicators
    WebSocket,             // WebSocket transport
    ChannelRename,         // Channel renaming
    Persistence,           // Message persistence features
    ServerNameIndication,  // SNI support
    
    // Client-only tags
    ClientTyping,          // +typing client tag
    ClientReply,           // +draft/reply client tag
    ClientReact,           // +draft/react client tag
    
    // Custom/Vendor specific
    Custom(String),
}

impl Capability {
    /// Parse a capability from its string representation
    pub fn from_str(s: &str) -> Self {
        match s {
            // Core IRCv3 capabilities (Ratified)
            "message-tags" => Capability::MessageTags,
            "server-time" => Capability::ServerTime,
            "account-notify" => Capability::AccountNotify,
            "account-tag" => Capability::AccountTag,
            "away-notify" => Capability::AwayNotify,
            "batch" => Capability::Batch,
            "cap-notify" => Capability::CapNotify,
            "chghost" => Capability::ChgHost,
            "echo-message" => Capability::EchoMessage,
            "extended-join" => Capability::ExtendedJoin,
            "invite-notify" => Capability::InviteNotify,
            "labeled-response" => Capability::LabeledResponse,
            "monitor" => Capability::Monitor,
            "multi-prefix" => Capability::MultiPrefix,
            "sasl" => Capability::Sasl,
            "setname" => Capability::Setname,
            "standard-replies" => Capability::StandardReplies,
            "userhost-in-names" => Capability::UserhostInNames,
            "bot" => Capability::BotMode,
            "utf8only" => Capability::UTF8Only,
            "sts" => Capability::StrictTransportSecurity,
            "webirc" => Capability::WebIRC,
            "chathistory" => Capability::Chathistory,
            
            // 2024 Bleeding-edge capabilities
            "draft/message-redaction" => Capability::MessageRedaction,
            "account-extban" => Capability::AccountExtban,
            "draft/metadata-2" => Capability::Metadata2,
            
            // Draft capabilities (Work in Progress)
            "draft/message-tags-unlimited" => Capability::MessageTagsUnlimited,
            "draft/multiline" => Capability::Multiline,
            "draft/no-implicit-names" => Capability::NoImplicitNames,
            "draft/pre-away" => Capability::PreAway,
            "draft/read-marker" => Capability::ReadMarker,
            "draft/relaymsg" => Capability::RelayMsg,
            "draft/reply" => Capability::ReplyDrafts,
            "draft/typing" => Capability::TypingClient,
            "draft/websocket" => Capability::WebSocket,
            "draft/channel-rename" => Capability::ChannelRename,
            "draft/persistence" => Capability::Persistence,
            "draft/sni" => Capability::ServerNameIndication,
            
            // Client-only tags (handled by client-tags capability)
            "+typing" => Capability::ClientTyping,
            "+draft/reply" => Capability::ClientReply,
            "+draft/react" => Capability::ClientReact,
            
            other => Capability::Custom(other.to_string()),
        }
    }
    
    /// Get the string representation of this capability
    pub fn as_str(&self) -> &str {
        match self {
            // Core IRCv3 capabilities (Ratified)
            Capability::MessageTags => "message-tags",
            Capability::ServerTime => "server-time",
            Capability::AccountNotify => "account-notify",
            Capability::AccountTag => "account-tag",
            Capability::AwayNotify => "away-notify",
            Capability::Batch => "batch",
            Capability::CapNotify => "cap-notify",
            Capability::ChgHost => "chghost",
            Capability::EchoMessage => "echo-message",
            Capability::ExtendedJoin => "extended-join",
            Capability::InviteNotify => "invite-notify",
            Capability::LabeledResponse => "labeled-response",
            Capability::Monitor => "monitor",
            Capability::MultiPrefix => "multi-prefix",
            Capability::Sasl => "sasl",
            Capability::Setname => "setname",
            Capability::StandardReplies => "standard-replies",
            Capability::UserhostInNames => "userhost-in-names",
            Capability::BotMode => "bot",
            Capability::UTF8Only => "utf8only",
            Capability::StrictTransportSecurity => "sts",
            Capability::WebIRC => "webirc",
            Capability::Chathistory => "chathistory",
            
            // 2024 Bleeding-edge capabilities
            Capability::MessageRedaction => "draft/message-redaction",
            Capability::AccountExtban => "account-extban",
            Capability::Metadata2 => "draft/metadata-2",
            
            // Draft capabilities (Work in Progress)
            Capability::MessageTagsUnlimited => "draft/message-tags-unlimited",
            Capability::Multiline => "draft/multiline",
            Capability::NoImplicitNames => "draft/no-implicit-names",
            Capability::PreAway => "draft/pre-away",
            Capability::ReadMarker => "draft/read-marker",
            Capability::RelayMsg => "draft/relaymsg",
            Capability::ReplyDrafts => "draft/reply",
            Capability::TypingClient => "draft/typing",
            Capability::WebSocket => "draft/websocket",
            Capability::ChannelRename => "draft/channel-rename",
            Capability::Persistence => "draft/persistence",
            Capability::ServerNameIndication => "draft/sni",
            
            // Client-only tags
            Capability::ClientTyping => "+typing",
            Capability::ClientReply => "+draft/reply",
            Capability::ClientReact => "+draft/react",
            
            Capability::Custom(s) => s,
        }
    }

    /// Check if this is a security-critical capability
    pub fn is_security_critical(&self) -> bool {
        matches!(self, 
            Capability::Sasl | 
            Capability::StrictTransportSecurity |
            Capability::AccountTag |
            Capability::AccountNotify
        )
    }

    /// Check if this is a draft/experimental capability
    pub fn is_draft(&self) -> bool {
        self.as_str().starts_with("draft/") || matches!(self,
            Capability::MessageRedaction |
            Capability::MessageTagsUnlimited |
            Capability::Multiline |
            Capability::NoImplicitNames |
            Capability::PreAway |
            Capability::ReadMarker |
            Capability::RelayMsg |
            Capability::ReplyDrafts |
            Capability::TypingClient |
            Capability::WebSocket |
            Capability::ChannelRename |
            Capability::Persistence |
            Capability::ServerNameIndication |
            Capability::Metadata2
        )
    }
}

/// A capability with its value and enabled state
#[derive(Debug, Clone)]
pub struct CapabilitySpec {
    pub name: String,
    pub value: Option<String>,
    pub enabled: bool,
}

/// Manages IRCv3 capability negotiation
pub struct CapabilityHandler {
    version: u16,
    available_caps: HashMap<String, CapabilitySpec>,
    requested_caps: Vec<String>,
    enabled_caps: HashMap<String, CapabilitySpec>,
    negotiation_complete: bool,
    sts_policies: HashMap<String, StsPolicy>,
}

/// STS (Strict Transport Security) policy
#[derive(Debug, Clone)]
pub struct StsPolicy {
    pub duration: Duration,
    pub port: Option<u16>,
    pub preload: bool,
    pub expires_at: SystemTime,
}

impl CapabilityHandler {
    /// Create a new capability handler
    pub fn new() -> Self {
        Self {
            version: 302,
            available_caps: HashMap::new(),
            requested_caps: Vec::new(),
            enabled_caps: HashMap::new(),
            negotiation_complete: false,
            sts_policies: HashMap::new(),
        }
    }

    /// Set the CAP version to use
    pub fn set_version(&mut self, version: u16) {
        self.version = version;
    }

    /// Handle CAP LS response
    pub fn handle_cap_ls(&mut self, params: &[String]) -> Result<bool> {
        if params.len() < 2 {
            return Err(IronError::Parse("Invalid CAP LS response".to_string()));
        }

        let is_multiline = params.len() > 2 && params[1] == "*";
        let caps_list = if is_multiline { &params[2] } else { &params[1] };
        
        self.parse_capabilities(caps_list)?;
        
        Ok(!is_multiline)
    }

    /// Handle CAP ACK response
    pub fn handle_cap_ack(&mut self, caps: &[String]) -> Result<()> {
        for cap_param in caps {
            // Split space-separated capabilities
            for cap_name in cap_param.split_whitespace() {
                let cap_name = cap_name.trim();
                if !cap_name.is_empty() {
                    if let Some(cap) = self.available_caps.get(cap_name) {
                        let mut enabled_cap = cap.clone();
                        enabled_cap.enabled = true;
                        self.enabled_caps.insert(cap_name.to_string(), enabled_cap);
                    }
                }
            }
        }
        Ok(())
    }

    /// Handle CAP NAK response
    pub fn handle_cap_nak(&mut self, caps: &[String]) -> Result<()> {
        for cap in caps {
            if self.get_essential_capabilities().contains(&cap.as_str()) {
                if matches!(cap.as_str(), "sasl" | "sts") {
                    return Err(IronError::SecurityViolation(
                        format!("Essential security capability rejected: {}", cap)
                    ));
                }
            }
            
            self.requested_caps.retain(|c| c != cap);
        }
        Ok(())
    }

    /// Handle CAP NEW notification (IRCv3.2+)
    pub fn handle_cap_new(&mut self, caps_str: &str) -> Result<Vec<String>> {
        if self.version < 302 {
            return Ok(Vec::new());
        }

        self.parse_capabilities(caps_str)?;
        
        let mut new_requests = Vec::new();
        for cap_name in caps_str.split_whitespace() {
            let cap_name = cap_name.split('=').next().unwrap_or(cap_name);
            if self.get_essential_capabilities().contains(&cap_name) {
                new_requests.push(cap_name.to_string());
            }
        }

        Ok(new_requests)
    }

    /// Handle CAP DEL notification (IRCv3.2+)
    pub fn handle_cap_del(&mut self, caps: &[String]) -> Result<()> {
        for cap in caps {
            self.available_caps.remove(cap);
            self.enabled_caps.remove(cap);
        }
        Ok(())
    }

    /// Get capabilities to request based on what's available
    pub fn get_capabilities_to_request(&self) -> Vec<String> {
        let mut caps_to_request = Vec::new();
        
        for &cap_name in &self.get_essential_capabilities() {
            if self.available_caps.contains_key(cap_name) {
                caps_to_request.push(cap_name.to_string());
            }
        }

        // Validate SASL mechanisms if present
        if let Some(sasl_cap) = self.available_caps.get("sasl") {
            if let Err(_) = self.validate_sasl_mechanisms(sasl_cap) {
                caps_to_request.retain(|c| c != "sasl");
            }
        }

        caps_to_request
    }

    /// Check if a capability is enabled
    pub fn is_capability_enabled(&self, cap_name: &str) -> bool {
        self.enabled_caps.contains_key(cap_name)
    }

    /// Get available SASL mechanisms
    pub fn get_sasl_mechanisms(&self) -> Vec<String> {
        if let Some(sasl_cap) = self.enabled_caps.get("sasl") {
            if let Some(value) = &sasl_cap.value {
                return value.split(',').map(|s| s.trim().to_string()).collect();
            }
        }
        Vec::new()
    }

    /// Mark capability negotiation as complete
    pub fn set_negotiation_complete(&mut self) {
        self.negotiation_complete = true;
    }

    /// Check if capability negotiation is complete
    pub fn is_negotiation_complete(&self) -> bool {
        self.negotiation_complete
    }

    /// Handle STS policy
    pub fn handle_sts_policy(&mut self, hostname: &str, cap_value: &str) -> Result<()> {
        let mut duration = None;
        let mut port = None;
        let mut preload = false;
        
        for param in cap_value.split(',') {
            let parts: Vec<&str> = param.splitn(2, '=').collect();
            match parts[0].trim() {
                "duration" => {
                    if parts.len() > 1 {
                        duration = Some(Duration::from_secs(
                            parts[1].parse().map_err(|_| {
                                IronError::Parse("Invalid STS duration".to_string())
                            })?
                        ));
                    }
                }
                "port" => {
                    if parts.len() > 1 {
                        port = Some(parts[1].parse().map_err(|_| {
                            IronError::Parse("Invalid STS port".to_string())
                        })?);
                    }
                }
                "preload" => preload = true,
                _ => {}
            }
        }
        
        let duration = duration.ok_or_else(|| {
            IronError::Parse("STS policy missing duration".to_string())
        })?;
        
        if duration.as_secs() == 0 {
            self.sts_policies.remove(hostname);
            return Ok(());
        }
        
        let policy = StsPolicy {
            duration,
            port,
            preload,
            expires_at: SystemTime::now() + duration,
        };
        
        self.sts_policies.insert(hostname.to_string(), policy);
        Ok(())
    }

    /// Check if we should upgrade to TLS for a hostname
    pub fn should_upgrade_to_tls(&self, hostname: &str) -> Option<u16> {
        if let Some(policy) = self.sts_policies.get(hostname) {
            if SystemTime::now() < policy.expires_at {
                return policy.port.or(Some(6697));
            }
        }
        None
    }

    /// Parse capabilities string
    fn parse_capabilities(&mut self, caps_str: &str) -> Result<()> {
        for cap_spec in caps_str.split_whitespace() {
            if cap_spec.is_empty() {
                continue;
            }

            let (name, value) = if let Some(eq_pos) = cap_spec.find('=') {
                (&cap_spec[..eq_pos], Some(&cap_spec[eq_pos + 1..]))
            } else {
                (cap_spec, None)
            };

            if !self.is_valid_capability_name(name) {
                return Err(IronError::SecurityViolation(
                    format!("Invalid capability name: {}", name)
                ));
            }

            self.available_caps.insert(name.to_string(), CapabilitySpec {
                name: name.to_string(),
                value: value.map(String::from),
                enabled: false,
            });
        }
        Ok(())
    }

    /// Get essential capabilities list
    pub fn get_essential_capabilities(&self) -> Vec<&str> {
        vec![
            // Core IRCv3 capabilities only (most compatible)
            "sasl",
            "message-tags",
            "server-time",
            "batch",
            // Reaction and reply capabilities
            "+draft/react",
            "+draft/reply",
        ]
    }

    /// Validate SASL mechanisms
    fn validate_sasl_mechanisms(&self, sasl_cap: &CapabilitySpec) -> Result<()> {
        if let Some(value) = &sasl_cap.value {
            let mechanisms: Vec<&str> = value.split(',').collect();
            
            let preferred_order = ["SCRAM-SHA-256", "EXTERNAL", "PLAIN"];
            
            for &preferred in &preferred_order {
                if mechanisms.iter().any(|m| m.trim() == preferred) {
                    return Ok(());
                }
            }
            
            return Err(IronError::Auth(
                "No supported SASL mechanisms".to_string()
            ));
        }
        Ok(())
    }

    /// Validate capability name
    fn is_valid_capability_name(&self, name: &str) -> bool {
        if name.is_empty() || name.len() > 64 {
            return false;
        }

        if name.starts_with('-') {
            return false;
        }

        if name.contains('/') {
            let parts: Vec<&str> = name.split('/').collect();
            if parts.len() != 2 {
                return false;
            }
            
            if parts[0].contains('.') && !parts[0].ends_with(".com") 
                && !parts[0].ends_with(".org") && !parts[0].ends_with(".net") 
                && !parts[0].ends_with(".chat") && !parts[0].ends_with(".in") {
                return false;
            }
        }

        name.chars().all(|c| {
            c.is_ascii_alphanumeric() || 
            c == '-' || c == '/' || c == '.' || c == '_' || c == '+'
        })
    }
}

impl Default for CapabilityHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// A set of capabilities for server advertisement
pub struct CapabilitySet {
    capabilities: HashSet<Capability>,
}

impl CapabilitySet {
    /// Create a new capability set with common IRCv3 capabilities
    pub fn new() -> Self {
        let mut capabilities = HashSet::new();
        
        // Core IRCv3 capabilities (Ratified)
        capabilities.insert(Capability::MessageTags);
        capabilities.insert(Capability::ServerTime);
        capabilities.insert(Capability::AccountNotify);
        capabilities.insert(Capability::AccountTag);
        capabilities.insert(Capability::AwayNotify);
        capabilities.insert(Capability::Batch);
        capabilities.insert(Capability::CapNotify);
        capabilities.insert(Capability::ChgHost);
        capabilities.insert(Capability::EchoMessage);
        capabilities.insert(Capability::ExtendedJoin);
        capabilities.insert(Capability::InviteNotify);
        capabilities.insert(Capability::LabeledResponse);
        capabilities.insert(Capability::Monitor);
        capabilities.insert(Capability::MultiPrefix);
        capabilities.insert(Capability::Sasl);
        capabilities.insert(Capability::Setname);
        capabilities.insert(Capability::StandardReplies);
        capabilities.insert(Capability::UserhostInNames);
        capabilities.insert(Capability::BotMode);
        capabilities.insert(Capability::UTF8Only);
        capabilities.insert(Capability::StrictTransportSecurity);
        capabilities.insert(Capability::Chathistory);
        
        Self { capabilities }
    }
    
    /// Create a capability set with only stable/ratified capabilities
    pub fn stable_only() -> Self {
        Self::new() // For now, new() already contains only stable capabilities
    }
    
    /// Create a bleeding-edge capability set with all 2024-2025 features
    pub fn bleeding_edge() -> Self {
        let mut set = Self::new();
        
        // Add 2024 bleeding-edge capabilities
        set.add(Capability::MessageRedaction);
        set.add(Capability::AccountExtban);
        set.add(Capability::Metadata2);
        
        // Add experimental capabilities
        set.add(Capability::MessageTagsUnlimited);
        set.add(Capability::Multiline);
        set.add(Capability::NoImplicitNames);
        set.add(Capability::PreAway);
        set.add(Capability::ReadMarker);
        set.add(Capability::RelayMsg);
        set.add(Capability::ReplyDrafts);
        set.add(Capability::TypingClient);
        set.add(Capability::WebSocket);
        set.add(Capability::ChannelRename);
        set.add(Capability::Persistence);
        set.add(Capability::ServerNameIndication);
        
        // Client-only tags support
        set.add(Capability::ClientTyping);
        set.add(Capability::ClientReply);
        set.add(Capability::ClientReact);
        
        set
    }
    
    /// Check if a capability is supported
    pub fn supports(&self, cap: &Capability) -> bool {
        self.capabilities.contains(cap)
    }
    
    /// Add a capability
    pub fn add(&mut self, cap: Capability) {
        self.capabilities.insert(cap);
    }
    
    /// Remove a capability
    pub fn remove(&mut self, cap: &Capability) -> bool {
        self.capabilities.remove(cap)
    }
    
    /// Convert to string list for CAP LS
    pub fn to_string_list(&self) -> Vec<String> {
        self.capabilities
            .iter()
            .map(|cap| cap.as_str().to_string())
            .collect()
    }

    /// Get all capabilities as a formatted string for CAP LS
    pub fn to_cap_ls_string(&self) -> String {
        self.to_string_list().join(" ")
    }
}

impl Default for CapabilitySet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_parsing() {
        let cap = Capability::from_str("message-tags");
        assert_eq!(cap, Capability::MessageTags);
        assert_eq!(cap.as_str(), "message-tags");
    }

    #[test]
    fn test_draft_capability_detection() {
        let draft_cap = Capability::from_str("draft/multiline");
        assert!(draft_cap.is_draft());
        
        let stable_cap = Capability::from_str("message-tags");
        assert!(!stable_cap.is_draft());
    }

    #[test]
    fn test_security_critical_detection() {
        let sasl = Capability::from_str("sasl");
        assert!(sasl.is_security_critical());
        
        let tags = Capability::from_str("message-tags");
        assert!(!tags.is_security_critical());
    }

    #[test]
    fn test_capability_handler() {
        let mut handler = CapabilityHandler::new();
        let params = vec!["*".to_string(), "LS".to_string(), "sasl=PLAIN message-tags".to_string()];
        
        let complete = handler.handle_cap_ls(&params).unwrap();
        assert!(!complete);
        assert!(handler.available_caps.contains_key("sasl"));
        assert!(handler.available_caps.contains_key("message-tags"));
    }

    #[test]
    fn test_capability_set() {
        let set = CapabilitySet::bleeding_edge();
        assert!(set.supports(&Capability::MessageTags));
        assert!(set.supports(&Capability::MessageRedaction));
        assert!(set.supports(&Capability::Multiline));
    }
}