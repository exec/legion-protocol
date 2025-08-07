//! IRC message parsing and serialization
//!
//! This module provides the core `IrcMessage` type and related functionality
//! for parsing and serializing IRC messages according to the IRCv3 specification.

use crate::error::{IronError, Result};
use crate::constants::*;
use std::collections::HashMap;
use std::str::FromStr;

#[cfg(feature = "chrono")]
use std::time::SystemTime;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// An IRC message with optional tags, prefix, command, and parameters
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IrcMessage {
    /// Message tags (IRCv3)
    pub tags: HashMap<String, Option<String>>,
    /// Message prefix (source)
    pub prefix: Option<String>,
    /// IRC command
    pub command: String,
    /// Command parameters
    pub params: Vec<String>,
}

impl IrcMessage {
    /// Create a new IRC message with the given command
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            tags: HashMap::new(),
            prefix: None,
            command: command.into(),
            params: Vec::new(),
        }
    }

    /// Add parameters to the message
    pub fn with_params(mut self, params: Vec<String>) -> Self {
        self.params = params;
        self
    }

    /// Add a prefix to the message
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    /// Add a tag to the message
    pub fn with_tag(mut self, key: impl Into<String>, value: Option<String>) -> Self {
        self.tags.insert(key.into(), value);
        self
    }

    /// Add multiple tags to the message
    pub fn with_tags(mut self, tags: HashMap<String, Option<String>>) -> Self {
        self.tags.extend(tags);
        self
    }

    /// Create a raw message (for debugging/testing)
    pub fn raw(data: &str) -> Self {
        Self {
            tags: HashMap::new(),
            prefix: None,
            command: "RAW".to_string(),
            params: vec![data.to_string()],
        }
    }

    /// Extract server timestamp from message tags, fallback to current time
    #[cfg(feature = "chrono")]
    pub fn get_timestamp(&self) -> SystemTime {
        if let Some(Some(time_str)) = self.tags.get("time") {
            // Parse ISO 8601 timestamp from server-time capability
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(time_str) {
                return SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(dt.timestamp() as u64);
            }
        }
        SystemTime::now()
    }

    /// Get the message ID from tags (if present)
    pub fn get_msgid(&self) -> Option<&str> {
        self.tags.get("msgid").and_then(|v| v.as_deref())
    }

    /// Get the account tag (if present)
    pub fn get_account(&self) -> Option<&str> {
        self.tags.get("account").and_then(|v| v.as_deref())
    }

    /// Check if this message has a specific tag
    pub fn has_tag(&self, key: &str) -> bool {
        self.tags.contains_key(key)
    }

    /// Get a tag value
    pub fn get_tag(&self, key: &str) -> Option<&Option<String>> {
        self.tags.get(key)
    }

    /// Check if this is a PRIVMSG or NOTICE
    pub fn is_message(&self) -> bool {
        matches!(self.command.as_str(), "PRIVMSG" | "NOTICE")
    }

    /// Check if this is a channel message (target starts with # or &)
    pub fn is_channel_message(&self) -> bool {
        self.is_message() && 
        self.params.first()
            .map(|target| target.starts_with('#') || target.starts_with('&'))
            .unwrap_or(false)
    }

    /// Get the target of a message (first parameter)
    pub fn target(&self) -> Option<&str> {
        self.params.first().map(|s| s.as_str())
    }

    /// Get the message text (last parameter, typically)
    pub fn text(&self) -> Option<&str> {
        self.params.last().map(|s| s.as_str())
    }

    /// Validate the message for security issues
    fn validate_security(&self) -> Result<()> {
        // Validate command length
        if self.command.len() > 32 {
            return Err(IronError::SecurityViolation(
                "Command too long".to_string()
            ));
        }

        // Validate parameter count
        if self.params.len() > MAX_PARAMS {
            return Err(IronError::SecurityViolation(
                "Too many parameters".to_string()
            ));
        }

        // Validate each parameter
        for param in &self.params {
            // CAP messages can have very long capability lists, allow up to 4KB for them
            let max_param_len = if self.command == "CAP" {
                4096
            } else {
                MAX_MESSAGE_LENGTH
            };
            
            if param.len() > max_param_len {
                return Err(IronError::SecurityViolation(
                    "Parameter too long".to_string()
                ));
            }
            
            // Check for invalid characters
            if param.contains('\0') || param.contains('\r') || param.contains('\n') {
                return Err(IronError::SecurityViolation(
                    "Invalid characters in parameter".to_string()
                ));
            }
            
            // Validate ASCII characters only (for now)
            if !param.is_ascii() {
                return Err(IronError::SecurityViolation(
                    "Non-ASCII characters in parameter".to_string()
                ));
            }
        }

        // Validate prefix
        if let Some(prefix) = &self.prefix {
            if prefix.len() > 255 || prefix.contains('\0') || prefix.contains(' ') {
                return Err(IronError::SecurityViolation(
                    "Invalid prefix".to_string()
                ));
            }
        }

        // Validate total tag length
        let total_tag_length: usize = self.tags.iter()
            .map(|(k, v)| k.len() + v.as_ref().map_or(0, |s| s.len()) + 2)
            .sum();
        
        if total_tag_length > MAX_TAG_LENGTH {
            return Err(IronError::SecurityViolation(
                "Tags too long".to_string()
            ));
        }

        Ok(())
    }
}

impl FromStr for IrcMessage {
    type Err = IronError;

    fn from_str(line: &str) -> Result<Self> {
        // Check total message length
        if line.len() > MAX_MESSAGE_LENGTH + MAX_TAG_LENGTH {
            return Err(IronError::SecurityViolation(
                "Message too long".to_string()
            ));
        }

        let line = line.trim_end_matches("\r\n");
        let mut message = IrcMessage::new("");
        let mut remaining = line;

        // Parse tags if present
        if remaining.starts_with('@') {
            let space_pos = remaining.find(' ')
                .ok_or_else(|| IronError::Parse("No space after tags".to_string()))?;
            
            let tag_str = &remaining[1..space_pos];
            
            // Check total tag length before parsing
            if tag_str.len() > MAX_TAG_LENGTH {
                return Err(IronError::SecurityViolation(
                    "Tag section exceeds maximum length".to_string()
                ));
            }
            
            remaining = &remaining[space_pos + 1..];

            // Parse individual tags
            for tag in tag_str.split(';') {
                if tag.is_empty() {
                    continue;
                }

                let (key, value) = if let Some(eq_pos) = tag.find('=') {
                    let key = &tag[..eq_pos];
                    let value_str = &tag[eq_pos + 1..];
                    let value = if value_str.is_empty() {
                        None
                    } else {
                        Some(unescape_tag_value(value_str))
                    };
                    (key, value)
                } else {
                    (tag, None)
                };

                if !is_valid_tag_key(key) {
                    return Err(IronError::SecurityViolation(
                        format!("Invalid tag key: {}", key)
                    ));
                }

                message.tags.insert(key.to_string(), value);
            }
        }

        // Parse prefix if present
        if remaining.starts_with(':') {
            let space_pos = remaining.find(' ')
                .ok_or_else(|| IronError::Parse("No space after prefix".to_string()))?;
            
            let prefix = &remaining[1..space_pos];
            // Validate prefix doesn't contain spaces
            if prefix.contains(' ') {
                return Err(IronError::SecurityViolation(
                    "Space in prefix".to_string()
                ));
            }
            
            message.prefix = Some(prefix.to_string());
            remaining = &remaining[space_pos + 1..];
        }

        // Parse command and parameters
        let mut parts: Vec<&str> = remaining.splitn(15, ' ').collect();
        
        if parts.is_empty() {
            return Err(IronError::Parse("No command found".to_string()));
        }

        message.command = parts.remove(0).to_uppercase();

        if !is_valid_command(&message.command) {
            return Err(IronError::SecurityViolation(
                format!("Invalid command: {}", message.command)
            ));
        }

        // Parse parameters
        for (i, part) in parts.iter().enumerate() {
            if part.starts_with(':') && i > 0 {
                // Trailing parameter - combine all remaining parts
                let trailing = parts[i..].join(" ");
                message.params.push(trailing[1..].to_string());
                break;
            } else {
                message.params.push(part.to_string());
            }
        }

        message.validate_security()?;
        Ok(message)
    }
}

impl std::fmt::Display for IrcMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Write tags if present
        if !self.tags.is_empty() {
            write!(f, "@")?;
            let mut first = true;
            for (key, value) in &self.tags {
                if !first {
                    write!(f, ";")?;
                }
                first = false;
                write!(f, "{}", key)?;
                if let Some(val) = value {
                    write!(f, "={}", escape_tag_value(val))?;
                }
            }
            write!(f, " ")?;
        }

        // Write prefix if present
        if let Some(prefix) = &self.prefix {
            write!(f, ":{} ", prefix)?;
        }

        // Write command
        write!(f, "{}", self.command)?;

        // Write parameters
        for (i, param) in self.params.iter().enumerate() {
            if i == self.params.len() - 1 && (param.contains(' ') || param.starts_with(':')) {
                write!(f, " :{}", param)?;
            } else {
                write!(f, " {}", param)?;
            }
        }

        write!(f, "\r\n")
    }
}

/// Unescape IRC tag values
fn unescape_tag_value(value: &str) -> String {
    value
        .replace("\\:", ";")
        .replace("\\s", " ")
        .replace("\\\\", "\\")
        .replace("\\r", "\r")
        .replace("\\n", "\n")
}

/// Escape IRC tag values
fn escape_tag_value(value: &str) -> String {
    value
        .replace("\\", "\\\\")
        .replace(";", "\\:")
        .replace(" ", "\\s")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
}

/// Check if a tag key is valid
fn is_valid_tag_key(key: &str) -> bool {
    if key.is_empty() || key.len() > MAX_CAPABILITY_NAME_LENGTH {
        return false;
    }

    key.chars().all(|c| {
        c.is_ascii_alphanumeric() || 
        c == '-' || c == '/' || c == '.' || c == '_' || c == '+'
    })
}

/// Check if a command is valid
fn is_valid_command(command: &str) -> bool {
    if command.is_empty() || command.len() > 32 {
        return false;
    }

    // Valid IRC commands are either:
    // 1. Alphabetic commands (PRIVMSG, NOTICE, etc.)
    // 2. Three-digit numeric replies (001, 372, etc.)
    let is_alpha_command = command.chars().all(|c| c.is_ascii_alphabetic());
    let is_numeric_reply = command.len() == 3 && command.chars().all(|c| c.is_ascii_digit());
    
    if !is_alpha_command && !is_numeric_reply {
        return false;
    }
    
    // Reject known non-IRC protocols
    const INVALID_COMMANDS: &[&str] = &[
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", // HTTP
        "HELO", "EHLO", "MAIL", "RCPT", "DATA", "RSET", "VRFY", // SMTP
        "SYST", "STAT", "RETR", "DELE", "UIDL", "APOP", // POP3
        "AUTH", "LOGIN", "SELECT", "EXAMINE", "CREATE", "RENAME", // IMAP
    ];
    
    !INVALID_COMMANDS.contains(&command)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_message_parsing() {
        let msg = "PRIVMSG #channel :Hello world".parse::<IrcMessage>().unwrap();
        assert_eq!(msg.command, "PRIVMSG");
        assert_eq!(msg.params, vec!["#channel", "Hello world"]);
        assert!(msg.tags.is_empty());
        assert!(msg.prefix.is_none());
    }

    #[test]
    fn test_message_with_tags() {
        let msg = "@time=2023-01-01T00:00:00.000Z PRIVMSG #channel :Hello"
            .parse::<IrcMessage>().unwrap();
        assert!(msg.tags.contains_key("time"));
        assert_eq!(msg.command, "PRIVMSG");
        assert_eq!(msg.params, vec!["#channel", "Hello"]);
    }

    #[test]
    fn test_message_with_prefix() {
        let msg = ":nick!user@host PRIVMSG #channel :Hello"
            .parse::<IrcMessage>().unwrap();
        assert_eq!(msg.prefix, Some("nick!user@host".to_string()));
        assert_eq!(msg.command, "PRIVMSG");
        assert_eq!(msg.params, vec!["#channel", "Hello"]);
    }

    #[test]
    fn test_message_formatting() {
        let msg = IrcMessage::new("PRIVMSG")
            .with_params(vec!["#channel".to_string(), "Hello world".to_string()]);
        let formatted = msg.to_string();
        assert_eq!(formatted, "PRIVMSG #channel :Hello world\r\n");
    }

    #[test]
    fn test_security_validation() {
        let long_command = "A".repeat(100);
        let result = format!("{} #channel :test", long_command).parse::<IrcMessage>();
        assert!(matches!(result, Err(IronError::SecurityViolation(_))));
    }

    #[test]
    fn test_helper_methods() {
        let msg = "PRIVMSG #channel :Hello world".parse::<IrcMessage>().unwrap();
        assert!(msg.is_message());
        assert!(msg.is_channel_message());
        assert_eq!(msg.target(), Some("#channel"));
        assert_eq!(msg.text(), Some("Hello world"));
    }
}