//! # Iron Protocol
//!
//! A bleeding-edge IRCv3 protocol library for modern IRC clients and servers.
//!
//! This crate provides comprehensive support for the IRC protocol with particular
//! emphasis on IRCv3 capabilities and the latest 2024-2025 draft specifications.
//!
//! ## Features
//!
//! - Full IRCv3 capability negotiation
//! - Message parsing and serialization with tags support
//! - SASL authentication mechanisms
//! - Security validation and DoS protection
//! - Bleeding-edge 2024-2025 draft features
//! - Both client and server-side utilities
//!
//! ## Examples
//!
//! ```rust
//! use iron_protocol::{IrcMessage, Command, Capability};
//!
//! // Parse an IRC message with tags
//! let msg: IrcMessage = "@id=123;time=2023-01-01T00:00:00.000Z PRIVMSG #channel :Hello world"
//!     .parse().unwrap();
//!
//! // Create a new message
//! let msg = IrcMessage::new("PRIVMSG")
//!     .with_params(vec!["#channel".to_string(), "Hello".to_string()])
//!     .with_tag("id", Some("123".to_string()));
//! ```

#![warn(missing_docs, rustdoc::missing_crate_level_docs)]
#![deny(unsafe_code)]

pub mod error;
pub mod message;
pub mod command;
pub mod capabilities;
pub mod sasl;
pub mod validation;
pub mod replies;

#[cfg(feature = "bleeding-edge")]
pub mod bleeding_edge;

// Re-export main types for convenience
pub use error::{IronError, Result};
pub use message::IrcMessage;
pub use command::Command;
pub use capabilities::{Capability, CapabilitySet, CapabilityHandler};
pub use replies::Reply;

#[cfg(feature = "bleeding-edge")]
pub use bleeding_edge::{MessageReply, MessageReaction, ReactionAction};

/// Protocol constants used throughout the IRC specification
pub mod constants {
    /// Maximum length of an IRC message (excluding tags)
    pub const MAX_MESSAGE_LENGTH: usize = 512;
    
    /// Maximum length of message tags section
    pub const MAX_TAG_LENGTH: usize = 8191;
    
    /// Maximum number of parameters in a message
    pub const MAX_PARAMS: usize = 15;
    
    /// Maximum length of a capability name
    pub const MAX_CAPABILITY_NAME_LENGTH: usize = 64;
    
    /// Maximum length of a nickname
    pub const MAX_NICK_LENGTH: usize = 32;
    
    /// Maximum length of a channel name
    pub const MAX_CHANNEL_LENGTH: usize = 50;
    
    /// Default IRC port (plaintext)
    pub const DEFAULT_IRC_PORT: u16 = 6667;
    
    /// Default IRC over TLS port
    pub const DEFAULT_IRCS_PORT: u16 = 6697;
}

/// Utility functions for IRC protocol handling
pub mod utils {
    use crate::constants::*;
    
    /// Check if a string is a valid IRC nickname
    pub fn is_valid_nick(nick: &str) -> bool {
        if nick.is_empty() || nick.len() > MAX_NICK_LENGTH {
            return false;
        }
        
        // First character must be letter or special character
        let first = nick.chars().next().unwrap();
        if !first.is_ascii_alphabetic() && !matches!(first, '[' | ']' | '\\' | '`' | '_' | '^' | '{' | '|' | '}') {
            return false;
        }
        
        // Remaining characters can be alphanumeric, hyphen, or special characters
        nick.chars().skip(1).all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '[' | ']' | '\\' | '`' | '_' | '^' | '{' | '|' | '}' | '-')
        })
    }
    
    /// Check if a string is a valid IRC channel name
    pub fn is_valid_channel(channel: &str) -> bool {
        if channel.is_empty() || channel.len() > MAX_CHANNEL_LENGTH {
            return false;
        }
        
        // Must start with # or &
        if !channel.starts_with('#') && !channel.starts_with('&') {
            return false;
        }
        
        // Cannot contain spaces, control characters, or commas
        !channel.chars().any(|c| c.is_control() || c == ' ' || c == ',' || c == '\x07')
    }
    
    /// Escape IRC message text for safe transmission
    pub fn escape_message(text: &str) -> String {
        text.replace('\r', "")
            .replace('\n', " ")
            .replace('\0', "")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::utils::*;
    
    #[test]
    fn test_valid_nicks() {
        assert!(is_valid_nick("Alice"));
        assert!(is_valid_nick("Bob123"));
        assert!(is_valid_nick("user_name"));
        assert!(is_valid_nick("[Bot]"));
        assert!(is_valid_nick("test-user"));
    }
    
    #[test]
    fn test_invalid_nicks() {
        assert!(!is_valid_nick(""));
        assert!(!is_valid_nick("123user")); // Can't start with number
        assert!(!is_valid_nick("user name")); // No spaces
        assert!(!is_valid_nick(&"a".repeat(50))); // Too long
    }
    
    #[test]
    fn test_valid_channels() {
        assert!(is_valid_channel("#general"));
        assert!(is_valid_channel("&local"));
        assert!(is_valid_channel("#test-channel"));
        assert!(is_valid_channel("#channel123"));
    }
    
    #[test]
    fn test_invalid_channels() {
        assert!(!is_valid_channel(""));
        assert!(!is_valid_channel("general")); // Must start with # or &
        assert!(!is_valid_channel("#test channel")); // No spaces
        assert!(!is_valid_channel("#test,channel")); // No commas
        assert!(!is_valid_channel(&format!("#{}", "a".repeat(60)))); // Too long
    }
}
