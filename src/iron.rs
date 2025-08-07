//! Iron Protocol extensions and handling
//!
//! This module contains Iron Protocol-specific functionality that extends
//! beyond standard IRC/IRCv3, including encrypted channels and protocol 
//! negotiation between Iron-capable clients and servers.

use crate::{ChannelType, IronError, Result};
use crate::utils::{get_channel_type, is_iron_encrypted_channel};
use crate::capabilities::Capability;

/// Iron Protocol version information
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IronVersion {
    V1,
}

impl IronVersion {
    /// Get the capability string for this Iron version
    pub fn as_capability(&self) -> &'static str {
        match self {
            IronVersion::V1 => "+iron-protocol/v1",
        }
    }
}

/// Result of Iron Protocol capability negotiation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IronNegotiationResult {
    /// Both client and server support Iron Protocol
    IronCapable { version: IronVersion },
    /// Only one side supports Iron Protocol (fallback to IRC)
    IrcFallback,
    /// No Iron Protocol support
    NotSupported,
}

/// Iron Protocol session state
#[derive(Debug, Clone)]
pub struct IronSession {
    version: Option<IronVersion>,
    encrypted_channels: Vec<String>,
    negotiation_complete: bool,
}

impl IronSession {
    /// Create a new Iron Protocol session
    pub fn new() -> Self {
        Self {
            version: None,
            encrypted_channels: Vec::new(),
            negotiation_complete: false,
        }
    }

    /// Set the negotiated Iron Protocol version
    pub fn set_version(&mut self, version: IronVersion) {
        self.version = Some(version);
    }

    /// Check if Iron Protocol is active
    pub fn is_iron_active(&self) -> bool {
        self.version.is_some() && self.negotiation_complete
    }

    /// Get the active Iron Protocol version
    pub fn version(&self) -> Option<IronVersion> {
        self.version
    }

    /// Complete Iron Protocol negotiation
    pub fn complete_negotiation(&mut self) {
        self.negotiation_complete = true;
    }

    /// Check if a channel is in our encrypted channels list
    pub fn is_encrypted_channel(&self, channel: &str) -> bool {
        self.encrypted_channels.iter().any(|c| c == channel)
    }

    /// Add an encrypted channel to our list
    pub fn add_encrypted_channel(&mut self, channel: String) {
        if !self.encrypted_channels.contains(&channel) {
            self.encrypted_channels.push(channel);
        }
    }

    /// Remove an encrypted channel from our list
    pub fn remove_encrypted_channel(&mut self, channel: &str) {
        self.encrypted_channels.retain(|c| c != channel);
    }
}

impl Default for IronSession {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle channel access control for Iron Protocol
pub struct IronChannelHandler;

impl IronChannelHandler {
    /// Check if a user can join a channel based on Iron Protocol capabilities
    pub fn can_join_channel(
        channel: &str,
        user_has_iron: bool,
        server_has_iron: bool,
    ) -> Result<ChannelJoinResult> {
        let channel_type = get_channel_type(channel);

        match channel_type {
            ChannelType::IrcGlobal | ChannelType::IrcLocal => {
                // Standard IRC channels - anyone can join
                Ok(ChannelJoinResult::Allowed)
            }
            ChannelType::IronEncrypted => {
                // Iron encrypted channels require both client and server Iron support
                if user_has_iron && server_has_iron {
                    Ok(ChannelJoinResult::AllowedEncrypted)
                } else {
                    Ok(ChannelJoinResult::Denied {
                        reason: IronChannelError::IncompatibleClient,
                    })
                }
            }
            ChannelType::Invalid => Err(IronError::Parse(format!(
                "Invalid channel name: {}",
                channel
            ))),
        }
    }

    /// Generate appropriate error message for IRC users trying to join Iron channels
    pub fn generate_error_message(channel: &str, error: &IronChannelError) -> String {
        match error {
            IronChannelError::IncompatibleClient => {
                format!(
                    "Cannot join encrypted channel {} - requires Iron Protocol support. \
                     Upgrade to an Iron-compatible client or ask channel admin to create \
                     a standard IRC channel (#{}) for IRC users.",
                    channel,
                    &channel[1..] // Remove the ! prefix to suggest # alternative
                )
            }
            IronChannelError::EncryptionRequired => {
                format!(
                    "Channel {} requires end-to-end encryption. \
                     Please use an Iron Protocol-compatible client.",
                    channel
                )
            }
        }
    }
}

/// Result of attempting to join a channel
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelJoinResult {
    /// User is allowed to join
    Allowed,
    /// User is allowed to join with encryption
    AllowedEncrypted,
    /// User is denied access
    Denied { reason: IronChannelError },
}

/// Reasons why a user might be denied access to an Iron channel
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IronChannelError {
    /// Client doesn't support Iron Protocol
    IncompatibleClient,
    /// Channel requires encryption but user can't provide it
    EncryptionRequired,
}

/// Detect Iron Protocol support during capability negotiation
pub fn detect_iron_support(
    client_caps: &[Capability],
    server_caps: &[Capability],
) -> IronNegotiationResult {
    let client_iron = client_caps
        .iter()
        .any(|cap| matches!(cap, Capability::IronProtocolV1));
    let server_iron = server_caps
        .iter()
        .any(|cap| matches!(cap, Capability::IronProtocolV1));

    match (client_iron, server_iron) {
        (true, true) => IronNegotiationResult::IronCapable {
            version: IronVersion::V1,
        },
        (true, false) | (false, true) => IronNegotiationResult::IrcFallback,
        (false, false) => IronNegotiationResult::NotSupported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iron_version_capability() {
        assert_eq!(IronVersion::V1.as_capability(), "+iron-protocol/v1");
    }

    #[test]
    fn test_channel_access_control() {
        // Standard IRC channels - always allowed
        let result = IronChannelHandler::can_join_channel("#general", false, false).unwrap();
        assert_eq!(result, ChannelJoinResult::Allowed);

        // Iron encrypted channel with compatible clients
        let result = IronChannelHandler::can_join_channel("!encrypted", true, true).unwrap();
        assert_eq!(result, ChannelJoinResult::AllowedEncrypted);

        // Iron encrypted channel with incompatible client
        let result = IronChannelHandler::can_join_channel("!encrypted", false, true).unwrap();
        assert!(matches!(
            result,
            ChannelJoinResult::Denied {
                reason: IronChannelError::IncompatibleClient
            }
        ));
    }

    #[test]
    fn test_iron_detection() {
        let client_caps = vec![Capability::IronProtocolV1, Capability::MessageTags];
        let server_caps = vec![Capability::IronProtocolV1, Capability::Sasl];

        let result = detect_iron_support(&client_caps, &server_caps);
        assert_eq!(
            result,
            IronNegotiationResult::IronCapable {
                version: IronVersion::V1
            }
        );

        // Test fallback scenario
        let client_caps = vec![Capability::MessageTags];
        let result = detect_iron_support(&client_caps, &server_caps);
        assert_eq!(result, IronNegotiationResult::IrcFallback);
    }

    #[test]
    fn test_iron_session() {
        let mut session = IronSession::new();
        assert!(!session.is_iron_active());

        session.set_version(IronVersion::V1);
        session.complete_negotiation();
        assert!(session.is_iron_active());
        assert_eq!(session.version(), Some(IronVersion::V1));

        session.add_encrypted_channel("!secure".to_string());
        assert!(session.is_encrypted_channel("!secure"));
        assert!(!session.is_encrypted_channel("!other"));
    }
}