//! Legion Protocol extensions and handling (legacy Iron Protocol support)
//!
//! This module contains Legion Protocol-specific functionality that extends
//! beyond standard IRC/IRCv3, including encrypted channels and protocol 
//! negotiation between Legion-capable clients and servers.
//!
//! Note: This module maintains backward compatibility with Iron Protocol
//! but has been updated to use Legion Protocol as the primary branding.

use crate::{ChannelType, IronError, Result};
use crate::utils::get_channel_type;
use crate::capabilities::Capability;

/// Legion Protocol version information
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IronVersion {
    V1,
}

/// Legion Protocol version information (current naming)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegionVersion {
    V1,
}

impl LegionVersion {
    /// Get the capability string for this Legion version
    pub fn as_capability(&self) -> &'static str {
        match self {
            LegionVersion::V1 => "+legion-protocol/v1",
        }
    }
}

impl IronVersion {
    /// Get the capability string for this Iron version (legacy support)
    pub fn as_capability(&self) -> &'static str {
        match self {
            IronVersion::V1 => "+iron-protocol/v1",
        }
    }
    
    /// Convert to Legion Protocol version
    pub fn to_legion_version(&self) -> LegionVersion {
        match self {
            IronVersion::V1 => LegionVersion::V1,
        }
    }
}

/// Result of Legion Protocol capability negotiation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IronNegotiationResult {
    /// Both client and server support Legion Protocol
    LegionCapable { version: LegionVersion },
    /// Both client and server support Iron Protocol (legacy)
    IronCapable { version: IronVersion },
    /// Only one side supports Legion/Iron Protocol (fallback to IRC)
    IrcFallback,
    /// No Legion/Iron Protocol support
    NotSupported,
}

/// Legion Protocol session state
#[derive(Debug, Clone)]
pub struct IronSession {
    iron_version: Option<IronVersion>,      // Legacy support
    legion_version: Option<LegionVersion>,  // Current version
    encrypted_channels: Vec<String>,
    negotiation_complete: bool,
}

impl IronSession {
    /// Create a new Legion Protocol session
    pub fn new() -> Self {
        Self {
            iron_version: None,
            legion_version: None,
            encrypted_channels: Vec::new(),
            negotiation_complete: false,
        }
    }

    /// Set the negotiated Iron Protocol version (legacy)
    pub fn set_version(&mut self, version: IronVersion) {
        self.iron_version = Some(version);
    }
    
    /// Set the negotiated Legion Protocol version
    pub fn set_legion_version(&mut self, version: LegionVersion) {
        self.legion_version = Some(version);
    }

    /// Check if Legion/Iron Protocol is active
    pub fn is_iron_active(&self) -> bool {
        (self.legion_version.is_some() || self.iron_version.is_some()) && self.negotiation_complete
    }
    
    /// Check if Legion Protocol specifically is active
    pub fn is_legion_active(&self) -> bool {
        self.legion_version.is_some() && self.negotiation_complete
    }

    /// Get the active Iron Protocol version (legacy)
    pub fn version(&self) -> Option<IronVersion> {
        self.iron_version
    }
    
    /// Get the active Legion Protocol version
    pub fn legion_version(&self) -> Option<LegionVersion> {
        self.legion_version
    }

    /// Complete Legion/Iron Protocol negotiation
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

/// Handle channel access control for Legion Protocol
pub struct IronChannelHandler;

impl IronChannelHandler {
    /// Check if a user can join a channel based on Legion Protocol capabilities
    pub fn can_join_channel(
        channel: &str,
        user_has_legion: bool,
        server_has_legion: bool,
    ) -> Result<ChannelJoinResult> {
        let channel_type = get_channel_type(channel);

        match channel_type {
            ChannelType::IrcGlobal | ChannelType::IrcLocal => {
                // Standard IRC channels - anyone can join
                Ok(ChannelJoinResult::Allowed)
            }
            ChannelType::LegionEncrypted => {
                // Legion encrypted channels require both client and server Legion support
                if user_has_legion && server_has_legion {
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

    /// Generate appropriate error message for IRC users trying to join Legion channels
    pub fn generate_error_message(channel: &str, error: &IronChannelError) -> String {
        match error {
            IronChannelError::IncompatibleClient => {
                format!(
                    "Cannot join encrypted channel {} - requires Legion Protocol support. \
                     Upgrade to a Legion-compatible client or ask channel admin to create \
                     a standard IRC channel (#{}) for IRC users.",
                    channel,
                    &channel[1..] // Remove the ! prefix to suggest # alternative
                )
            }
            IronChannelError::EncryptionRequired => {
                format!(
                    "Channel {} requires end-to-end encryption. \
                     Please use a Legion Protocol-compatible client.",
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

/// Reasons why a user might be denied access to a Legion channel
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IronChannelError {
    /// Client doesn't support Legion Protocol
    IncompatibleClient,
    /// Channel requires encryption but user can't provide it
    EncryptionRequired,
}

/// Detect Legion/Iron Protocol support during capability negotiation
pub fn detect_legion_support(
    client_caps: &[Capability],
    server_caps: &[Capability],
) -> IronNegotiationResult {
    let client_legion = client_caps
        .iter()
        .any(|cap| matches!(cap, Capability::LegionProtocolV1));
    let server_legion = server_caps
        .iter()
        .any(|cap| matches!(cap, Capability::LegionProtocolV1));
        
    let client_iron = client_caps
        .iter()
        .any(|cap| matches!(cap, Capability::IronProtocolV1));
    let server_iron = server_caps
        .iter()
        .any(|cap| matches!(cap, Capability::IronProtocolV1));

    // Prefer Legion Protocol over Iron Protocol
    match (client_legion, server_legion) {
        (true, true) => IronNegotiationResult::LegionCapable {
            version: LegionVersion::V1,
        },
        _ => {
            // Fall back to Iron Protocol support
            match (client_iron, server_iron) {
                (true, true) => IronNegotiationResult::IronCapable {
                    version: IronVersion::V1,
                },
                (true, false) | (false, true) => {
                    // Check if at least one side supports Legion (mixed capability fallback)
                    if client_legion || server_legion {
                        IronNegotiationResult::IrcFallback
                    } else {
                        IronNegotiationResult::IrcFallback
                    }
                },
                (false, false) => {
                    // Check if at least one side supports Legion
                    if client_legion || server_legion {
                        IronNegotiationResult::IrcFallback
                    } else {
                        IronNegotiationResult::NotSupported
                    }
                },
            }
        }
    }
}

/// Legacy function for backward compatibility
#[deprecated(note = "Use detect_legion_support instead")]
pub fn detect_iron_support(
    client_caps: &[Capability],
    server_caps: &[Capability],
) -> IronNegotiationResult {
    detect_legion_support(client_caps, server_caps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iron_version_capability() {
        // Test legacy Iron version
        assert_eq!(IronVersion::V1.as_capability(), "+iron-protocol/v1");
        
        // Test new Legion version
        assert_eq!(LegionVersion::V1.as_capability(), "+legion-protocol/v1");
        
        // Test conversion
        assert_eq!(IronVersion::V1.to_legion_version(), LegionVersion::V1);
    }

    #[test]
    fn test_channel_access_control() {
        // Standard IRC channels - always allowed
        let result = IronChannelHandler::can_join_channel("#general", false, false).unwrap();
        assert_eq!(result, ChannelJoinResult::Allowed);

        // Legion encrypted channel with compatible clients
        let result = IronChannelHandler::can_join_channel("!encrypted", true, true).unwrap();
        assert_eq!(result, ChannelJoinResult::AllowedEncrypted);

        // Legion encrypted channel with incompatible client
        let result = IronChannelHandler::can_join_channel("!encrypted", false, true).unwrap();
        assert!(matches!(
            result,
            ChannelJoinResult::Denied {
                reason: IronChannelError::IncompatibleClient
            }
        ));
    }

    #[test]
    fn test_legion_detection() {
        // Test Legion Protocol detection (preferred)
        let client_caps = vec![Capability::LegionProtocolV1, Capability::MessageTags];
        let server_caps = vec![Capability::LegionProtocolV1, Capability::Sasl];

        let result = detect_legion_support(&client_caps, &server_caps);
        assert_eq!(
            result,
            IronNegotiationResult::LegionCapable {
                version: LegionVersion::V1
            }
        );
        
        // Test Iron Protocol fallback (legacy)
        let client_caps = vec![Capability::IronProtocolV1, Capability::MessageTags];
        let server_caps = vec![Capability::IronProtocolV1, Capability::Sasl];

        let result = detect_legion_support(&client_caps, &server_caps);
        assert_eq!(
            result,
            IronNegotiationResult::IronCapable {
                version: IronVersion::V1
            }
        );

        // Test fallback scenario
        let client_caps = vec![Capability::MessageTags];
        let result = detect_legion_support(&client_caps, &server_caps);
        assert_eq!(result, IronNegotiationResult::IrcFallback);
        
        // Test backward compatibility
        #[allow(deprecated)]
        let result = detect_iron_support(&client_caps, &server_caps);
        assert_eq!(result, IronNegotiationResult::IrcFallback);
    }

    #[test]
    fn test_legion_session() {
        let mut session = IronSession::new();
        assert!(!session.is_iron_active());
        assert!(!session.is_legion_active());

        // Test legacy Iron Protocol support
        session.set_version(IronVersion::V1);
        session.complete_negotiation();
        assert!(session.is_iron_active());
        assert!(!session.is_legion_active());
        assert_eq!(session.version(), Some(IronVersion::V1));
        
        // Test new Legion Protocol support
        let mut legion_session = IronSession::new();
        legion_session.set_legion_version(LegionVersion::V1);
        legion_session.complete_negotiation();
        assert!(legion_session.is_iron_active()); // Should be true for either protocol
        assert!(legion_session.is_legion_active());
        assert_eq!(legion_session.legion_version(), Some(LegionVersion::V1));

        session.add_encrypted_channel("!secure".to_string());
        assert!(session.is_encrypted_channel("!secure"));
        assert!(!session.is_encrypted_channel("!other"));
    }
}