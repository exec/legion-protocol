//! Legion Protocol channel administration
//! 
//! Provides channel management, role-based permissions, and administrative operations
//! for Legion encrypted channels.

use crate::error::{IronError, Result};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use std::time::SystemTime;

/// Channel administration operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdminOperation {
    /// Create a new encrypted channel
    CreateChannel {
        channel: String,
        settings: ChannelSettings,
    },
    /// Set channel topic
    SetTopic {
        channel: String,
        topic: String,
    },
    /// Change channel mode
    SetMode {
        channel: String,
        mode: ChannelMode,
        enabled: bool,
    },
    /// Manage channel member
    MemberOperation {
        channel: String,
        target: String,
        operation: MemberOperation,
    },
    /// Manage channel bans
    BanOperation {
        channel: String,
        target: String,
        operation: BanOperation,
        duration: Option<SystemTime>,
    },
    /// Key management operations
    KeyOperation {
        channel: String,
        operation: KeyOperation,
    },
}

/// Member management operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MemberOperation {
    /// Invite user to channel
    Invite,
    /// Remove user from channel (kick)
    Kick { reason: Option<String> },
    /// Grant operator status
    Op,
    /// Remove operator status
    Deop,
    /// Grant voice status
    Voice,
    /// Remove voice status
    Devoice,
    /// Change member role
    SetRole { role: MemberRole },
    /// Mute member (temporary silence)
    Mute { duration: Option<SystemTime> },
    /// Unmute member
    Unmute,
}

/// Ban management operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BanOperation {
    /// Add ban
    Add { reason: Option<String> },
    /// Remove ban
    Remove,
    /// List bans
    List,
    /// Check if user is banned
    Check,
}

/// Key management operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyOperation {
    /// Rotate channel encryption keys
    Rotate,
    /// Backup current keys
    Backup,
    /// Restore keys from backup
    Restore { backup_id: String },
    /// Generate new key pair
    Generate,
    /// Export public key
    ExportPublic,
    /// Import member public key
    ImportPublic { user_id: String, public_key: Vec<u8> },
}

/// Channel member roles with hierarchical permissions
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemberRole {
    /// Channel founder (highest level)
    Founder,
    /// Channel owner (can manage all aspects)
    Owner,
    /// Channel administrator (can manage members)
    Admin,
    /// Channel operator (can moderate)
    Operator,
    /// Half-operator (limited moderation)
    HalfOp,
    /// Voiced member (can speak when moderated)
    Voice,
    /// Regular member
    Member,
    /// Restricted member (limited permissions)
    Restricted,
    /// Muted member (cannot speak)
    Muted,
}

/// Channel operational modes
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChannelMode {
    /// Moderated channel (only voiced+ can speak)
    Moderated,
    /// Invite-only channel
    InviteOnly,
    /// No external messages
    NoExternal,
    /// Topic protection (only ops can change)
    TopicProtected,
    /// Secret channel (hidden from lists)
    Secret,
    /// Private channel (invite required)
    Private,
    /// Key rotation enabled
    KeyRotation,
    /// Message history enabled
    History,
    /// Anonymous mode (hide real identities)
    Anonymous,
    /// Rate limiting enabled
    RateLimit,
}

/// Comprehensive channel settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelSettings {
    /// Channel topic
    pub topic: Option<String>,
    /// Topic set by (user and timestamp)
    pub topic_set_by: Option<(String, SystemTime)>,
    /// Active channel modes
    pub modes: HashSet<ChannelMode>,
    /// Maximum number of members
    pub member_limit: Option<usize>,
    /// Channel password/key
    pub password: Option<String>,
    /// Invite-only list
    pub invite_list: HashSet<String>,
    /// Exception list (users who can bypass bans)
    pub exception_list: HashSet<String>,
    /// Quiet list (users who cannot speak)
    pub quiet_list: HashSet<String>,
    /// Rate limiting settings
    pub rate_limit: Option<RateLimit>,
    /// Key rotation interval in seconds
    pub key_rotation_interval: Option<u64>,
    /// Message history retention
    pub history_retention: Option<u64>,
    /// Channel creation time
    pub created_at: SystemTime,
    /// Last activity time
    pub last_activity: SystemTime,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    /// Messages per time window
    pub messages: u32,
    /// Time window in seconds
    pub window: u64,
    /// Burst allowance
    pub burst: u32,
}

/// Channel ban entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelBan {
    /// Banned pattern (nick!user@host or Legion ID)
    pub pattern: String,
    /// Ban reason
    pub reason: Option<String>,
    /// Who set the ban
    pub set_by: String,
    /// When the ban was set
    pub set_at: SystemTime,
    /// When the ban expires (if temporary)
    pub expires_at: Option<SystemTime>,
    /// Ban type
    pub ban_type: BanType,
}

/// Types of bans
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BanType {
    /// Full ban (cannot join)
    Full,
    /// Quiet ban (can join but cannot speak)
    Quiet,
    /// Invite ban (cannot be invited)
    Invite,
}

/// Channel administration result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminResult {
    /// Operation that was performed
    pub operation: AdminOperation,
    /// Whether the operation succeeded
    pub success: bool,
    /// Result message or error description
    pub message: String,
    /// Additional data (e.g., ban lists, member info)
    pub data: Option<AdminData>,
    /// Timestamp of the operation
    pub timestamp: SystemTime,
}

/// Additional data returned by admin operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdminData {
    /// List of channel members
    MemberList(Vec<ChannelMember>),
    /// List of channel bans
    BanList(Vec<ChannelBan>),
    /// Channel information
    ChannelInfo(ChannelInfo),
    /// Key information
    KeyInfo(KeyInfo),
    /// Permission information
    Permissions(HashSet<Permission>),
}

/// Channel member information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelMember {
    /// Member user ID
    pub user_id: String,
    /// Member nickname
    pub nickname: String,
    /// Member role in channel
    pub role: MemberRole,
    /// When the member joined
    pub joined_at: SystemTime,
    /// Last activity time
    pub last_activity: SystemTime,
    /// Member's Legion public key
    pub public_key: Option<Vec<u8>>,
    /// Custom permissions (overrides role defaults)
    pub custom_permissions: Option<HashSet<Permission>>,
    /// Whether member is currently online
    pub is_online: bool,
}

/// Channel information summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelInfo {
    /// Channel name
    pub name: String,
    /// Channel settings
    pub settings: ChannelSettings,
    /// Number of members
    pub member_count: usize,
    /// Current topic
    pub topic: Option<String>,
    /// Channel modes
    pub modes: HashSet<ChannelMode>,
    /// Channel statistics
    pub stats: ChannelStats,
}

/// Channel statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelStats {
    /// Total messages sent
    pub total_messages: u64,
    /// Messages today
    pub messages_today: f64,
    /// Average messages per day
    pub avg_messages_per_day: f64,
    /// Most active member
    pub most_active_member: Option<String>,
    /// Key rotations performed
    pub key_rotations: u64,
    /// Last key rotation
    pub last_key_rotation: Option<SystemTime>,
}

impl Default for ChannelStats {
    fn default() -> Self {
        Self {
            total_messages: 0,
            messages_today: 0.0,
            avg_messages_per_day: 0.0,
            most_active_member: None,
            key_rotations: 0,
            last_key_rotation: None,
        }
    }
}

/// Encryption key information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    /// Current key version/sequence
    pub key_version: u64,
    /// Key creation time
    pub created_at: SystemTime,
    /// Key rotation schedule
    pub rotation_schedule: Option<SystemTime>,
    /// Number of members with current key
    pub member_key_count: usize,
    /// Backup availability
    pub has_backup: bool,
}

/// Granular permissions for channel operations
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    // Basic permissions
    /// Can send messages to channel
    SendMessage,
    /// Can read channel messages
    ReadMessage,
    /// Can join the channel
    JoinChannel,
    /// Can leave the channel
    LeaveChannel,
    
    // Moderation permissions
    /// Can kick members
    KickMember,
    /// Can ban members
    BanMember,
    /// Can unban members
    UnbanMember,
    /// Can mute members
    MuteMember,
    /// Can unmute members
    UnmuteMember,
    
    // Channel management
    /// Can change channel topic
    SetTopic,
    /// Can change channel modes
    SetMode,
    /// Can invite members
    InviteMember,
    /// Can grant voice status
    GrantVoice,
    /// Can grant operator status
    GrantOp,
    
    // Administrative permissions
    /// Can manage channel settings
    ManageChannel,
    /// Can manage member roles
    ManageRoles,
    /// Can view channel logs
    ViewLogs,
    /// Can manage channel bans
    ManageBans,
    
    // Encryption permissions
    /// Can rotate channel keys
    RotateKeys,
    /// Can backup keys
    BackupKeys,
    /// Can restore keys
    RestoreKeys,
    /// Can manage member keys
    ManageKeys,
    
    // Owner permissions
    /// Can transfer ownership
    TransferOwnership,
    /// Can destroy channel
    DestroyChannel,
    /// Can manage administrators
    ManageAdmins,
}

impl Default for ChannelSettings {
    fn default() -> Self {
        Self {
            topic: None,
            topic_set_by: None,
            modes: HashSet::new(),
            member_limit: None,
            password: None,
            invite_list: HashSet::new(),
            exception_list: HashSet::new(),
            quiet_list: HashSet::new(),
            rate_limit: None,
            key_rotation_interval: Some(86400), // 24 hours
            history_retention: Some(2592000), // 30 days
            created_at: SystemTime::now(),
            last_activity: SystemTime::now(),
        }
    }
}

impl MemberRole {
    /// Check if this role has a specific permission
    pub fn has_permission(&self, permission: &Permission) -> bool {
        match self {
            MemberRole::Founder => true, // Founder has all permissions
            MemberRole::Owner => !matches!(permission, Permission::TransferOwnership),
            MemberRole::Admin => matches!(permission,
                Permission::SendMessage | Permission::ReadMessage | Permission::JoinChannel | Permission::LeaveChannel |
                Permission::KickMember | Permission::BanMember | Permission::UnbanMember | Permission::MuteMember | Permission::UnmuteMember |
                Permission::SetTopic | Permission::SetMode | Permission::InviteMember | Permission::GrantVoice | Permission::GrantOp |
                Permission::ManageChannel | Permission::ManageRoles | Permission::ViewLogs | Permission::ManageBans |
                Permission::RotateKeys | Permission::BackupKeys | Permission::RestoreKeys | Permission::ManageKeys
            ),
            MemberRole::Operator => matches!(permission,
                Permission::SendMessage | Permission::ReadMessage | Permission::JoinChannel | Permission::LeaveChannel |
                Permission::KickMember | Permission::BanMember | Permission::UnbanMember | Permission::MuteMember | Permission::UnmuteMember |
                Permission::SetTopic | Permission::InviteMember | Permission::GrantVoice |
                Permission::ViewLogs | Permission::ManageBans
            ),
            MemberRole::HalfOp => matches!(permission,
                Permission::SendMessage | Permission::ReadMessage | Permission::JoinChannel | Permission::LeaveChannel |
                Permission::MuteMember | Permission::UnmuteMember | Permission::InviteMember |
                Permission::ViewLogs
            ),
            MemberRole::Voice => matches!(permission,
                Permission::SendMessage | Permission::ReadMessage | Permission::JoinChannel | Permission::LeaveChannel
            ),
            MemberRole::Member => matches!(permission,
                Permission::SendMessage | Permission::ReadMessage | Permission::JoinChannel | Permission::LeaveChannel
            ),
            MemberRole::Restricted => matches!(permission,
                Permission::ReadMessage | Permission::JoinChannel | Permission::LeaveChannel
            ),
            MemberRole::Muted => matches!(permission,
                Permission::ReadMessage | Permission::JoinChannel | Permission::LeaveChannel
            ),
        }
    }
    
    /// Get all permissions for this role
    pub fn permissions(&self) -> HashSet<Permission> {
        use Permission::*;
        let all_permissions = vec![
            SendMessage, ReadMessage, JoinChannel, LeaveChannel,
            KickMember, BanMember, UnbanMember, MuteMember, UnmuteMember,
            SetTopic, SetMode, InviteMember, GrantVoice, GrantOp,
            ManageChannel, ManageRoles, ViewLogs, ManageBans,
            RotateKeys, BackupKeys, RestoreKeys, ManageKeys,
            TransferOwnership, DestroyChannel, ManageAdmins,
        ];
        
        all_permissions.into_iter()
            .filter(|p| self.has_permission(p))
            .collect()
    }
    
    /// Check if this role can perform an operation on another role
    pub fn can_manage_role(&self, target_role: &MemberRole) -> bool {
        use MemberRole::*;
        match (self, target_role) {
            (Founder, _) => true,
            (Owner, Founder) => false,
            (Owner, _) => true,
            (Admin, Founder | Owner) => false,
            (Admin, _) => true,
            (Operator, Founder | Owner | Admin) => false,
            (Operator, _) => true,
            _ => false,
        }
    }
    
    /// Get role hierarchy level (higher number = more permissions)
    pub fn hierarchy_level(&self) -> u8 {
        match self {
            MemberRole::Founder => 100,
            MemberRole::Owner => 90,
            MemberRole::Admin => 80,
            MemberRole::Operator => 70,
            MemberRole::HalfOp => 60,
            MemberRole::Voice => 50,
            MemberRole::Member => 40,
            MemberRole::Restricted => 30,
            MemberRole::Muted => 20,
        }
    }
}

impl ChannelBan {
    /// Check if this ban is currently active
    pub fn is_active(&self) -> bool {
        match self.expires_at {
            Some(expires) => SystemTime::now() < expires,
            None => true, // Permanent ban
        }
    }
    
    /// Check if this ban matches a user pattern
    pub fn matches_pattern(&self, pattern: &str) -> bool {
        // Simple wildcard matching - in production this would be more sophisticated
        if self.pattern.contains('*') || self.pattern.contains('?') {
            self.wildcard_match(&self.pattern, pattern)
        } else {
            self.pattern == pattern
        }
    }
    
    fn wildcard_match(&self, pattern: &str, text: &str) -> bool {
        // Basic wildcard matching implementation
        // * matches any sequence of characters
        // ? matches any single character
        let pattern_chars: Vec<char> = pattern.chars().collect();
        let text_chars: Vec<char> = text.chars().collect();
        
        self.match_recursive(&pattern_chars, &text_chars, 0, 0)
    }
    
    fn match_recursive(&self, pattern: &[char], text: &[char], p_idx: usize, t_idx: usize) -> bool {
        if p_idx >= pattern.len() {
            return t_idx >= text.len();
        }
        
        match pattern[p_idx] {
            '*' => {
                // Try matching zero or more characters
                for i in t_idx..=text.len() {
                    if self.match_recursive(pattern, text, p_idx + 1, i) {
                        return true;
                    }
                }
                false
            },
            '?' => {
                // Match any single character
                if t_idx < text.len() {
                    self.match_recursive(pattern, text, p_idx + 1, t_idx + 1)
                } else {
                    false
                }
            },
            c => {
                // Exact character match
                if t_idx < text.len() && text[t_idx] == c {
                    self.match_recursive(pattern, text, p_idx + 1, t_idx + 1)
                } else {
                    false
                }
            }
        }
    }
}

/// Channel administration manager
pub struct ChannelAdmin {
    /// User performing the admin operation
    user_id: String,
    /// User's role in the channel
    user_role: MemberRole,
    /// Additional permissions granted to user
    user_permissions: HashSet<Permission>,
}

impl ChannelAdmin {
    /// Create a new channel admin context
    pub fn new(user_id: String, user_role: MemberRole, user_permissions: HashSet<Permission>) -> Self {
        Self {
            user_id,
            user_role,
            user_permissions,
        }
    }
    
    /// Check if the user can perform a specific operation
    pub fn can_perform(&self, operation: &AdminOperation, target_channel: &ChannelSettings) -> bool {
        match operation {
            AdminOperation::CreateChannel { .. } => {
                // Anyone can create channels, but may be subject to server limits
                true
            },
            AdminOperation::SetTopic { .. } => {
                self.has_permission(&Permission::SetTopic) &&
                (!target_channel.modes.contains(&ChannelMode::TopicProtected) || 
                 self.user_role.hierarchy_level() >= MemberRole::Operator.hierarchy_level())
            },
            AdminOperation::SetMode { .. } => {
                self.has_permission(&Permission::SetMode)
            },
            AdminOperation::MemberOperation { operation, .. } => {
                match operation {
                    MemberOperation::Invite => self.has_permission(&Permission::InviteMember),
                    MemberOperation::Kick { .. } => self.has_permission(&Permission::KickMember),
                    MemberOperation::Op | MemberOperation::Deop => self.has_permission(&Permission::GrantOp),
                    MemberOperation::Voice | MemberOperation::Devoice => self.has_permission(&Permission::GrantVoice),
                    MemberOperation::SetRole { .. } => self.has_permission(&Permission::ManageRoles),
                    MemberOperation::Mute { .. } | MemberOperation::Unmute => self.has_permission(&Permission::MuteMember),
                }
            },
            AdminOperation::BanOperation { operation, .. } => {
                match operation {
                    BanOperation::Add { .. } => self.has_permission(&Permission::BanMember),
                    BanOperation::Remove => self.has_permission(&Permission::UnbanMember),
                    BanOperation::List | BanOperation::Check => self.has_permission(&Permission::ViewLogs),
                }
            },
            AdminOperation::KeyOperation { operation, .. } => {
                match operation {
                    KeyOperation::Rotate => self.has_permission(&Permission::RotateKeys),
                    KeyOperation::Backup => self.has_permission(&Permission::BackupKeys),
                    KeyOperation::Restore { .. } => self.has_permission(&Permission::RestoreKeys),
                    KeyOperation::Generate => self.has_permission(&Permission::ManageKeys),
                    KeyOperation::ExportPublic => true, // Anyone can export public keys
                    KeyOperation::ImportPublic { .. } => self.has_permission(&Permission::ManageKeys),
                }
            },
        }
    }
    
    /// Check if user has a specific permission (from role or custom grants)
    pub fn has_permission(&self, permission: &Permission) -> bool {
        self.user_role.has_permission(permission) || self.user_permissions.contains(permission)
    }
    
    /// Get all permissions for this user
    pub fn get_permissions(&self) -> HashSet<Permission> {
        let mut permissions = self.user_role.permissions();
        permissions.extend(self.user_permissions.clone());
        permissions
    }
    
    /// Check if user can manage another user's role
    pub fn can_manage_user_role(&self, target_role: &MemberRole) -> bool {
        self.user_role.can_manage_role(target_role)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_role_permissions() {
        let owner = MemberRole::Owner;
        let member = MemberRole::Member;
        
        assert!(owner.has_permission(&Permission::KickMember));
        assert!(!member.has_permission(&Permission::KickMember));
        assert!(member.has_permission(&Permission::SendMessage));
    }
    
    #[test]
    fn test_role_hierarchy() {
        let founder = MemberRole::Founder;
        let admin = MemberRole::Admin;
        let member = MemberRole::Member;
        
        assert!(founder.can_manage_role(&admin));
        assert!(admin.can_manage_role(&member));
        assert!(!member.can_manage_role(&admin));
    }
    
    #[test]
    fn test_ban_wildcard_matching() {
        let ban = ChannelBan {
            pattern: "*@evil.com".to_string(),
            reason: Some("Spam domain".to_string()),
            set_by: "admin".to_string(),
            set_at: SystemTime::now(),
            expires_at: None,
            ban_type: BanType::Full,
        };
        
        assert!(ban.matches_pattern("user@evil.com"));
        assert!(ban.matches_pattern("spammer@evil.com"));
        assert!(!ban.matches_pattern("user@good.com"));
    }
    
    #[test]
    fn test_admin_permissions() {
        let admin = ChannelAdmin::new(
            "admin_user".to_string(),
            MemberRole::Admin,
            HashSet::new(),
        );
        
        let settings = ChannelSettings::default();
        let kick_op = AdminOperation::MemberOperation {
            channel: "!test".to_string(),
            target: "user".to_string(),
            operation: MemberOperation::Kick { reason: None },
        };
        
        assert!(admin.can_perform(&kick_op, &settings));
    }
}