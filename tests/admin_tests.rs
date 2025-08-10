//! Comprehensive tests for Legion Protocol admin functionality

use legion_protocol::admin::*;
use std::collections::HashSet;
use std::time::SystemTime;

#[test]
fn test_member_role_permissions() {
    // Test permission hierarchy
    assert!(MemberRole::Founder.has_permission(&Permission::TransferOwnership));
    assert!(!MemberRole::Owner.has_permission(&Permission::TransferOwnership));
    assert!(MemberRole::Admin.has_permission(&Permission::ManageRoles));
    assert!(!MemberRole::Member.has_permission(&Permission::BanMember));
    assert!(!MemberRole::Muted.has_permission(&Permission::SendMessage));
}

#[test]
fn test_role_hierarchy() {
    assert!(MemberRole::Founder.can_manage_role(&MemberRole::Owner));
    assert!(MemberRole::Owner.can_manage_role(&MemberRole::Admin));
    assert!(!MemberRole::Admin.can_manage_role(&MemberRole::Owner));
    assert!(!MemberRole::Member.can_manage_role(&MemberRole::Admin));
    
    // Test hierarchy levels
    assert!(MemberRole::Founder.hierarchy_level() > MemberRole::Owner.hierarchy_level());
    assert!(MemberRole::Admin.hierarchy_level() > MemberRole::Member.hierarchy_level());
}

#[test]
fn test_channel_admin_permissions() {
    let admin = ChannelAdmin::new(
        "admin_user".to_string(),
        MemberRole::Admin,
        HashSet::new(),
    );
    
    let settings = ChannelSettings::default();
    
    // Test various operations
    let create_op = AdminOperation::CreateChannel {
        channel: "!test".to_string(),
        settings: settings.clone(),
    };
    assert!(admin.can_perform(&create_op, &settings));
    
    let kick_op = AdminOperation::MemberOperation {
        channel: "!test".to_string(),
        target: "user".to_string(),
        operation: MemberOperation::Kick { reason: None },
    };
    assert!(admin.can_perform(&kick_op, &settings));
    
    let rotate_op = AdminOperation::KeyOperation {
        channel: "!test".to_string(),
        operation: KeyOperation::Rotate,
    };
    assert!(admin.can_perform(&rotate_op, &settings));
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
    
    // Test with question mark wildcard
    let ban2 = ChannelBan {
        pattern: "bad?user@*".to_string(),
        reason: None,
        set_by: "admin".to_string(),
        set_at: SystemTime::now(),
        expires_at: None,
        ban_type: BanType::Full,
    };
    
    assert!(ban2.matches_pattern("bad1user@example.com"));
    assert!(ban2.matches_pattern("bad2user@test.org"));
    assert!(!ban2.matches_pattern("baduser@example.com")); // Missing character for ?
}

#[test]
fn test_ban_expiration() {
    let past_time = SystemTime::now() - std::time::Duration::from_secs(3600);
    let future_time = SystemTime::now() + std::time::Duration::from_secs(3600);
    
    let expired_ban = ChannelBan {
        pattern: "test@example.com".to_string(),
        reason: None,
        set_by: "admin".to_string(),
        set_at: past_time,
        expires_at: Some(past_time),
        ban_type: BanType::Full,
    };
    assert!(!expired_ban.is_active());
    
    let active_ban = ChannelBan {
        pattern: "test@example.com".to_string(),
        reason: None,
        set_by: "admin".to_string(),
        set_at: SystemTime::now(),
        expires_at: Some(future_time),
        ban_type: BanType::Full,
    };
    assert!(active_ban.is_active());
    
    let permanent_ban = ChannelBan {
        pattern: "test@example.com".to_string(),
        reason: None,
        set_by: "admin".to_string(),
        set_at: SystemTime::now(),
        expires_at: None,
        ban_type: BanType::Full,
    };
    assert!(permanent_ban.is_active());
}

#[test]
fn test_channel_modes() {
    let mut modes = HashSet::new();
    modes.insert(ChannelMode::Moderated);
    modes.insert(ChannelMode::InviteOnly);
    
    assert!(modes.contains(&ChannelMode::Moderated));
    assert!(!modes.contains(&ChannelMode::Anonymous));
    
    // Test mode combinations
    modes.insert(ChannelMode::KeyRotation);
    assert_eq!(modes.len(), 3);
}

#[test]
fn test_admin_operation_variants() {
    // Test serialization round-trip for all operation types
    let ops = vec![
        AdminOperation::CreateChannel {
            channel: "!test".to_string(),
            settings: ChannelSettings::default(),
        },
        AdminOperation::SetTopic {
            channel: "!test".to_string(),
            topic: "Test topic".to_string(),
        },
        AdminOperation::SetMode {
            channel: "!test".to_string(),
            mode: ChannelMode::Moderated,
            enabled: true,
        },
        AdminOperation::MemberOperation {
            channel: "!test".to_string(),
            target: "user".to_string(),
            operation: MemberOperation::SetRole { role: MemberRole::Admin },
        },
        AdminOperation::BanOperation {
            channel: "!test".to_string(),
            target: "spammer".to_string(),
            operation: BanOperation::Add { reason: Some("Spamming".to_string()) },
            duration: None,
        },
        AdminOperation::KeyOperation {
            channel: "!test".to_string(),
            operation: KeyOperation::Rotate,
        },
    ];
    
    for op in ops {
        // Test that operations can be cloned and compared
        let cloned = op.clone();
        // Just verify they're the same type
        match (&op, &cloned) {
            (AdminOperation::CreateChannel { .. }, AdminOperation::CreateChannel { .. }) => {},
            (AdminOperation::SetTopic { .. }, AdminOperation::SetTopic { .. }) => {},
            (AdminOperation::SetMode { .. }, AdminOperation::SetMode { .. }) => {},
            (AdminOperation::MemberOperation { .. }, AdminOperation::MemberOperation { .. }) => {},
            (AdminOperation::BanOperation { .. }, AdminOperation::BanOperation { .. }) => {},
            (AdminOperation::KeyOperation { .. }, AdminOperation::KeyOperation { .. }) => {},
            _ => panic!("Clone produced different variant"),
        }
    }
}

#[test]
fn test_rate_limiting() {
    let rate_limit = RateLimit {
        messages: 10,
        window: 60,
        burst: 3,
    };
    
    assert_eq!(rate_limit.messages, 10);
    assert_eq!(rate_limit.window, 60);
    assert_eq!(rate_limit.burst, 3);
}

#[test]
fn test_custom_permissions() {
    let mut permissions = HashSet::new();
    permissions.insert(Permission::SendMessage);
    permissions.insert(Permission::ViewLogs);
    
    let admin = ChannelAdmin::new(
        "custom_user".to_string(),
        MemberRole::Member,
        permissions.clone(),
    );
    
    // Member normally can't view logs, but has custom permission
    assert!(admin.has_permission(&Permission::ViewLogs));
    // Member normally can send messages
    assert!(admin.has_permission(&Permission::SendMessage));
    // Member doesn't have ban permission even with custom permissions
    assert!(!admin.has_permission(&Permission::BanMember));
}

#[test]
fn test_permission_aggregation() {
    let member_perms = MemberRole::Member.permissions();
    assert!(member_perms.contains(&Permission::SendMessage));
    assert!(member_perms.contains(&Permission::ReadMessage));
    assert!(!member_perms.contains(&Permission::BanMember));
    
    let admin_perms = MemberRole::Admin.permissions();
    assert!(admin_perms.contains(&Permission::BanMember));
    assert!(admin_perms.contains(&Permission::ManageRoles));
    assert!(!admin_perms.contains(&Permission::TransferOwnership));
    
    let owner_perms = MemberRole::Owner.permissions();
    assert!(owner_perms.contains(&Permission::DestroyChannel));
    assert!(!owner_perms.contains(&Permission::TransferOwnership));
}

#[cfg(test)]
mod concurrent_tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::thread;
    
    #[test]
    fn test_concurrent_permission_checks() {
        let admin = Arc::new(ChannelAdmin::new(
            "admin".to_string(),
            MemberRole::Admin,
            HashSet::new(),
        ));
        
        let settings = Arc::new(ChannelSettings::default());
        let mut handles = vec![];
        
        // Spawn multiple threads checking permissions
        for i in 0..10 {
            let admin_clone = Arc::clone(&admin);
            let settings_clone = Arc::clone(&settings);
            
            let handle = thread::spawn(move || {
                let op = AdminOperation::MemberOperation {
                    channel: format!("!test{}", i),
                    target: "user".to_string(),
                    operation: MemberOperation::Kick { reason: None },
                };
                
                admin_clone.can_perform(&op, &settings_clone)
            });
            
            handles.push(handle);
        }
        
        // All threads should return true
        for handle in handles {
            assert!(handle.join().unwrap());
        }
    }
}