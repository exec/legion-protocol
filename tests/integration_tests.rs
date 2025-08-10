//! Integration tests for Legion Protocol

use legion_protocol::admin::*;
use std::collections::HashSet;
use std::time::{SystemTime, Duration};

#[test]
fn test_channel_lifecycle() {
    // Create a channel
    let mut settings = ChannelSettings::default();
    settings.topic = Some("Integration test channel".to_string());
    settings.modes.insert(ChannelMode::KeyRotation);
    settings.modes.insert(ChannelMode::History);
    
    let channel_info = ChannelInfo {
        name: "!test-channel".to_string(),
        settings: settings.clone(),
        member_count: 0,
        topic: settings.topic.clone(),
        modes: settings.modes.clone(),
        stats: ChannelStats::default(),
    };
    
    // Verify channel properties
    assert_eq!(channel_info.name, "!test-channel");
    assert_eq!(channel_info.topic, Some("Integration test channel".to_string()));
    assert!(channel_info.modes.contains(&ChannelMode::KeyRotation));
}

#[test]
fn test_member_lifecycle() {
    let timestamp = SystemTime::now();
    
    // Create founder
    let founder = ChannelMember {
        user_id: "founder123".to_string(),
        nickname: "FounderNick".to_string(),
        role: MemberRole::Founder,
        joined_at: timestamp,
        last_activity: timestamp,
        public_key: Some(vec![1, 2, 3, 4]),
        custom_permissions: None,
        is_online: true,
    };
    
    // Add regular member
    let member = ChannelMember {
        user_id: "member456".to_string(),
        nickname: "MemberNick".to_string(),
        role: MemberRole::Member,
        joined_at: timestamp,
        last_activity: timestamp,
        public_key: Some(vec![5, 6, 7, 8]),
        custom_permissions: Some(HashSet::from([Permission::InviteMember])),
        is_online: true,
    };
    
    // Verify role hierarchy
    assert!(founder.role.can_manage_role(&member.role));
    assert!(!member.role.can_manage_role(&founder.role));
    
    // Test custom permissions
    assert!(member.custom_permissions.as_ref().unwrap().contains(&Permission::InviteMember));
}

#[test]
fn test_admin_workflow() {
    let admin_id = "admin_user";
    let target_id = "target_user";
    let channel = "!test";
    
    // Create admin
    let admin = ChannelAdmin::new(
        admin_id.to_string(),
        MemberRole::Admin,
        HashSet::new(),
    );
    
    let settings = ChannelSettings::default();
    
    // Test various admin operations
    let operations = vec![
        // Kick a user
        AdminOperation::MemberOperation {
            channel: channel.to_string(),
            target: target_id.to_string(),
            operation: MemberOperation::Kick { 
                reason: Some("Violating rules".to_string()) 
            },
        },
        // Ban a user
        AdminOperation::BanOperation {
            channel: channel.to_string(),
            target: format!("*@{}", target_id),
            operation: BanOperation::Add { 
                reason: Some("Repeated violations".to_string()) 
            },
            duration: Some(SystemTime::now() + Duration::from_secs(86400)),
        },
        // Change topic
        AdminOperation::SetTopic {
            channel: channel.to_string(),
            topic: "New channel topic".to_string(),
        },
        // Set mode
        AdminOperation::SetMode {
            channel: channel.to_string(),
            mode: ChannelMode::Moderated,
            enabled: true,
        },
    ];
    
    // Verify admin can perform all operations
    for op in operations {
        assert!(admin.can_perform(&op, &settings), "Admin should be able to perform {:?}", op);
    }
}

#[test]
fn test_ban_enforcement() {
    let current_time = SystemTime::now();
    
    // Create various ban types
    let bans = vec![
        // Permanent ban
        ChannelBan {
            pattern: "spammer@*".to_string(),
            reason: Some("Permanent spam".to_string()),
            set_by: "admin".to_string(),
            set_at: current_time,
            expires_at: None,
            ban_type: BanType::Full,
        },
        // Temporary ban (1 hour)
        ChannelBan {
            pattern: "temp_user@example.com".to_string(),
            reason: Some("Temporary violation".to_string()),
            set_by: "moderator".to_string(),
            set_at: current_time,
            expires_at: Some(current_time + Duration::from_secs(3600)),
            ban_type: BanType::Full,
        },
        // Quiet ban
        ChannelBan {
            pattern: "noisy@*".to_string(),
            reason: Some("Too noisy".to_string()),
            set_by: "admin".to_string(),
            set_at: current_time,
            expires_at: None,
            ban_type: BanType::Quiet,
        },
    ];
    
    // Test ban matching
    assert!(bans[0].matches_pattern("spammer@evil.com"));
    assert!(bans[0].matches_pattern("spammer@spam.org"));
    assert!(!bans[0].matches_pattern("good@user.com"));
    
    assert!(bans[1].matches_pattern("temp_user@example.com"));
    assert!(!bans[1].matches_pattern("temp_user@other.com"));
    
    assert!(bans[2].matches_pattern("noisy@loud.com"));
    
    // All bans should be active
    for ban in &bans {
        assert!(ban.is_active());
    }
}

#[test]
fn test_permission_enforcement() {
    let settings = ChannelSettings::default();
    
    // Test different roles
    let roles = vec![
        (MemberRole::Founder, "founder"),
        (MemberRole::Owner, "owner"),
        (MemberRole::Admin, "admin"),
        (MemberRole::Operator, "operator"),
        (MemberRole::Member, "member"),
        (MemberRole::Muted, "muted"),
    ];
    
    for (role, user_id) in roles {
        let user = ChannelAdmin::new(
            user_id.to_string(),
            role.clone(),
            HashSet::new(),
        );
        
        // Test kick permission
        let kick_op = AdminOperation::MemberOperation {
            channel: "!test".to_string(),
            target: "target".to_string(),
            operation: MemberOperation::Kick { reason: None },
        };
        
        let can_kick = user.can_perform(&kick_op, &settings);
        
        // Only Operator and above can kick
        match role {
            MemberRole::Founder | MemberRole::Owner | MemberRole::Admin | MemberRole::Operator => {
                assert!(can_kick, "{:?} should be able to kick", role);
            }
            _ => {
                assert!(!can_kick, "{:?} should NOT be able to kick", role);
            }
        }
    }
}

#[test]
fn test_key_operations() {
    let admin = ChannelAdmin::new(
        "key_admin".to_string(),
        MemberRole::Admin,
        HashSet::new(),
    );
    
    let settings = ChannelSettings::default();
    
    let key_ops = vec![
        KeyOperation::Rotate,
        KeyOperation::Backup,
        KeyOperation::Generate,
        KeyOperation::ExportPublic,
    ];
    
    for key_op in key_ops {
        let op = AdminOperation::KeyOperation {
            channel: "!secure".to_string(),
            operation: key_op.clone(),
        };
        
        let can_perform = admin.can_perform(&op, &settings);
        
        match key_op {
            KeyOperation::ExportPublic => {
                assert!(can_perform, "Anyone should be able to export public keys");
            }
            _ => {
                assert!(can_perform, "Admin should be able to perform {:?}", key_op);
            }
        }
    }
}

#[test]
fn test_channel_statistics() {
    let mut stats = ChannelStats::default();
    
    // Simulate activity
    stats.total_messages = 1000;
    stats.messages_today = 50.0;
    stats.avg_messages_per_day = 33.3;
    stats.most_active_member = Some("active_user".to_string());
    stats.key_rotations = 5;
    stats.last_key_rotation = Some(SystemTime::now());
    
    assert_eq!(stats.total_messages, 1000);
    assert_eq!(stats.messages_today, 50.0);
    assert!(stats.last_key_rotation.is_some());
}

#[test]
fn test_admin_result_handling() {
    let timestamp = SystemTime::now();
    
    // Successful operation
    let success_result = AdminResult {
        operation: AdminOperation::SetTopic {
            channel: "!test".to_string(),
            topic: "New topic".to_string(),
        },
        success: true,
        message: "Topic updated successfully".to_string(),
        data: None,
        timestamp,
    };
    
    assert!(success_result.success);
    assert_eq!(success_result.message, "Topic updated successfully");
    
    // Failed operation with data
    let member_list = vec![
        ChannelMember {
            user_id: "user1".to_string(),
            nickname: "User1".to_string(),
            role: MemberRole::Member,
            joined_at: timestamp,
            last_activity: timestamp,
            public_key: None,
            custom_permissions: None,
            is_online: true,
        },
    ];
    
    let fail_result = AdminResult {
        operation: AdminOperation::MemberOperation {
            channel: "!test".to_string(),
            target: "user1".to_string(),
            operation: MemberOperation::Kick { reason: None },
        },
        success: false,
        message: "Insufficient permissions".to_string(),
        data: Some(AdminData::MemberList(member_list)),
        timestamp,
    };
    
    assert!(!fail_result.success);
    assert!(fail_result.data.is_some());
}

#[test]
fn test_complex_permission_scenario() {
    // Create a channel with specific settings
    let mut settings = ChannelSettings::default();
    settings.modes.insert(ChannelMode::TopicProtected);
    settings.invite_list.insert("trusted_user".to_string());
    settings.quiet_list.insert("quiet_user".to_string());
    
    // Test topic change with protected mode
    let operator = ChannelAdmin::new(
        "op_user".to_string(),
        MemberRole::Operator,
        HashSet::new(),
    );
    
    let topic_op = AdminOperation::SetTopic {
        channel: "!protected".to_string(),
        topic: "New protected topic".to_string(),
    };
    
    // Operator can change topic even when protected
    assert!(operator.can_perform(&topic_op, &settings));
    
    // Regular member cannot
    let member = ChannelAdmin::new(
        "regular_user".to_string(),
        MemberRole::Member,
        HashSet::new(),
    );
    assert!(!member.can_perform(&topic_op, &settings));
}

// Test for thread safety and concurrent operations
#[cfg(test)]
mod stress_tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::thread;
    
    #[test]
    fn test_concurrent_ban_checking() {
        let ban = Arc::new(ChannelBan {
            pattern: "*@banned.com".to_string(),
            reason: Some("Domain ban".to_string()),
            set_by: "admin".to_string(),
            set_at: SystemTime::now(),
            expires_at: None,
            ban_type: BanType::Full,
        });
        
        let mut handles = vec![];
        
        // Spawn multiple threads checking ban patterns
        for i in 0..20 {
            let ban_clone = Arc::clone(&ban);
            
            let handle = thread::spawn(move || {
                let test_pattern = format!("user{}@banned.com", i);
                ban_clone.matches_pattern(&test_pattern)
            });
            
            handles.push(handle);
        }
        
        // All should match
        for handle in handles {
            assert!(handle.join().unwrap());
        }
    }
}