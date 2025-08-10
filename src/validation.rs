//! Protocol validation and security checks

use crate::error::{IronError, Result};
use crate::constants::*;
use crate::utils::{is_valid_nick, is_valid_channel};

/// Validate an IRC nickname
pub fn validate_nickname(nick: &str) -> Result<()> {
    if !is_valid_nick(nick) {
        return Err(IronError::InvalidInput(
            format!("Invalid nickname: {}", nick)
        ));
    }
    Ok(())
}

/// Validate an IRC channel name
pub fn validate_channel_name(channel: &str) -> Result<()> {
    if !is_valid_channel(channel) {
        return Err(IronError::InvalidInput(
            format!("Invalid channel name: {}", channel)
        ));
    }
    Ok(())
}

/// Validate message content for security issues
pub fn validate_message_content(content: &str) -> Result<()> {
    // Check for null bytes
    if content.contains('\0') {
        return Err(IronError::SecurityViolation(
            "Message contains null bytes".to_string()
        ));
    }

    // Check for control characters that could cause issues
    if content.chars().any(|c| c.is_control() && c != '\t') {
        return Err(IronError::SecurityViolation(
            "Message contains dangerous control characters".to_string()
        ));
    }

    // Check message length
    if content.len() > MAX_MESSAGE_LENGTH {
        return Err(IronError::InvalidInput(
            format!("Message too long: {} > {}", content.len(), MAX_MESSAGE_LENGTH)
        ));
    }

    Ok(())
}

/// Validate hostname/server name
pub fn validate_hostname(hostname: &str) -> Result<()> {
    if hostname.is_empty() {
        return Err(IronError::InvalidInput(
            "Hostname cannot be empty".to_string()
        ));
    }

    if hostname.len() > 255 {
        return Err(IronError::InvalidInput(
            "Hostname too long".to_string()
        ));
    }

    // Basic hostname validation
    if !hostname.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
        return Err(IronError::InvalidInput(
            "Invalid characters in hostname".to_string()
        ));
    }

    // Cannot start or end with hyphen
    if hostname.starts_with('-') || hostname.ends_with('-') {
        return Err(IronError::InvalidInput(
            "Hostname cannot start or end with hyphen".to_string()
        ));
    }

    Ok(())
}

/// Validate user information for registration
pub fn validate_user_info(username: &str, realname: &str) -> Result<()> {
    // Validate username
    if username.is_empty() || username.len() > 32 {
        return Err(IronError::InvalidInput(
            "Invalid username length".to_string()
        ));
    }

    if !username.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
        return Err(IronError::InvalidInput(
            "Invalid characters in username".to_string()
        ));
    }

    // Validate realname
    if realname.len() > 255 {
        return Err(IronError::InvalidInput(
            "Real name too long".to_string()
        ));
    }

    // Check for dangerous characters in realname
    if realname.contains('\0') || realname.contains('\r') || realname.contains('\n') {
        return Err(IronError::SecurityViolation(
            "Real name contains invalid characters".to_string()
        ));
    }

    Ok(())
}

/// Validate CTCP message
pub fn validate_ctcp_message(message: &str) -> Result<()> {
    // CTCP messages should be wrapped in \x01
    if !message.starts_with('\x01') || !message.ends_with('\x01') {
        return Err(IronError::InvalidInput(
            "Invalid CTCP message format".to_string()
        ));
    }

    // Extract the inner content
    let content = &message[1..message.len()-1];
    
    // Basic length check
    if content.len() > MAX_MESSAGE_LENGTH - 20 { // Leave room for formatting
        return Err(IronError::InvalidInput(
            "CTCP message too long".to_string()
        ));
    }

    // Check for nested CTCP delimiters
    if content.contains('\x01') {
        return Err(IronError::SecurityViolation(
            "Nested CTCP delimiters not allowed".to_string()
        ));
    }

    Ok(())
}

/// Check for flood/spam patterns
pub fn check_flood_protection(messages: &[&str], _time_window: std::time::Duration) -> Result<()> {
    if messages.len() > 10 {
        return Err(IronError::RateLimit(
            "Too many messages in time window".to_string()
        ));
    }

    // Check for repeated messages (simple spam detection)
    if messages.len() >= 3 {
        let last_three: Vec<&str> = messages.iter().rev().take(3).cloned().collect();
        if last_three.iter().all(|&msg| msg == last_three[0]) {
            return Err(IronError::RateLimit(
                "Repeated message spam detected".to_string()
            ));
        }
    }

    Ok(())
}

/// Validate IRC mode string
pub fn validate_mode_string(mode_string: &str) -> Result<()> {
    if mode_string.is_empty() {
        return Ok(());
    }

    let mut chars = mode_string.chars();
    
    // First character should be + or -
    match chars.next() {
        Some('+') | Some('-') => {},
        _ => return Err(IronError::InvalidInput(
            "Mode string must start with + or -".to_string()
        )),
    }

    // Remaining characters should be valid mode letters
    for c in chars {
        if !c.is_ascii_alphabetic() {
            return Err(IronError::InvalidInput(
                format!("Invalid mode character: {}", c)
            ));
        }
    }

    Ok(())
}

/// Sanitize user input to prevent injection attacks
pub fn sanitize_user_input(input: &str) -> String {
    input
        .replace('\0', "")        // Remove null bytes
        .replace('\r', "")        // Remove carriage returns
        .replace('\n', " ")       // Replace newlines with spaces
        .replace('\t', " ")       // Replace tabs with spaces
        .chars()
        .filter(|c| !c.is_control() || *c == ' ') // Remove other control characters
        .take(MAX_MESSAGE_LENGTH) // Truncate to max length
        .collect()
}

/// Check if a string contains potentially dangerous content
pub fn contains_dangerous_content(content: &str) -> bool {
    // Check for common IRC injection patterns
    let dangerous_patterns = [
        "\r\n",           // IRC line breaks
        "\x01",           // CTCP delimiter
        "PRIVMSG",        // Command injection attempts
        "NOTICE",
        "JOIN",
        "PART",
        "QUIT",
        "KICK",
        "MODE",
    ];

    for pattern in &dangerous_patterns {
        if content.to_uppercase().contains(&pattern.to_uppercase()) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nickname_validation() {
        assert!(validate_nickname("Alice").is_ok());
        assert!(validate_nickname("Bot123").is_ok());
        assert!(validate_nickname("[Server]").is_ok());
        
        assert!(validate_nickname("").is_err());
        assert!(validate_nickname("123user").is_err()); // Can't start with number
        assert!(validate_nickname("user name").is_err()); // No spaces
    }

    #[test]
    fn test_channel_validation() {
        assert!(validate_channel_name("#general").is_ok());
        assert!(validate_channel_name("&local").is_ok());
        
        assert!(validate_channel_name("general").is_err()); // Must start with # or &
        assert!(validate_channel_name("#test channel").is_err()); // No spaces
    }

    #[test]
    fn test_message_content_validation() {
        assert!(validate_message_content("Hello world").is_ok());
        
        assert!(validate_message_content("Bad\0message").is_err()); // Null byte
        assert!(validate_message_content(&"x".repeat(600)).is_err()); // Too long
    }

    #[test]
    fn test_hostname_validation() {
        assert!(validate_hostname("irc.example.com").is_ok());
        assert!(validate_hostname("server1.chat").is_ok());
        
        assert!(validate_hostname("").is_err()); // Empty
        assert!(validate_hostname("-invalid.com").is_err()); // Starts with hyphen
        assert!(validate_hostname("bad_host").is_err()); // Invalid character
    }

    #[test]
    fn test_user_info_validation() {
        assert!(validate_user_info("alice", "Alice Smith").is_ok());
        
        assert!(validate_user_info("", "Real Name").is_err()); // Empty username
        assert!(validate_user_info("user@host", "Name").is_err()); // Invalid char
        assert!(validate_user_info("user", "Bad\0name").is_err()); // Null in realname
    }

    #[test]
    fn test_ctcp_validation() {
        assert!(validate_ctcp_message("\x01VERSION\x01").is_ok());
        assert!(validate_ctcp_message("\x01ACTION waves\x01").is_ok());
        
        assert!(validate_ctcp_message("VERSION").is_err()); // Missing delimiters
        assert!(validate_ctcp_message("\x01BAD\x01MESSAGE\x01").is_err()); // Nested delimiters
    }

    #[test]
    fn test_mode_string_validation() {
        assert!(validate_mode_string("+nt").is_ok());
        assert!(validate_mode_string("-i").is_ok());
        assert!(validate_mode_string("").is_ok()); // Empty is OK
        
        assert!(validate_mode_string("nt").is_err()); // Missing +/-
        assert!(validate_mode_string("+n2t").is_err()); // Invalid character
    }

    #[test]
    fn test_sanitize_user_input() {
        assert_eq!(sanitize_user_input("Hello\0world\r\n"), "Helloworld ");
        assert_eq!(sanitize_user_input("Normal text"), "Normal text");
        
        let long_input = "x".repeat(1000);
        let sanitized = sanitize_user_input(&long_input);
        assert!(sanitized.len() <= MAX_MESSAGE_LENGTH);
    }

    #[test]
    fn test_dangerous_content_detection() {
        assert!(contains_dangerous_content("PRIVMSG #test :hello"));
        assert!(contains_dangerous_content("Some\r\nmessage"));
        assert!(contains_dangerous_content("\x01ACTION test\x01"));
        
        assert!(!contains_dangerous_content("Normal message"));
        assert!(!contains_dangerous_content("Hello world"));
    }
}