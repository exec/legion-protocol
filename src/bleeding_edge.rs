//! Bleeding-edge IRCv3 features (2024-2025 specifications)
//!
//! This module contains implementations of the latest IRCv3 draft specifications
//! and experimental features that are still in development.

use crate::error::{IronError, Result};
use crate::message::IrcMessage;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Message redaction request
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RedactionRequest {
    pub target: String,
    pub msgid: String,
    pub reason: Option<String>,
    pub redactor: String,
}

impl RedactionRequest {
    /// Create a new redaction request
    pub fn new(target: String, msgid: String, reason: Option<String>, redactor: String) -> Self {
        Self { target, msgid, reason, redactor }
    }

    /// Convert to IRC message
    pub fn to_message(&self) -> IrcMessage {
        let mut params = vec![self.target.clone(), self.msgid.clone()];
        if let Some(reason) = &self.reason {
            params.push(reason.clone());
        }

        IrcMessage::new("REDACT")
            .with_params(params)
            .with_tag("redactor", Some(self.redactor.clone()))
    }

    /// Parse from IRC message
    pub fn from_message(msg: &IrcMessage) -> Result<Self> {
        if msg.command != "REDACT" || msg.params.len() < 2 {
            return Err(IronError::Parse("Invalid REDACT message".to_string()));
        }

        let redactor = msg.get_tag("redactor")
            .and_then(|v| v.as_ref())
            .map(|s| s.clone())
            .unwrap_or_else(|| "unknown".to_string());

        Ok(Self {
            target: msg.params[0].clone(),
            msgid: msg.params[1].clone(),
            reason: msg.params.get(2).cloned(),
            redactor,
        })
    }
}

/// Read marker for tracking message read status
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ReadMarker {
    pub target: String,
    pub timestamp: Option<String>,
    pub msgid: Option<String>,
}

impl ReadMarker {
    /// Create a new read marker
    pub fn new(target: String, timestamp: Option<String>, msgid: Option<String>) -> Self {
        Self { target, timestamp, msgid }
    }

    /// Convert to IRC message
    pub fn to_message(&self) -> IrcMessage {
        let mut params = vec![self.target.clone()];
        if let Some(timestamp) = &self.timestamp {
            params.push(timestamp.clone());
        }

        let mut msg = IrcMessage::new("MARKREAD").with_params(params);
        
        if let Some(msgid) = &self.msgid {
            msg = msg.with_tag("msgid", Some(msgid.clone()));
        }

        msg
    }

    /// Parse from IRC message
    pub fn from_message(msg: &IrcMessage) -> Result<Self> {
        if msg.command != "MARKREAD" || msg.params.is_empty() {
            return Err(IronError::Parse("Invalid MARKREAD message".to_string()));
        }

        let msgid = msg.get_tag("msgid")
            .and_then(|v| v.as_ref())
            .cloned();

        Ok(Self {
            target: msg.params[0].clone(),
            timestamp: msg.params.get(1).cloned(),
            msgid,
        })
    }
}

/// Typing indicator
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TypingIndicator {
    pub target: String,
    pub state: TypingState,
    pub duration: Option<u32>, // seconds
}

/// Typing states
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TypingState {
    Active,
    Paused,
    Done,
}

impl TypingState {
    pub fn as_str(&self) -> &str {
        match self {
            TypingState::Active => "active",
            TypingState::Paused => "paused",
            TypingState::Done => "done",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "active" => Some(TypingState::Active),
            "paused" => Some(TypingState::Paused),
            "done" => Some(TypingState::Done),
            _ => None,
        }
    }
}

impl TypingIndicator {
    /// Create a new typing indicator
    pub fn new(target: String, state: TypingState, duration: Option<u32>) -> Self {
        Self { target, state, duration }
    }

    /// Convert to IRC message (TAGMSG with typing tag)
    pub fn to_message(&self) -> IrcMessage {
        let mut msg = IrcMessage::new("TAGMSG")
            .with_params(vec![self.target.clone()])
            .with_tag("+typing", Some(self.state.as_str().to_string()));

        if let Some(duration) = self.duration {
            msg = msg.with_tag("+typing-duration", Some(duration.to_string()));
        }

        msg
    }

    /// Parse from IRC message
    pub fn from_message(msg: &IrcMessage) -> Result<Self> {
        if msg.command != "TAGMSG" || msg.params.is_empty() {
            return Err(IronError::Parse("Invalid typing indicator message".to_string()));
        }

        let typing_tag = msg.get_tag("+typing")
            .and_then(|v| v.as_ref())
            .ok_or_else(|| IronError::Parse("Missing +typing tag".to_string()))?;

        let state = TypingState::from_str(typing_tag)
            .ok_or_else(|| IronError::Parse("Invalid typing state".to_string()))?;

        let duration = msg.get_tag("+typing-duration")
            .and_then(|v| v.as_ref())
            .and_then(|s| s.parse().ok());

        Ok(Self {
            target: msg.params[0].clone(),
            state,
            duration,
        })
    }
}

/// Multiline message
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MultilineMessage {
    pub target: String,
    pub lines: Vec<String>,
    pub concat_tag: Option<String>,
}

impl MultilineMessage {
    /// Create a new multiline message
    pub fn new(target: String, lines: Vec<String>) -> Self {
        Self {
            target,
            lines,
            concat_tag: None,
        }
    }

    /// Convert to batch of IRC messages
    pub fn to_messages(&self, batch_id: &str) -> Vec<IrcMessage> {
        let mut messages = Vec::new();

        // Start batch
        let batch_start = IrcMessage::new("BATCH")
            .with_params(vec![
                format!("+{}", batch_id),
                "draft/multiline".to_string(),
                self.target.clone()
            ]);
        messages.push(batch_start);

        // Add individual lines
        for (_i, line) in self.lines.iter().enumerate() {
            let mut msg = IrcMessage::new("PRIVMSG")
                .with_params(vec![self.target.clone(), line.clone()])
                .with_tag("batch", Some(batch_id.to_string()));

            if let Some(concat_tag) = &self.concat_tag {
                msg = msg.with_tag("draft/multiline-concat", Some(concat_tag.clone()));
            }

            messages.push(msg);
        }

        // End batch
        let batch_end = IrcMessage::new("BATCH")
            .with_params(vec![format!("-{}", batch_id)]);
        messages.push(batch_end);

        messages
    }
}

/// Chat history request
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ChatHistoryRequest {
    pub subcommand: String,
    pub target: String,
    pub timestamp: Option<String>,
    pub limit: Option<u32>,
}

impl ChatHistoryRequest {
    /// Create a new chat history request
    pub fn new(subcommand: String, target: String, timestamp: Option<String>, limit: Option<u32>) -> Self {
        Self { subcommand, target, timestamp, limit }
    }

    /// Create a request for latest messages
    pub fn latest(target: String, limit: u32) -> Self {
        Self::new("LATEST".to_string(), target, None, Some(limit))
    }

    /// Create a request for messages before a timestamp
    pub fn before(target: String, timestamp: String, limit: u32) -> Self {
        Self::new("BEFORE".to_string(), target, Some(timestamp), Some(limit))
    }

    /// Create a request for messages after a timestamp
    pub fn after(target: String, timestamp: String, limit: u32) -> Self {
        Self::new("AFTER".to_string(), target, Some(timestamp), Some(limit))
    }

    /// Convert to IRC message
    pub fn to_message(&self) -> IrcMessage {
        let mut params = vec![self.subcommand.clone(), self.target.clone()];
        
        if let Some(timestamp) = &self.timestamp {
            params.push(timestamp.clone());
        }
        
        if let Some(limit) = self.limit {
            params.push(limit.to_string());
        }

        IrcMessage::new("CHATHISTORY").with_params(params)
    }

    /// Parse from IRC message
    pub fn from_message(msg: &IrcMessage) -> Result<Self> {
        if msg.command != "CHATHISTORY" || msg.params.len() < 2 {
            return Err(IronError::Parse("Invalid CHATHISTORY message".to_string()));
        }

        let timestamp = msg.params.get(2).cloned();
        let limit = msg.params.get(3).and_then(|s| s.parse().ok());

        Ok(Self {
            subcommand: msg.params[0].clone(),
            target: msg.params[1].clone(),
            timestamp,
            limit,
        })
    }
}

/// Reaction to a message
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MessageReaction {
    pub target: String,
    pub msgid: String,
    pub reaction: String,
    pub action: ReactionAction,
}

/// Reaction actions
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ReactionAction {
    Add,
    Remove,
}

impl ReactionAction {
    pub fn as_str(&self) -> &str {
        match self {
            ReactionAction::Add => "+",
            ReactionAction::Remove => "-",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "+" => Some(ReactionAction::Add),
            "-" => Some(ReactionAction::Remove),
            _ => None,
        }
    }
}

/// Reply to a message
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MessageReply {
    pub target: String,
    pub msgid: String,
    pub reply_text: String,
}

impl MessageReply {
    /// Create a new message reply
    pub fn new(target: String, msgid: String, reply_text: String) -> Self {
        Self { target, msgid, reply_text }
    }

    /// Convert to IRC message (PRIVMSG with reply tag)
    pub fn to_message(&self) -> IrcMessage {
        IrcMessage::new("PRIVMSG")
            .with_params(vec![self.target.clone(), self.reply_text.clone()])
            .with_tag("+draft/reply", Some(self.msgid.clone()))
    }

    /// Parse from IRC message
    pub fn from_message(msg: &IrcMessage) -> Result<Self> {
        if msg.command != "PRIVMSG" || msg.params.len() < 2 {
            return Err(IronError::Parse("Invalid reply message".to_string()));
        }

        let msgid = msg.get_tag("+draft/reply")
            .and_then(|v| v.as_ref())
            .ok_or_else(|| IronError::Parse("Missing +draft/reply tag".to_string()))?;

        Ok(Self {
            target: msg.params[0].clone(),
            msgid: msgid.clone(),
            reply_text: msg.params[1].clone(),
        })
    }
}

impl MessageReaction {
    /// Create a new message reaction
    pub fn new(target: String, msgid: String, reaction: String, action: ReactionAction) -> Self {
        Self { target, msgid, reaction, action }
    }

    /// Convert to IRC message (TAGMSG with reaction tag)
    pub fn to_message(&self) -> IrcMessage {
        let reaction_value = format!("{}{}", self.action.as_str(), self.reaction);
        
        IrcMessage::new("TAGMSG")
            .with_params(vec![self.target.clone()])
            .with_tag("+draft/react", Some(reaction_value))
            .with_tag("+draft/reply", Some(self.msgid.clone()))
    }

    /// Parse from IRC message
    pub fn from_message(msg: &IrcMessage) -> Result<Self> {
        if msg.command != "TAGMSG" || msg.params.is_empty() {
            return Err(IronError::Parse("Invalid reaction message".to_string()));
        }

        let react_tag = msg.get_tag("+draft/react")
            .and_then(|v| v.as_ref())
            .ok_or_else(|| IronError::Parse("Missing +draft/react tag".to_string()))?;

        let msgid = msg.get_tag("+draft/reply")
            .and_then(|v| v.as_ref())
            .ok_or_else(|| IronError::Parse("Missing +draft/reply tag".to_string()))?;

        if react_tag.is_empty() {
            return Err(IronError::Parse("Empty reaction tag".to_string()));
        }

        let (action, reaction) = match react_tag.chars().next().unwrap() {
            '+' => (ReactionAction::Add, &react_tag[1..]),
            '-' => (ReactionAction::Remove, &react_tag[1..]),
            _ => return Err(IronError::Parse("Invalid reaction action".to_string())),
        };

        Ok(Self {
            target: msg.params[0].clone(),
            msgid: msgid.clone(),
            reaction: reaction.to_string(),
            action,
        })
    }
}

/// Generate a unique batch ID
pub fn generate_batch_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("batch_{:x}", rng.r#gen::<u64>())
}

/// Validate a msgid format
pub fn validate_msgid(msgid: &str) -> Result<()> {
    if msgid.is_empty() {
        return Err(IronError::InvalidInput("Message ID cannot be empty".to_string()));
    }

    if msgid.len() > 64 {
        return Err(IronError::InvalidInput("Message ID too long".to_string()));
    }

    // Only allow alphanumeric, hyphens, and underscores
    if !msgid.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(IronError::InvalidInput("Invalid characters in message ID".to_string()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redaction_request() {
        let redaction = RedactionRequest::new(
            "#channel".to_string(),
            "msg123".to_string(),
            Some("spam".to_string()),
            "moderator".to_string()
        );

        let msg = redaction.to_message();
        assert_eq!(msg.command, "REDACT");
        assert_eq!(msg.params, vec!["#channel", "msg123", "spam"]);
        assert_eq!(msg.get_tag("redactor"), Some(&Some("moderator".to_string())));

        let parsed = RedactionRequest::from_message(&msg).unwrap();
        assert_eq!(parsed, redaction);
    }

    #[test]
    fn test_typing_indicator() {
        let typing = TypingIndicator::new(
            "#channel".to_string(),
            TypingState::Active,
            Some(30)
        );

        let msg = typing.to_message();
        assert_eq!(msg.command, "TAGMSG");
        assert_eq!(msg.params, vec!["#channel"]);
        assert_eq!(msg.get_tag("+typing"), Some(&Some("active".to_string())));
        assert_eq!(msg.get_tag("+typing-duration"), Some(&Some("30".to_string())));

        let parsed = TypingIndicator::from_message(&msg).unwrap();
        assert_eq!(parsed, typing);
    }

    #[test]
    fn test_chat_history_request() {
        let request = ChatHistoryRequest::latest("#channel".to_string(), 50);

        let msg = request.to_message();
        assert_eq!(msg.command, "CHATHISTORY");
        assert_eq!(msg.params, vec!["LATEST", "#channel", "50"]);

        let parsed = ChatHistoryRequest::from_message(&msg).unwrap();
        assert_eq!(parsed.subcommand, "LATEST");
        assert_eq!(parsed.target, "#channel");
        assert_eq!(parsed.limit, Some(50));
    }

    #[test]
    fn test_message_reply() {
        let reply = MessageReply::new(
            "#channel".to_string(),
            "msg123".to_string(),
            "This is a reply!".to_string()
        );

        let msg = reply.to_message();
        assert_eq!(msg.command, "PRIVMSG");
        assert_eq!(msg.params[0], "#channel");
        assert_eq!(msg.params[1], "This is a reply!");
        assert_eq!(msg.get_tag("+draft/reply"), Some(&Some("msg123".to_string())));

        let parsed = MessageReply::from_message(&msg).unwrap();
        assert_eq!(parsed, reply);
    }

    #[test]
    fn test_message_reaction() {
        let reaction = MessageReaction::new(
            "#channel".to_string(),
            "msg123".to_string(),
            "👍".to_string(),
            ReactionAction::Add
        );

        let msg = reaction.to_message();
        assert_eq!(msg.command, "TAGMSG");
        assert_eq!(msg.get_tag("+draft/react"), Some(&Some("+👍".to_string())));
        assert_eq!(msg.get_tag("+draft/reply"), Some(&Some("msg123".to_string())));

        let parsed = MessageReaction::from_message(&msg).unwrap();
        assert_eq!(parsed, reaction);
    }

    #[test]
    fn test_multiline_message() {
        let multiline = MultilineMessage::new(
            "#channel".to_string(),
            vec!["Line 1".to_string(), "Line 2".to_string(), "Line 3".to_string()]
        );

        let messages = multiline.to_messages("test123");
        assert_eq!(messages.len(), 5); // start batch + 3 lines + end batch

        // Check batch start
        assert_eq!(messages[0].command, "BATCH");
        assert_eq!(messages[0].params[0], "+test123");
        assert_eq!(messages[0].params[1], "draft/multiline");

        // Check first line
        assert_eq!(messages[1].command, "PRIVMSG");
        assert_eq!(messages[1].params[1], "Line 1");
        assert_eq!(messages[1].get_tag("batch"), Some(&Some("test123".to_string())));

        // Check batch end
        assert_eq!(messages[4].command, "BATCH");
        assert_eq!(messages[4].params[0], "-test123");
    }

    #[test]
    fn test_msgid_validation() {
        assert!(validate_msgid("msg123").is_ok());
        assert!(validate_msgid("msg_test-456").is_ok());
        
        assert!(validate_msgid("").is_err());
        assert!(validate_msgid(&"x".repeat(100)).is_err());
        assert!(validate_msgid("msg@123").is_err());
    }

    #[test]
    fn test_batch_id_generation() {
        let id1 = generate_batch_id();
        let id2 = generate_batch_id();
        
        assert_ne!(id1, id2);
        assert!(id1.starts_with("batch_"));
        assert!(id2.starts_with("batch_"));
    }
}