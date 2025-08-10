//! IRC command parsing and representation
//!
//! This module provides types and functionality for working with IRC commands,
//! including both standard IRC commands and IRCv3 extensions.

// use std::str::FromStr; // Not currently used

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Represents various IRC commands with their parameters
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Command {
    // Connection registration
    /// NICK command - set nickname
    Nick(String),
    /// USER command - user registration
    User { username: String, realname: String },
    /// PASS command - connection password
    Pass(String),
    /// QUIT command - disconnect
    Quit(Option<String>),
    /// PING command - server ping
    Ping(String),
    /// PONG command - ping response
    Pong(String),
    
    // Channel operations
    /// JOIN command - join channels
    Join(Vec<String>, Vec<String>), // channels, keys
    /// PART command - leave channels
    Part(Vec<String>, Option<String>), // channels, message
    /// TOPIC command - get/set channel topic
    Topic { channel: String, topic: Option<String> },
    /// NAMES command - list channel members
    Names(Vec<String>),
    /// LIST command - list channels
    List(Option<Vec<String>>),
    
    // Messaging
    /// PRIVMSG command - send message
    Privmsg { target: String, message: String },
    /// NOTICE command - send notice
    Notice { target: String, message: String },
    
    // User queries
    /// WHO command - query user information
    Who(Option<String>),
    /// WHOIS command - detailed user information
    Whois(Vec<String>),
    /// WHOWAS command - historical user information
    Whowas(String, Option<i32>),
    /// QUERY command - open private message window
    Query(String),
    
    // Channel management
    /// KICK command - remove user from channel
    Kick { channel: String, user: String, reason: Option<String> },
    /// MODE command - change modes
    Mode { target: String, modes: Option<String>, params: Vec<String> },
    /// INVITE command - invite user to channel
    Invite { nick: String, channel: String },
    
    // Server queries
    /// MOTD command - message of the day
    Motd(Option<String>),
    /// VERSION command - server version
    Version(Option<String>),
    /// STATS command - server statistics
    Stats(Option<String>, Option<String>),
    /// TIME command - server time
    Time(Option<String>),
    /// INFO command - server information
    Info(Option<String>),
    
    // IRCv3 commands
    /// CAP command - capability negotiation
    Cap { subcommand: String, params: Vec<String> },
    /// AUTHENTICATE command - SASL authentication
    Authenticate(String),
    /// ACCOUNT command - account notification
    Account(String),
    /// MONITOR command - nickname monitoring
    Monitor { subcommand: String, targets: Vec<String> },
    /// METADATA command - user metadata
    Metadata { target: String, subcommand: String, params: Vec<String> },
    /// TAGMSG command - tag-only message
    TagMsg { target: String },
    /// BATCH command - message batching
    Batch { reference: String, batch_type: Option<String>, params: Vec<String> },
    
    // 2024 Bleeding-edge IRCv3 commands
    /// REDACT command - message redaction
    Redact { target: String, msgid: String, reason: Option<String> },
    /// MARKREAD command - mark messages as read
    MarkRead { target: String, timestamp: Option<String> },
    /// SETNAME command - change real name
    SetName { realname: String },
    /// CHATHISTORY command - request chat history
    ChatHistory { subcommand: String, target: String, params: Vec<String> },
    
    // Operator commands
    /// OPER command - gain operator privileges
    Oper { name: String, password: String },
    /// KILL command - forcibly disconnect user
    Kill { nick: String, reason: String },
    /// REHASH command - reload server configuration
    Rehash,
    /// RESTART command - restart server
    Restart,
    /// DIE command - shutdown server
    Die,
    
    // CTCP commands
    /// CTCP request
    CtcpRequest { target: String, command: String, params: String },
    /// CTCP response
    CtcpResponse { target: String, command: String, params: String },
    
    // Fallback for unknown commands
    /// Unknown command
    Unknown(String, Vec<String>),
}

impl Command {
    /// Parse a command from its string representation and parameters
    pub fn parse(command: &str, params: Vec<String>) -> Self {
        match command.to_uppercase().as_str() {
            "NICK" => {
                if let Some(nick) = params.first() {
                    Command::Nick(nick.clone())
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            "USER" => {
                if params.len() >= 4 {
                    Command::User {
                        username: params[0].clone(),
                        realname: params[3].clone(),
                    }
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            "PASS" => {
                if let Some(pass) = params.first() {
                    Command::Pass(pass.clone())
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            "QUIT" => Command::Quit(params.first().cloned()),
            "PING" => {
                if let Some(token) = params.first() {
                    Command::Ping(token.clone())
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            "PONG" => {
                if let Some(token) = params.first() {
                    Command::Pong(token.clone())
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            "JOIN" => {
                if let Some(channels) = params.first() {
                    let channels: Vec<String> = channels.split(',').map(|s| s.to_string()).collect();
                    let keys: Vec<String> = params.get(1)
                        .map(|k| k.split(',').map(|s| s.to_string()).collect())
                        .unwrap_or_default();
                    Command::Join(channels, keys)
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            "PART" => {
                if let Some(channels) = params.first() {
                    let channels: Vec<String> = channels.split(',').map(|s| s.to_string()).collect();
                    let message = params.get(1).cloned();
                    Command::Part(channels, message)
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            "TOPIC" => {
                if let Some(channel) = params.first() {
                    Command::Topic {
                        channel: channel.clone(),
                        topic: params.get(1).cloned(),
                    }
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            "NAMES" => {
                if let Some(channels) = params.first() {
                    let channels: Vec<String> = channels.split(',').map(|s| s.to_string()).collect();
                    Command::Names(channels)
                } else {
                    Command::Names(Vec::new())
                }
            }
            "LIST" => {
                if let Some(channels) = params.first() {
                    let channels: Vec<String> = channels.split(',').map(|s| s.to_string()).collect();
                    Command::List(Some(channels))
                } else {
                    Command::List(None)
                }
            }
            "PRIVMSG" => {
                if params.len() >= 2 {
                    Command::Privmsg {
                        target: params[0].clone(),
                        message: params[1].clone(),
                    }
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            "NOTICE" => {
                if params.len() >= 2 {
                    Command::Notice {
                        target: params[0].clone(),
                        message: params[1].clone(),
                    }
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            "WHO" => Command::Who(params.first().cloned()),
            "WHOIS" => {
                if !params.is_empty() {
                    Command::Whois(params)
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            "WHOWAS" => {
                if let Some(nick) = params.first() {
                    let count = params.get(1).and_then(|s| s.parse().ok());
                    Command::Whowas(nick.clone(), count)
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            "QUERY" => {
                if let Some(target) = params.first() {
                    Command::Query(target.clone())
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            "KICK" => {
                if params.len() >= 2 {
                    Command::Kick {
                        channel: params[0].clone(),
                        user: params[1].clone(),
                        reason: params.get(2).cloned(),
                    }
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            "MODE" => {
                if let Some(target) = params.first() {
                    Command::Mode {
                        target: target.clone(),
                        modes: params.get(1).cloned(),
                        params: params[2..].to_vec(),
                    }
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            "INVITE" => {
                if params.len() >= 2 {
                    Command::Invite {
                        nick: params[0].clone(),
                        channel: params[1].clone(),
                    }
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            "MOTD" => Command::Motd(params.first().cloned()),
            "VERSION" => Command::Version(params.first().cloned()),
            "STATS" => Command::Stats(params.first().cloned(), params.get(1).cloned()),
            "TIME" => Command::Time(params.first().cloned()),
            "INFO" => Command::Info(params.first().cloned()),
            
            // IRCv3 commands
            "CAP" => {
                if let Some(subcommand) = params.first() {
                    Command::Cap {
                        subcommand: subcommand.clone(),
                        params: params[1..].to_vec(),
                    }
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            "AUTHENTICATE" => {
                if let Some(data) = params.first() {
                    Command::Authenticate(data.clone())
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            "ACCOUNT" => {
                if let Some(account) = params.first() {
                    Command::Account(account.clone())
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            "MONITOR" => {
                if let Some(subcommand) = params.first() {
                    Command::Monitor {
                        subcommand: subcommand.clone(),
                        targets: params[1..].to_vec(),
                    }
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            "METADATA" => {
                if params.len() >= 2 {
                    Command::Metadata {
                        target: params[0].clone(),
                        subcommand: params[1].clone(),
                        params: params[2..].to_vec(),
                    }
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            "TAGMSG" => {
                if let Some(target) = params.first() {
                    Command::TagMsg {
                        target: target.clone(),
                    }
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            "BATCH" => {
                if let Some(reference) = params.first() {
                    Command::Batch {
                        reference: reference.clone(),
                        batch_type: params.get(1).cloned(),
                        params: params[2..].to_vec(),
                    }
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            
            // 2024 Bleeding-edge IRCv3 commands
            "REDACT" => {
                if params.len() >= 2 {
                    Command::Redact {
                        target: params[0].clone(),
                        msgid: params[1].clone(),
                        reason: params.get(2).cloned(),
                    }
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            "MARKREAD" => {
                if !params.is_empty() {
                    Command::MarkRead {
                        target: params[0].clone(),
                        timestamp: params.get(1).cloned(),
                    }
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            "SETNAME" => {
                if let Some(realname) = params.first() {
                    Command::SetName {
                        realname: realname.clone(),
                    }
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            "CHATHISTORY" => {
                if params.len() >= 2 {
                    Command::ChatHistory {
                        subcommand: params[0].clone(),
                        target: params[1].clone(),
                        params: params[2..].to_vec(),
                    }
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            
            // Operator commands
            "OPER" => {
                if params.len() >= 2 {
                    Command::Oper {
                        name: params[0].clone(),
                        password: params[1].clone(),
                    }
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            "KILL" => {
                if params.len() >= 2 {
                    Command::Kill {
                        nick: params[0].clone(),
                        reason: params[1].clone(),
                    }
                } else {
                    Command::Unknown(command.to_string(), params)
                }
            }
            "REHASH" => Command::Rehash,
            "RESTART" => Command::Restart,
            "DIE" => Command::Die,
            
            _ => Command::Unknown(command.to_string(), params),
        }
    }

    /// Get the command name as a string
    pub fn command_name(&self) -> &str {
        match self {
            Command::Nick(_) => "NICK",
            Command::User { .. } => "USER",
            Command::Pass(_) => "PASS",
            Command::Quit(_) => "QUIT",
            Command::Ping(_) => "PING",
            Command::Pong(_) => "PONG",
            Command::Join(_, _) => "JOIN",
            Command::Part(_, _) => "PART",
            Command::Topic { .. } => "TOPIC",
            Command::Names(_) => "NAMES",
            Command::List(_) => "LIST",
            Command::Privmsg { .. } => "PRIVMSG",
            Command::Notice { .. } => "NOTICE",
            Command::Who(_) => "WHO",
            Command::Whois(_) => "WHOIS",
            Command::Whowas(_, _) => "WHOWAS",
            Command::Query(_) => "QUERY",
            Command::Kick { .. } => "KICK",
            Command::Mode { .. } => "MODE",
            Command::Invite { .. } => "INVITE",
            Command::Motd(_) => "MOTD",
            Command::Version(_) => "VERSION",
            Command::Stats(_, _) => "STATS",
            Command::Time(_) => "TIME",
            Command::Info(_) => "INFO",
            Command::Cap { .. } => "CAP",
            Command::Authenticate(_) => "AUTHENTICATE",
            Command::Account(_) => "ACCOUNT",
            Command::Monitor { .. } => "MONITOR",
            Command::Metadata { .. } => "METADATA",
            Command::TagMsg { .. } => "TAGMSG",
            Command::Batch { .. } => "BATCH",
            Command::Redact { .. } => "REDACT",
            Command::MarkRead { .. } => "MARKREAD",
            Command::SetName { .. } => "SETNAME",
            Command::ChatHistory { .. } => "CHATHISTORY",
            Command::Oper { .. } => "OPER",
            Command::Kill { .. } => "KILL",
            Command::Rehash => "REHASH",
            Command::Restart => "RESTART",
            Command::Die => "DIE",
            Command::CtcpRequest { .. } => "PRIVMSG", // CTCP is sent via PRIVMSG
            Command::CtcpResponse { .. } => "NOTICE", // CTCP response via NOTICE
            Command::Unknown(cmd, _) => cmd,
        }
    }

    /// Check if this is a channel-related command
    pub fn is_channel_command(&self) -> bool {
        match self {
            Command::Join(_, _) |
            Command::Part(_, _) |
            Command::Topic { .. } |
            Command::Names(_) |
            Command::Kick { .. } => true,
            Command::Mode { target, .. } => target.starts_with('#') || target.starts_with('&'),
            _ => false,
        }
    }

    /// Check if this is a messaging command
    pub fn is_message_command(&self) -> bool {
        matches!(self, Command::Privmsg { .. } | Command::Notice { .. })
    }

    /// Check if this is an IRCv3 command
    pub fn is_ircv3_command(&self) -> bool {
        matches!(self,
            Command::Cap { .. } |
            Command::Authenticate(_) |
            Command::Account(_) |
            Command::Monitor { .. } |
            Command::Metadata { .. } |
            Command::TagMsg { .. } |
            Command::Batch { .. } |
            Command::Redact { .. } |
            Command::MarkRead { .. } |
            Command::SetName { .. } |
            Command::ChatHistory { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_command_parsing() {
        let cmd = Command::parse("PRIVMSG", vec!["#channel".to_string(), "Hello world".to_string()]);
        match cmd {
            Command::Privmsg { target, message } => {
                assert_eq!(target, "#channel");
                assert_eq!(message, "Hello world");
            }
            _ => panic!("Expected Privmsg command"),
        }
    }

    #[test]
    fn test_join_command_parsing() {
        let cmd = Command::parse("JOIN", vec!["#chan1,#chan2".to_string(), "key1,key2".to_string()]);
        match cmd {
            Command::Join(channels, keys) => {
                assert_eq!(channels, vec!["#chan1", "#chan2"]);
                assert_eq!(keys, vec!["key1", "key2"]);
            }
            _ => panic!("Expected Join command"),
        }
    }

    #[test]
    fn test_cap_command_parsing() {
        let cmd = Command::parse("CAP", vec!["LS".to_string(), "302".to_string()]);
        match cmd {
            Command::Cap { subcommand, params } => {
                assert_eq!(subcommand, "LS");
                assert_eq!(params, vec!["302"]);
            }
            _ => panic!("Expected Cap command"),
        }
    }

    #[test]
    fn test_command_name() {
        let cmd = Command::Privmsg { target: "#test".to_string(), message: "hello".to_string() };
        assert_eq!(cmd.command_name(), "PRIVMSG");
    }

    #[test]
    fn test_command_categories() {
        let privmsg = Command::Privmsg { target: "#test".to_string(), message: "hello".to_string() };
        let join = Command::Join(vec!["#test".to_string()], vec![]);
        let cap = Command::Cap { subcommand: "LS".to_string(), params: vec![] };

        assert!(privmsg.is_message_command());
        assert!(join.is_channel_command());
        assert!(cap.is_ircv3_command());
    }

    #[test]
    fn test_unknown_command() {
        let cmd = Command::parse("UNKNOWN", vec!["param1".to_string()]);
        match cmd {
            Command::Unknown(name, params) => {
                assert_eq!(name, "UNKNOWN");
                assert_eq!(params, vec!["param1"]);
            }
            _ => panic!("Expected Unknown command"),
        }
    }
}