//! IRC numeric replies and error codes
//!
//! This module contains the standard IRC numeric reply codes and error messages
//! as defined in RFC 1459, RFC 2812, and various IRCv3 specifications.

use crate::message::IrcMessage;

/// IRC numeric replies and error codes
#[derive(Debug, Clone)]
pub enum Reply {
    // Welcome sequence (001-005)
    /// 001 RPL_WELCOME
    Welcome { nick: String, network: String },
    /// 002 RPL_YOURHOST
    YourHost { nick: String, servername: String, version: String },
    /// 003 RPL_CREATED
    Created { nick: String, date: String },
    /// 004 RPL_MYINFO
    MyInfo { nick: String, servername: String, version: String, usermodes: String, chanmodes: String },
    /// 005 RPL_ISUPPORT
    ISupport { nick: String, tokens: Vec<String> },
    
    // Channel operations (331-366)
    /// 331 RPL_NOTOPIC
    NoTopic { nick: String, channel: String },
    /// 332 RPL_TOPIC
    Topic { nick: String, channel: String, topic: String },
    /// 353 RPL_NAMREPLY
    NamReply { nick: String, symbol: char, channel: String, names: Vec<String> },
    /// 366 RPL_ENDOFNAMES
    EndOfNames { nick: String, channel: String },
    
    // MOTD (372-376, 422)
    /// 375 RPL_MOTDSTART
    MotdStart { nick: String, server: String },
    /// 372 RPL_MOTD
    Motd { nick: String, line: String },
    /// 376 RPL_ENDOFMOTD
    EndOfMotd { nick: String },
    /// 422 ERR_NOMOTD
    NoMotd { nick: String },
    
    // Error replies (400-599)
    /// 401 ERR_NOSUCHNICK
    NoSuchNick { nick: String, target: String },
    /// 403 ERR_NOSUCHCHANNEL
    NoSuchChannel { nick: String, channel: String },
    /// 404 ERR_CANNOTSENDTOCHAN
    CannotSendToChan { nick: String, channel: String },
    /// 442 ERR_NOTONCHANNEL
    NotOnChannel { nick: String, channel: String },
    /// 433 ERR_NICKNAMEINUSE
    NicknameInUse { nick: String, attempted: String },
    /// 461 ERR_NEEDMOREPARAMS
    NeedMoreParams { nick: String, command: String },
    /// 462 ERR_ALREADYREGISTERED
    AlreadyRegistered { nick: String },
    /// 421 ERR_UNKNOWNCOMMAND
    UnknownCommand { nick: String, command: String },
    /// 464 ERR_PASSWDMISMATCH
    PasswdMismatch { nick: String },
    /// 451 ERR_NOTREGISTERED
    NotRegistered { nick: String },
    
    // Additional replies for compatibility
    /// 432 ERR_ERRONEUSNICKNAME
    ErroneousNickname { nick: String, attempted: String },
    /// 475 ERR_BADCHANNELKEY
    BadChannelKey { nick: String, channel: String },
    /// 471 ERR_CHANNELISFULL
    ChannelIsFull { nick: String, channel: String },
    /// 482 ERR_CHANOPRIVSNEEDED
    ChanOpPrivsNeeded { nick: String, channel: String },
    /// 441 ERR_USERNOTINCHANNEL
    UserNotInChannel { nick: String, target: String, channel: String },
    /// 324 RPL_CHANNELMODEIS
    ChannelModeIs { nick: String, channel: String, modes: String, params: Vec<String> },
    /// 322 RPL_LIST
    List { nick: String, channel: String, visible: usize, topic: String },
    /// 315 RPL_ENDOFWHO
    EndOfWho { nick: String, target: String },
    /// 311 RPL_WHOISUSER
    WhoisUser { nick: String, target: String, username: String, host: String, realname: String },
    /// 312 RPL_WHOISSERVER
    WhoisServer { nick: String, target: String, server: String, info: String },
    /// 318 RPL_ENDOFWHOIS
    EndOfWhois { nick: String, target: String },
    /// 321 RPL_LISTSTART
    ListStart { nick: String },
    /// 323 RPL_LISTEND
    ListEnd { nick: String },
}

impl Reply {
    /// Convert reply to IRC message
    pub fn to_message(&self, server_name: &str) -> IrcMessage {
        match self {
            Reply::Welcome { nick, network } => {
                IrcMessage::new("001")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        format!("Welcome to the {} IRC Network, {}", network, nick),
                    ])
            }
            Reply::YourHost { nick, servername, version } => {
                IrcMessage::new("002")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        format!("Your host is {}, running version {}", servername, version),
                    ])
            }
            Reply::Created { nick, date } => {
                IrcMessage::new("003")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        format!("This server was created {}", date),
                    ])
            }
            Reply::MyInfo { nick, servername, version, usermodes, chanmodes } => {
                IrcMessage::new("004")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        servername.clone(),
                        version.clone(),
                        usermodes.clone(),
                        chanmodes.clone(),
                    ])
            }
            Reply::ISupport { nick, tokens } => {
                let mut params = vec![nick.clone()];
                params.extend(tokens.clone());
                params.push("are supported by this server".to_string());
                IrcMessage::new("005")
                    .with_prefix(server_name)
                    .with_params(params)
            }
            Reply::NoTopic { nick, channel } => {
                IrcMessage::new("331")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        channel.clone(),
                        "No topic is set".to_string(),
                    ])
            }
            Reply::Topic { nick, channel, topic } => {
                IrcMessage::new("332")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        channel.clone(),
                        topic.clone(),
                    ])
            }
            Reply::NamReply { nick, symbol, channel, names } => {
                let mut params = vec![
                    nick.clone(),
                    symbol.to_string(),
                    channel.clone(),
                ];
                let names_str = names.join(" ");
                params.push(names_str);
                IrcMessage::new("353")
                    .with_prefix(server_name)
                    .with_params(params)
            }
            Reply::EndOfNames { nick, channel } => {
                IrcMessage::new("366")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        channel.clone(),
                        "End of /NAMES list".to_string(),
                    ])
            }
            Reply::MotdStart { nick, server } => {
                IrcMessage::new("375")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        format!("- {} Message of the day -", server),
                    ])
            }
            Reply::Motd { nick, line } => {
                IrcMessage::new("372")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        format!("- {}", line),
                    ])
            }
            Reply::EndOfMotd { nick } => {
                IrcMessage::new("376")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        "End of /MOTD command".to_string(),
                    ])
            }
            Reply::NoMotd { nick } => {
                IrcMessage::new("422")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        "MOTD File is missing".to_string(),
                    ])
            }
            Reply::NoSuchNick { nick, target } => {
                IrcMessage::new("401")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        target.clone(),
                        "No such nick/channel".to_string(),
                    ])
            }
            Reply::NoSuchChannel { nick, channel } => {
                IrcMessage::new("403")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        channel.clone(),
                        "No such channel".to_string(),
                    ])
            }
            Reply::CannotSendToChan { nick, channel } => {
                IrcMessage::new("404")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        channel.clone(),
                        "Cannot send to channel".to_string(),
                    ])
            }
            Reply::NotOnChannel { nick, channel } => {
                IrcMessage::new("442")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        channel.clone(),
                        "You're not on that channel".to_string(),
                    ])
            }
            Reply::NicknameInUse { nick, attempted } => {
                IrcMessage::new("433")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        attempted.clone(),
                        "Nickname is already in use".to_string(),
                    ])
            }
            Reply::NeedMoreParams { nick, command } => {
                IrcMessage::new("461")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        command.clone(),
                        "Not enough parameters".to_string(),
                    ])
            }
            Reply::AlreadyRegistered { nick } => {
                IrcMessage::new("462")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        "You may not reregister".to_string(),
                    ])
            }
            Reply::UnknownCommand { nick, command } => {
                IrcMessage::new("421")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        command.clone(),
                        "Unknown command".to_string(),
                    ])
            }
            Reply::PasswdMismatch { nick } => {
                IrcMessage::new("464")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        "Password incorrect".to_string(),
                    ])
            }
            Reply::NotRegistered { nick } => {
                IrcMessage::new("451")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        "You have not registered".to_string(),
                    ])
            }
            Reply::ErroneousNickname { nick, attempted } => {
                IrcMessage::new("432")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        attempted.clone(),
                        "Erroneous nickname".to_string(),
                    ])
            }
            Reply::BadChannelKey { nick, channel } => {
                IrcMessage::new("475")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        channel.clone(),
                        "Cannot join channel (+k)".to_string(),
                    ])
            }
            Reply::ChannelIsFull { nick, channel } => {
                IrcMessage::new("471")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        channel.clone(),
                        "Cannot join channel (+l)".to_string(),
                    ])
            }
            Reply::ChanOpPrivsNeeded { nick, channel } => {
                IrcMessage::new("482")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        channel.clone(),
                        "You're not channel operator".to_string(),
                    ])
            }
            Reply::UserNotInChannel { nick, target, channel } => {
                IrcMessage::new("441")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        target.clone(),
                        channel.clone(),
                        "They aren't on that channel".to_string(),
                    ])
            }
            Reply::ChannelModeIs { nick, channel, modes, params } => {
                let mut msg_params = vec![nick.clone(), channel.clone(), modes.clone()];
                msg_params.extend(params.clone());
                IrcMessage::new("324")
                    .with_prefix(server_name)
                    .with_params(msg_params)
            }
            Reply::List { nick, channel, visible, topic } => {
                IrcMessage::new("322")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        channel.clone(),
                        visible.to_string(),
                        topic.clone(),
                    ])
            }
            Reply::EndOfWho { nick, target } => {
                IrcMessage::new("315")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        target.clone(),
                        "End of /WHO list".to_string(),
                    ])
            }
            Reply::WhoisUser { nick, target, username, host, realname } => {
                IrcMessage::new("311")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        target.clone(),
                        username.clone(),
                        host.clone(),
                        "*".to_string(),
                        realname.clone(),
                    ])
            }
            Reply::WhoisServer { nick, target, server, info } => {
                IrcMessage::new("312")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        target.clone(),
                        server.clone(),
                        info.clone(),
                    ])
            }
            Reply::EndOfWhois { nick, target } => {
                IrcMessage::new("318")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        target.clone(),
                        "End of /WHOIS list".to_string(),
                    ])
            }
            Reply::ListStart { nick } => {
                IrcMessage::new("321")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        "Channel".to_string(),
                        "Users  Name".to_string(),
                    ])
            }
            Reply::ListEnd { nick } => {
                IrcMessage::new("323")
                    .with_prefix(server_name)
                    .with_params(vec![
                        nick.clone(),
                        "End of /LIST".to_string(),
                    ])
            }
        }
    }
}

impl From<Reply> for crate::IrcMessage {
    fn from(reply: Reply) -> Self {
        reply.to_message("ironchatd.local")
    }
}