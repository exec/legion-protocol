# 🏛️ Legion Protocol

**Modern IRC extensions with enhanced capabilities and security.**

A comprehensive protocol library that extends IRC with modern features while maintaining complete backward compatibility. Part of the Legion ecosystem designed for secure, self-hostable communication.

## 🎯 Project Overview

Legion Protocol is a Rust library that implements IRC protocol parsing and extensions, providing the foundation for modern IRC servers and clients. It includes support for IRCv3 capabilities, message tagging, and enhanced channel management while maintaining 100% compatibility with standard IRC.

### 🏗️ Ecosystem Architecture

```
🏛️ LEGION ECOSYSTEM
├── 📡 legion-protocol    (THIS REPO) - Core protocol library  
├── 🏛️ centurion        - IRC server implementation
├── ⚔️ legionnaire      - IRC client with modern features
└── 🛡️ phalanx          - E2E encryption library (future)
```

### 🎖️ Component Overview

- **Legion Protocol** = Core IRC protocol implementation and extensions
- **Centurion** = High-performance IRC server daemon
- **Legionnaire** = Modern IRC client with enhanced features
- **Phalanx** = Encryption and security layer (planned)

## 🚀 Features

### ✅ Core Protocol Implementation

#### 🏛️ **IRC Protocol Foundation**
- **Complete RFC 1459/2812 compliance** with modern parsing
- **Message parsing and formatting** with proper IRC formatting
- **Command enumeration** covering all standard IRC commands
- **Channel management** with prefix system support (`#`, `&`, `!`, `+`)
- **User management** and state tracking
- **Error handling** with proper IRC numeric replies

#### 📡 **IRCv3 Extensions**
- **Capability negotiation** (CAP LS, REQ, ACK, NAK, END)
- **Message tags** with proper parsing and validation
- **SASL authentication** framework (multiple mechanisms)
- **Server-time** and other time-based extensions
- **Batch processing** for efficient message grouping

#### 🔧 **Advanced Features**
- **Admin module** for server management capabilities
- **Protocol validation** ensuring message integrity
- **Extensible design** for custom capabilities and commands
- **Zero-copy parsing** where possible for performance

## 📦 Installation

Add Legion Protocol to your `Cargo.toml`:

```toml
[dependencies]
legion-protocol = { git = "https://github.com/dylan-k/legion-protocol.git" }
```

Or for local development:

```toml
[dependencies]
legion-protocol = { path = "../legion-protocol" }
```

## 🔧 Usage Examples

### Basic Message Parsing

```rust
use legion_protocol::{Message, Command};

// Parse IRC message
let raw = ":nick!user@host PRIVMSG #channel :Hello world!";
let message = Message::parse(raw)?;

assert_eq!(message.prefix, Some("nick!user@host".to_string()));
assert_eq!(message.command, "PRIVMSG");
assert_eq!(message.params, vec!["#channel", "Hello world!"]);

// Convert back to raw format
let formatted = message.to_string();
```

### Command Handling

```rust
use legion_protocol::Command;

let command = Command::parse("PRIVMSG", vec!["#channel".to_string(), "Hello!".to_string()]);

match command {
    Command::Privmsg { target, message } => {
        println!("Message to {}: {}", target, message);
    }
    Command::Join(channels, keys) => {
        println!("Joining channels: {:?}", channels);
    }
    _ => {}
}
```

### Capability Negotiation

```rust
use legion_protocol::Capability;

// Server advertising capabilities
let caps = vec![
    Capability::MessageTags,
    Capability::ServerTime,
    Capability::Sasl,
    Capability::Batch,
    Capability::EchoMessage,
];

// Convert to CAP LS format
let cap_string = caps.iter()
    .map(|cap| cap.to_string())
    .collect::<Vec<_>>()
    .join(" ");
```

### Message Tags

```rust
use legion_protocol::Message;

// Create message with tags
let mut message = Message::new("PRIVMSG")
    .with_params(vec!["#channel".to_string(), "Hello!".to_string()]);

// Add server-time tag
message = message.with_tag("time".to_string(), Some("2024-01-01T12:00:00.000Z".to_string()));

// Add message ID
message = message.with_tag("msgid".to_string(), Some("abc123".to_string()));

// Parse message with tags
let raw = "@time=2024-01-01T12:00:00.000Z;msgid=abc123 PRIVMSG #channel :Hello!";
let parsed = Message::parse(raw)?;
assert_eq!(parsed.tags.get("time"), Some(&Some("2024-01-01T12:00:00.000Z".to_string())));
```

### SASL Authentication

```rust
use legion_protocol::SaslMechanism;

// SASL PLAIN mechanism
let mechanism = SaslMechanism::Plain;
let credentials = "username\0username\0password";
let encoded = base64::encode(credentials);

// Send AUTHENTICATE command
println!("AUTHENTICATE PLAIN");
println!("AUTHENTICATE {}", encoded);
```

## 🗂️ Library Structure

### Core Modules

- **`message.rs`** - IRC message parsing and formatting
- **`command.rs`** - IRC command enumeration and parsing  
- **`capabilities.rs`** - IRCv3 capability negotiation
- **`replies.rs`** - IRC numeric replies and errors
- **`sasl.rs`** - SASL authentication mechanisms
- **`admin.rs`** - Server administration commands
- **`validation.rs`** - Input validation and security checks
- **`utils.rs`** - Utility functions and helpers

### Design Principles

- **Zero-copy parsing** where possible for performance
- **Comprehensive error handling** with detailed error messages
- **Extensible architecture** for adding new capabilities
- **Type safety** with Rust's ownership system
- **Complete IRC compliance** with modern extensions

## 🧪 Testing

```bash
# Run all tests
cargo test

# Run specific test module
cargo test test_message_parsing

# Run with output
cargo test -- --nocapture

# Run benchmarks
cargo bench
```

### Test Coverage

- **Message parsing** - Comprehensive IRC message format tests
- **Command parsing** - All IRC commands and parameters  
- **Capability negotiation** - IRCv3 capability flows
- **Tag parsing** - Message tags and escaping
- **SASL mechanisms** - Authentication flows
- **Error handling** - Invalid input and edge cases

## 🏗️ Development Status

### ✅ Completed

- Core IRC message parsing and formatting
- Complete command enumeration
- IRCv3 capability negotiation
- Message tagging support
- SASL authentication framework
- Admin module for server management
- Comprehensive test coverage
- Documentation and examples

### 🚧 In Progress

- Enhanced error messages and validation
- Performance optimizations
- Additional SASL mechanisms
- Extended IRCv3 features

### 📋 Planned

- Integration with Phalanx encryption library
- Advanced channel management features
- Federation and bridging support
- Performance benchmarking suite

## 🤝 Contributing

Contributions are welcome! Please see the issues section for current development needs.

### Development Setup

```bash
git clone https://github.com/dylan-k/legion-protocol.git
cd legion-protocol
cargo build
cargo test
```

### Contributing Guidelines

- Follow Rust naming conventions
- Add tests for new functionality
- Update documentation for public APIs
- Ensure backward compatibility with IRC
- Run `cargo fmt` and `cargo clippy` before submitting

## 📄 License

Legion Protocol is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- The IRC protocol specifications (RFC 1459, RFC 2812)
- The IRCv3 working group for modern IRC extensions
- The Rust community for excellent tooling and libraries
- All contributors and testers who help improve the library

---

*Legion Protocol: Modern IRC extensions built with Rust's safety and performance in mind.*