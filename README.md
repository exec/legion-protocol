# 🏛️ Legion Protocol

A modern IRC protocol library in Rust with IRCv3 support and enhanced capabilities.

## Features

- **IRCv3 Protocol**: Complete capability negotiation, message tags, server-time
- **Message Parsing**: Fast, zero-copy IRC message parsing and validation
- **SASL Authentication**: Multiple authentication mechanisms (PLAIN, SCRAM-SHA-256)
- **Admin Extensions**: Channel management and moderation commands
- **Bleeding Edge**: Experimental IRCv3 draft capabilities
- **Security**: Input validation and protocol confusion protection

## Installation

```bash
cargo add legion-protocol
```

## Usage

### Basic Message Parsing

```rust
use legion_protocol::{IrcMessage, Command};

let raw = ":nick!user@host PRIVMSG #channel :Hello world";
let msg = IrcMessage::parse(raw).unwrap();

match msg.command {
    Command::Privmsg { target, text } => {
        println!("Message to {}: {}", target, text);
    }
    _ => {}
}
```

### Capability Negotiation

```rust
use legion_protocol::{CapabilitySet, Capability};

let mut caps = CapabilitySet::new();
caps.request(Capability::ServerTime);
caps.request(Capability::MessageTags);

// Server response
caps.acknowledge(Capability::ServerTime);
```

### Message Tags

```rust
use legion_protocol::IrcMessage;

let tagged = "@time=2023-01-01T00:00:00.000Z :nick PRIVMSG #chan :hi";
let msg = IrcMessage::parse(tagged).unwrap();

if let Some(time) = msg.tags.get("time") {
    println!("Message sent at: {}", time);
}
```

## Features

- `std` - Standard library support (default)
- `serde` - Serialization support 
- `chrono` - Timestamp parsing
- `bleeding-edge` - Experimental IRCv3 drafts
- `server` - Server-side extensions

## License

MIT OR Apache-2.0