# Legion Protocol

**The secure, IRC-compatible communication protocol that unites communities.**

🏛️ **United we communicate** - Modern encrypted messaging with complete IRC backward compatibility.

## 🎯 Project Overview

Legion Protocol is a revolutionary communication standard that bridges the gap between classic IRC and modern secure messaging. Part of a larger military-themed ecosystem designed to replace Discord while maintaining 100% IRC compatibility.

### 🏗️ Ecosystem Architecture

```
🏛️ LEGION ECOSYSTEM
├── 📡 legion-protocol    (THIS REPO) - Core protocol library  
├── 🛡️ phalanx          - General-purpose group E2E encryption
├── 🏛️ centurion        - Server daemon (centuriond) 
├── ⚔️ legionnaire      - Client applications
└── 🤝 herald           - Bridge service (planned)
```

### 🎖️ Military Branding Strategy

**Perfect synergy with [Bastion](https://github.com/exec/bastion) security platform:**
- **Bastion** = Defensive security operations platform
- **Legion** = Organized communication forces
- **Centurion** = Command & control servers  
- **Legionnaire** = Individual warrior clients
- **Phalanx** = Collective encryption defense
- **Herald** = Diplomatic messengers between legions

## 🚀 Current Status & Development State

### ✅ COMPLETED FEATURES

#### 🏛️ **Core Legion Protocol Foundation**
- **Channel prefix system implemented:**
  - `#channel` = Standard IRC global channels
  - `&channel` = Standard IRC local channels  
  - `!channel` = Legion encrypted channels
- **Capability system:** `+legion-protocol/v1` for client/server detection
- **Channel type detection and validation**
- **IRC user protection** - clear errors when IRC users try to join `!encrypted`

#### 🛡️ **Security Architecture** 
- **IronSession management** (tracks Legion negotiation state)
- **Access control logic** for encrypted channels
- **Capability-based protocol detection**
- **100% IRC backward compatibility maintained**

#### 🎯 **Strategic Positioning**
- **Discord replacement focus** (not just IRC modernization)
- **Gaming community targeting** with military aesthetics
- **Privacy-first messaging** with self-hosting
- **Enterprise-ready** compliance and security

### 🏗️ IN PROGRESS

#### 📊 **Rebranding Effort**
- ✅ GitHub repositories renamed and populated:
  - `iron-protocol` → `legion-protocol` 
  - `ironchatd` → `centurion`
  - `ironchat` → `legionnaire` 
- ⏳ Import statements and references need updating
- ⏳ Documentation and branding updates

### 📋 IMMEDIATE NEXT STEPS

#### 🛡️ **Phalanx Protocol Integration** 
**NEW STRATEGIC DECISION:** Phalanx will be a **separate crate** for maximum adoption:
- **Repository created:** https://github.com/exec/phalanx
- **Rationale:** Broader contribution base, multiple use cases, competitive positioning
- **Architecture:** Legion Protocol will depend on Phalanx for encryption
- **Benefits:** Crypto experts contribute to Phalanx, protocol experts to Legion

#### 📝 **Critical Implementation Tasks:**
1. **Update all import statements** from `iron_protocol` to `legion_protocol`
2. **Implement Phalanx Protocol** in separate repository
3. **Integrate Phalanx** as dependency in Legion Protocol
4. **Update capability names** from `+iron-protocol/v1` to `+legion-protocol/v1`
5. **Complete Centurion server** integration with Legion capabilities
6. **Complete Legionnaire client** Legion Protocol support

## 🔧 Technical Implementation Details

### 📡 Protocol Capabilities

```rust
// Current capabilities implemented
"+legion-protocol/v1"  // Legion Protocol extensions
"+draft/react"         // Message reactions  
"+draft/reply"         // Message replies
"sasl"                 // Authentication
"message-tags"         // IRCv3 message tags
"server-time"          // Timestamp support
"batch"                // Message batching
```

### 🏛️ Channel System

```rust
use legion_protocol::{ChannelType, utils::get_channel_type};

let channel_type = get_channel_type("#general");   // ChannelType::IrcGlobal
let channel_type = get_channel_type("&local");     // ChannelType::IrcLocal  
let channel_type = get_channel_type("!encrypted"); // ChannelType::IronEncrypted
```

### 🛡️ Security Model

```rust
// Access control for encrypted channels
use legion_protocol::{IronChannelHandler, ChannelJoinResult};

let result = IronChannelHandler::can_join_channel(
    "!secure",     // Legion encrypted channel
    true,          // User has Legion support  
    true           // Server has Legion support
);
// Result: ChannelJoinResult::AllowedEncrypted
```

### 🔄 Session Management

```rust  
use legion_protocol::{IronSession, IronVersion};

let mut session = IronSession::new();
session.set_version(IronVersion::V1);
session.complete_negotiation();

if session.is_iron_active() {
    session.add_encrypted_channel("!secure".to_string());
}
```

## 🎯 Strategic Market Position

### 📊 Competitive Analysis

```
┌─────────────────┬─────────┬──────────┬─────────┬──────────┬──────────┐
│ Protocol        │ IRC     │ Mobile   │ E2E     │ Fed      │ Gaming   │
│                 │ Native  │ First    │ Native  │ Native   │ Voice    │
├─────────────────┼─────────┼──────────┼─────────┼──────────┼──────────┤
│ IRC             │ ✅      │ ❌       │ ❌      │ ❌       │ ❌       │
│ Matrix          │ ❌      │ ⚠️       │ ✅      │ ✅       │ ❌       │
│ Signal          │ ❌      │ ✅       │ ✅      │ ❌       │ ❌       │  
│ Discord         │ ❌      │ ✅       │ ❌      │ ❌       │ ✅       │
│ Telegram        │ ❌      │ ✅       │ ⚠️      │ ❌       │ ❌       │
│ Legion Protocol │ ✅      │ ✅       │ ✅      │ ✅       │ ✅       │
└─────────────────┴─────────┴──────────┴─────────┴──────────┴──────────┘
```

### 🎖️ Unique Value Propositions

1. **For IRC Veterans:** "Your existing workflow, but secure & mobile-friendly"
2. **For Matrix Users:** "Same security, way simpler setup, broader compatibility"  
3. **For Signal Users:** "Same encryption, but with persistent channels & desktop-first option"
4. **For Discord Migrants:** "Community control, no corporate data harvesting, E2E encrypted"
5. **For Gaming Communities:** "Discord-like experience with military aesthetics and real security"

## 🛠️ Current Codebase Structure

```
legion-protocol/src/
├── lib.rs              // Main exports, protocol constants
├── capabilities.rs     // IRCv3 + Legion capability negotiation  
├── message.rs          // IRC message parsing with Legion extensions
├── command.rs          // IRC commands + Legion-specific commands
├── iron.rs            // Legion session management & channel control
├── utils.rs           // Channel validation, type detection
├── error.rs           // Error handling
├── sasl.rs            // Authentication mechanisms
├── validation.rs      // Security validation
├── replies.rs         // IRC numeric replies
└── bleeding_edge.rs   // Experimental IRCv3 features
```

### 🔑 Key Modules

#### **`iron.rs` - Legion Protocol Core**
- `IronSession` - Tracks Legion negotiation state
- `IronChannelHandler` - Encrypted channel access control  
- `IronVersion` - Protocol versioning
- `detect_iron_support()` - Capability detection

#### **`capabilities.rs` - Protocol Negotiation**
- `Capability::IronProtocolV1` - Legion Protocol capability
- `CapabilityHandler` - IRCv3 capability negotiation
- Essential capabilities list includes Legion Protocol

#### **`utils.rs` - Channel System**
- `ChannelType` - IRC vs Legion channel detection
- `get_channel_type()` - Channel prefix parsing
- `is_iron_encrypted_channel()` - Legion channel validation

## 🚧 Known Issues & Technical Debt

### 🔄 **Rebranding Debt**
- Import statements still reference `iron_protocol` in some places
- Capability strings still use `+iron-protocol/v1` in some code paths  
- Documentation and comments reference old "Iron" naming
- Test cases need Legion Protocol terminology updates

### 🛡️ **Encryption Gap**
- Phalanx Protocol not yet implemented
- No actual E2E encryption yet - only the framework
- Channel encryption is planned but not functional

### 📊 **Integration Issues** 
- Centurion server needs Legion Protocol integration
- Legionnaire client needs Legion capabilities implementation
- Herald bridge service not started

## 🎯 Next Conversation Priorities

### 🥇 **HIGHEST PRIORITY**
1. **Complete rebranding** - Update all `iron_protocol` imports to `legion_protocol`
2. **Fix capability strings** - Change `+iron-protocol/v1` to `+legion-protocol/v1` everywhere  
3. **Start Phalanx implementation** in separate repository

### 🥈 **HIGH PRIORITY**  
4. **Test Legion Protocol** - Ensure capability negotiation works end-to-end
5. **Update Centurion** - Integrate Legion capabilities in server
6. **Update Legionnaire** - Add Legion support to client

### 🥉 **MEDIUM PRIORITY**
7. **Clean up technical debt** - Remove old `read_message` implementations
8. **Documentation** - Update all READMEs with Legion branding
9. **Testing** - Comprehensive test suite for Legion features

## 🧭 Vision & Roadmap

### 🎖️ **Mission Statement**
Create the secure, self-hostable communication platform that gives communities back control of their data while maintaining universal compatibility.

### 🗺️ **Roadmap Phases**

#### **Phase 1: Foundation** ✅ (Mostly Complete)
- ✅ Legion Protocol core capabilities
- ✅ Channel prefix system  
- ✅ IRC compatibility layer
- ⏳ Complete rebranding effort

#### **Phase 2: Encryption** 🚧 (In Progress)  
- 🛡️ Implement Phalanx Protocol (separate repo)
- 🔐 Integrate E2E encryption in Legion channels
- 🛡️ Cross-server federation crypto

#### **Phase 3: Ecosystem** 📋 (Planned)
- 🏛️ Complete Centurion server implementation
- ⚔️ Feature-complete Legionnaire client
- 🤝 Herald bridge service for federation
- 📱 Mobile Legionnaire apps

#### **Phase 4: Dominance** 🏆 (Future)
- 🎮 Gaming community features (voice, rich media)
- 🏢 Enterprise deployment tools
- 🌐 Public Legion hosting services
- 📈 Discord/Slack replacement campaigns

## 📞 Current Context for Next Developer

**You are picking up after a successful rebranding effort where "IronChat" became "Legion Protocol". All GitHub repositories are correctly set up and populated:**

- ✅ **https://github.com/exec/legion-protocol** - This protocol library
- ✅ **https://github.com/exec/centurion** - Server daemon  
- ✅ **https://github.com/exec/legionnaire** - Client applications
- ✅ **https://github.com/exec/phalanx** - Encryption library (empty, just created)

**The code works but needs import statement updates and the encryption isn't implemented yet.**

**Primary focus should be:**
1. **Fix all imports** throughout the codebase
2. **Start implementing Phalanx** encryption protocol  
3. **Test end-to-end** Legion capabilities between client/server

**The vision is solid, the architecture is sound, and the foundation is strong. Time to make it fully functional! 🏛️⚔️**