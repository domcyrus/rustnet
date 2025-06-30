use anyhow::Result;

// submodules
pub mod capture;
pub mod dpi;
pub mod merge;
pub mod parser;
pub mod platform;
pub mod services;
pub mod types;

// Re-export commonly used items at the module root
pub use capture::setup_packet_capture;
pub use parser::{PacketParser, ParsedPacket};
pub use platform::{ConnectionKey, ProcessLookup, create_process_lookup};
pub use services::ServiceLookup;
pub use types::{ApplicationProtocol, Connection, DpiInfo, Protocol, ProtocolState, TcpState};
