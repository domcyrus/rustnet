use super::{ConnectionKey, ProcessLookup};
use crate::network::types::{Connection, Protocol};
use anyhow::Result;
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::RwLock;

pub struct MacOSProcessLookup {
    cache: RwLock<HashMap<ConnectionKey, (u32, String)>>,
}

impl MacOSProcessLookup {
    pub fn new() -> Result<Self> {
        Ok(Self {
            cache: RwLock::new(HashMap::new()),
        })
    }

    fn parse_lsof() -> Result<HashMap<ConnectionKey, (u32, String)>> {
        let mut lookup = HashMap::new();

        info!("Running lsof to get network connections");

        // Run lsof to get network connections
        let output = Command::new("lsof")
            .args(["-i", "-n", "-P", "+c", "0"])
            .output()?;

        if !output.status.success() {
            error!("lsof command failed with status: {}", output.status);
            error!("stderr: {}", String::from_utf8_lossy(&output.stderr));
            return Ok(lookup);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = stdout.lines().collect();
        info!("lsof returned {} lines", lines.len());

        if lines.is_empty() {
            warn!("lsof returned no output");
            return Ok(lookup);
        }

        debug!("lsof header: {}", lines.first().unwrap_or(&""));
        debug!("First few lines of lsof output:");
        for (i, line) in lines.iter().take(5).enumerate() {
            debug!("  {}: {}", i, line);
        }

        let mut processed_lines = 0;
        let mut successful_parsers = 0;

        for line in stdout.lines().skip(1) {
            processed_lines += 1;
            let parts: Vec<&str> = line.split_whitespace().collect();

            debug!("Processing line {}: {} parts", processed_lines, parts.len());
            debug!("  Raw line: {}", line);

            if parts.len() < 8 {
                debug!("  Skipping line with too few parts ({})", parts.len());
                continue;
            }

            let process_name = normalize_process_name_robust(&decode_lsof_string(parts[0]));
            let pid = match parts[1].parse::<u32>() {
                Ok(p) => p,
                Err(e) => {
                    debug!("  Failed to parse PID '{}': {}", parts[1], e);
                    continue;
                }
            };

            debug!("  Process: {} (PID: {})", process_name, pid);
            debug!("  Parts: {:?}", parts);

            // Check TYPE field (usually parts[4]) to determine protocol
            let protocol_hint = if parts.len() > 4 {
                match parts[4] {
                    "IPv4" | "IPv6" => {
                        // Need to look at NODE field for protocol
                        if parts.len() > 7 && (parts[7] == "TCP" || parts[7].contains("TCP")) {
                            debug!("  Detected TCP from NODE field: {}", parts[7]);
                            Some(Protocol::TCP)
                        } else if parts.len() > 7 && (parts[7] == "UDP" || parts[7].contains("UDP"))
                        {
                            debug!("  Detected UDP from NODE field: {}", parts[7]);
                            Some(Protocol::UDP)
                        } else {
                            debug!(
                                "  No protocol detected from NODE field: {}",
                                parts.get(7).unwrap_or(&"")
                            );
                            None
                        }
                    }
                    _ => {
                        debug!("  TYPE field not IPv4/IPv6: {}", parts[4]);
                        None
                    }
                }
            } else {
                debug!("  Not enough parts for TYPE field");
                None
            };

            // For lsof output, the connection info can be in different places:
            // If the last field looks like a state (starts with "(" and ends with ")"),
            // then the connection info is in the second-to-last field.
            // Otherwise, it's in the last field.
            let last_field = parts.last().map_or("", |v| v);
            let connection_field = if last_field.starts_with('(') && last_field.ends_with(')') {
                // Connection address is in the second-to-last field (before the state)
                if parts.len() >= 2 {
                    parts[parts.len() - 2]
                } else {
                    last_field
                }
            } else {
                // Connection info is in the last field
                last_field
            };

            debug!("  Connection field: '{}'", connection_field);

            if let Some((protocol, local, remote)) =
                parse_lsof_connection_with_hint(connection_field, protocol_hint)
            {
                let key = ConnectionKey {
                    protocol,
                    local_addr: local,
                    remote_addr: remote,
                };
                debug!(
                    "  Successfully parsed connection: {:?} -> {} ({})",
                    key, process_name, pid
                );
                lookup.insert(key, (pid, process_name));
                successful_parsers += 1;
            } else {
                debug!("  Failed to parse connection from NAME field");
            }
        }

        info!(
            "Processed {} lines, successfully parsed {} connections",
            processed_lines, successful_parsers
        );
        info!("Total connections in lookup table: {}", lookup.len());

        Ok(lookup)
    }
}

impl ProcessLookup for MacOSProcessLookup {
    fn get_process_for_connection(&self, conn: &Connection) -> Option<(u32, String)> {
        let key = ConnectionKey::from_connection(conn);
        let cache = self.cache.read().unwrap();
        let result = cache.get(&key).cloned();

        if result.is_some() {
            debug!("Found process info for connection {:?}: {:?}", key, result);
        } else {
            debug!("No process info found for connection {:?}", key);
            debug!("Available keys in cache:");
            for (cached_key, (pid, name)) in cache.iter().take(10) {
                debug!("  {:?} -> {} ({})", cached_key, name, pid);
            }
            if cache.len() > 10 {
                debug!("  ... and {} more entries", cache.len() - 10);
            }
        }

        result
    }

    fn refresh(&self) -> Result<()> {
        info!("Refreshing macOS process lookup cache");
        let new_cache = Self::parse_lsof()?;
        let cache_size = new_cache.len();
        *self.cache.write().unwrap() = new_cache;
        info!("Process lookup cache refreshed with {} entries", cache_size);
        Ok(())
    }

    fn get_detection_method(&self) -> &str {
        "lsof"
    }
}

fn parse_lsof_connection_with_hint(
    name: &str,
    protocol_hint: Option<Protocol>,
) -> Option<(Protocol, SocketAddr, SocketAddr)> {
    // Parse lsof NAME field format:
    // "192.168.1.1:443->10.0.0.1:12345" (TCP)
    // "192.168.1.1:53" (UDP)
    // "*:80" (listening)

    debug!(
        "    Parsing NAME field: '{}' with hint: {:?}",
        name, protocol_hint
    );

    if name.contains("->") {
        // Established connection with remote address
        let parts: Vec<&str> = name.split("->").collect();
        if parts.len() != 2 {
            debug!("    Failed: arrow connection doesn't have exactly 2 parts");
            return None;
        }

        debug!(
            "    Parsing arrow connection: '{}' -> '{}'",
            parts[0], parts[1]
        );
        let local = parse_socket_addr(parts[0])?;
        let remote = parse_socket_addr(parts[1])?;

        // Use hint if available, otherwise assume TCP for established connections
        let protocol = protocol_hint.unwrap_or(Protocol::TCP);
        debug!(
            "    Success: {:?} {}:{} -> {}:{}",
            protocol,
            local.ip(),
            local.port(),
            remote.ip(),
            remote.port()
        );
        Some((protocol, local, remote))
    } else if name.contains(":") {
        // UDP or listening socket
        debug!("    Parsing single address: '{}'", name);
        let local = parse_socket_addr(name)?;

        // For UDP or listening, we create a dummy remote address
        let remote = match local {
            SocketAddr::V4(_) => "0.0.0.0:0".parse().ok()?,
            SocketAddr::V6(_) => "[::]:0".parse().ok()?,
        };

        // Use hint if available, otherwise assume UDP for single address
        let protocol = protocol_hint.unwrap_or(Protocol::UDP);
        debug!(
            "    Success: {:?} {}:{} (listening/UDP)",
            protocol,
            local.ip(),
            local.port()
        );
        Some((protocol, local, remote))
    } else {
        debug!("    Failed: no recognizable connection format");
        None
    }
}

fn parse_socket_addr(addr_str: &str) -> Option<SocketAddr> {
    debug!("      Parsing socket address: '{}'", addr_str);

    // Handle IPv6 addresses in brackets
    if addr_str.starts_with('[') {
        let result = addr_str.parse().ok();
        debug!("      IPv6 parse result: {:?}", result);
        result
    } else if addr_str.starts_with('*') {
        // Listening on all interfaces
        let port_str = addr_str.strip_prefix("*:")?;
        let port = port_str.parse().ok()?;
        let result = Some(SocketAddr::new("0.0.0.0".parse().ok()?, port));
        debug!("      Wildcard parse result: {:?}", result);
        result
    } else {
        let result = addr_str.parse().ok();
        debug!("      Regular parse result: {:?}", result);
        result
    }
}

/// Robust normalization of process names to match PKTAP normalization
/// Handles all types of whitespace and control characters consistently
fn normalize_process_name_robust(name: &str) -> String {
    let normalized = name
        .chars()
        .map(|c| {
            if c.is_whitespace() || c.is_control() {
                ' ' // Convert whitespace and control characters to space
            } else {
                c
            }
        })
        .collect::<String>()
        .split_whitespace() // Split on any whitespace
        .collect::<Vec<&str>>()
        .join(" "); // Join with single spaces

    debug!(
        "📝 Normalized lsof process name: '{}' -> '{}'",
        name, normalized
    );
    normalized
}

/// Decode lsof escape sequences like \x20 back to regular characters
fn decode_lsof_string(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\\' && chars.peek() == Some(&'x') {
            // Skip the 'x'
            chars.next();

            // Try to read two hex digits
            let hex_digits: String = chars.by_ref().take(2).collect();
            if hex_digits.len() == 2
                && let Ok(byte_val) = u8::from_str_radix(&hex_digits, 16)
                && let Some(decoded_char) = std::char::from_u32(byte_val as u32)
            {
                result.push(decoded_char);
                continue;
            }

            // If decoding failed, push the original characters
            result.push('\\');
            result.push('x');
            result.push_str(&hex_digits);
        } else {
            result.push(ch);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_lsof_string() {
        // Test basic space decoding
        assert_eq!(
            decode_lsof_string("Microsoft\\x20Teams\\x20WebView\\x20Helper"),
            "Microsoft Teams WebView Helper"
        );

        // Test single word with space
        assert_eq!(decode_lsof_string("Brave\\x20Browser"), "Brave Browser");

        // Test process name without escaping
        assert_eq!(decode_lsof_string("firefox"), "firefox");

        // Test process name with single escaped space
        assert_eq!(decode_lsof_string("App\\x20Name"), "App Name");

        // Test empty string
        assert_eq!(decode_lsof_string(""), "");

        // Test string with no escape sequences
        assert_eq!(decode_lsof_string("launchd"), "launchd");

        // Test malformed escape sequence (should be preserved)
        assert_eq!(
            decode_lsof_string("App\\x2G"),
            "App\\x2G" // Invalid hex, should remain unchanged
        );

        // Test incomplete escape sequence at end
        assert_eq!(
            decode_lsof_string("App\\x2"),
            "App\\x2" // Incomplete, should remain unchanged
        );

        // Test multiple different escape sequences
        assert_eq!(
            decode_lsof_string("Test\\x20App\\x2D\\x2EExe"),
            "Test App-.Exe" // \x20 = space, \x2D = hyphen, \x2E = period
        );

        // Test backslash without escape sequence
        assert_eq!(
            decode_lsof_string("App\\Normal"),
            "App\\Normal" // Should preserve non-escape backslashes
        );
    }
}
