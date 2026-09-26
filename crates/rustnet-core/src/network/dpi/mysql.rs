//! MySQL classic protocol greeting and protocol-4.1 SSLRequest inspection.
//! Only complete messages at the start of a TCP payload are inspected.

use crate::network::types::MySqlInfo;

const CLIENT_PROTOCOL_41: u16 = 0x0200;
const CLIENT_SSL: u16 = 0x0800;

pub(super) fn analyze_mysql(payload: &[u8], to_mysql_port: bool) -> Option<MySqlInfo> {
    let header = payload.get(..4)?;
    let length =
        usize::from(header[0]) | (usize::from(header[1]) << 8) | (usize::from(header[2]) << 16);
    if length > 16_384 {
        return None;
    }
    let body = payload.get(4..4 + length)?;
    if to_mysql_port && header[3] == 1 && body.len() == 32 {
        let flags = u16::from_le_bytes([body[0], body[1]]);
        if flags & (CLIENT_PROTOCOL_41 | CLIENT_SSL) == (CLIENT_PROTOCOL_41 | CLIENT_SSL)
            && body[9..].iter().all(|b| *b == 0)
        {
            return Some(MySqlInfo {
                tls_requested: true,
                ..Default::default()
            });
        }
    }
    if header[3] != 0 || body.first() != Some(&10) {
        return None;
    }
    let version_end = body.get(1..)?.iter().take(129).position(|b| *b == 0)? + 1;
    let version = &body[1..version_end];
    if !version.first()?.is_ascii_digit()
        || !version.contains(&b'.')
        || !version.iter().all(|b| b.is_ascii_graphic())
    {
        return None;
    }
    let fields = body.get(version_end + 1..)?;
    let base = fields.get(..15)?;
    if base[12] != 0 {
        return None;
    }
    let flags = u16::from_le_bytes([base[13], base[14]]);
    if flags & CLIENT_PROTOCOL_41 != 0 {
        // The first six reserved bytes are zero in both MySQL and MariaDB;
        // MariaDB may use the last four for extended capability flags.
        let extended = fields.get(..31)?;
        if !extended[21..27].iter().all(|b| *b == 0) {
            return None;
        }
        let mut tail = &fields[31..];
        // Validate the advertised authentication framing without retaining
        // either the scramble or plugin name.
        if flags & 0x8000 != 0 {
            let scramble_length = usize::from(extended[20]).saturating_sub(8).max(13);
            tail = tail.get(scramble_length..)?;
        }
        let plugin_auth = u16::from_le_bytes([extended[18], extended[19]]) & 8 != 0;
        if plugin_auth {
            let plugin = tail.strip_suffix(&[0])?;
            if plugin.is_empty() || plugin.len() > 128 || !plugin.iter().all(u8::is_ascii_graphic) {
                return None;
            }
        } else if !tail.is_empty() {
            return None;
        }
    } else if fields.len() != 15 {
        return None;
    }
    Some(MySqlInfo {
        server_version: Some(std::str::from_utf8(version).ok()?.to_owned()),
        connection_id: Some(u32::from_le_bytes(base[..4].try_into().ok()?)),
        tls_supported: Some(flags & CLIENT_SSL != 0),
        ..Default::default()
    })
}
