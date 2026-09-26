//! PostgreSQL protocol-3 startup and SSLRequest inspection. No query decoding.

use crate::network::types::PostgreSqlInfo;

pub(super) fn analyze_postgres(payload: &[u8]) -> Option<PostgreSqlInfo> {
    let length = u32::from_be_bytes(payload.get(..4)?.try_into().ok()?) as usize;
    if !(8..=16_384).contains(&length) {
        return None;
    }
    let message = payload.get(..length)?;
    let version = u32::from_be_bytes(message[4..8].try_into().ok()?);
    if length == 8 && version == 80_877_103 {
        return Some(PostgreSqlInfo {
            tls_requested: true,
            ..Default::default()
        });
    }
    if version >> 16 != 3 {
        return None;
    }
    let mut info = PostgreSqlInfo {
        protocol_minor: Some(version as u16),
        ..Default::default()
    };
    let mut rest = &message[8..];
    let mut has_user = false;
    for _ in 0..64 {
        if rest == [0] {
            return has_user.then_some(info);
        }
        let key = cstring(&mut rest)?;
        if key.is_empty() {
            return None;
        }
        let value = cstring(&mut rest)?;
        match key {
            b"user" => {
                // Required for identification, but deliberately not retained.
                if value.is_empty() || has_user {
                    return None;
                }
                has_user = true;
            }
            b"database" => info.database = metadata(value),
            b"application_name" => info.application_name = metadata(value),
            _ => {}
        }
    }
    None
}

fn cstring<'a>(bytes: &mut &'a [u8]) -> Option<&'a [u8]> {
    let end = bytes.iter().position(|b| *b == 0)?;
    let value = &bytes[..end];
    *bytes = &bytes[end + 1..];
    Some(value)
}

fn metadata(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || bytes.len() > 256 {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    (!text.chars().any(char::is_control)).then(|| text.to_owned())
}
