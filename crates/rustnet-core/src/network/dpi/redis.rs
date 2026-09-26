//! Bounded RESP command-array inspection. Arguments are validated as borrowed
//! slices and discarded; only HELLO's version and SELECT's index are retained.

use crate::network::types::RedisInfo;

pub(super) fn analyze_redis(payload: &[u8], to_redis_port: bool) -> Option<RedisInfo> {
    let mut rest = payload.strip_prefix(b"*")?;
    let count = number(&mut rest)?;
    if !(1..=128).contains(&count) {
        return None;
    }
    let mut command = &[][..];
    let mut argument = &[][..];
    for index in 0..count {
        rest = rest.strip_prefix(b"$")?;
        let length = number(&mut rest)?;
        // Per-message CPU is bounded even with large pipelined captures.
        if length > 16_384 {
            return None;
        }
        let value = rest.get(..length)?;
        rest = rest.get(length..)?.strip_prefix(b"\r\n")?;
        match index {
            0 => command = value,
            1 => argument = value,
            _ => {}
        }
    }
    if command.is_empty()
        || command.len() > 32
        || !command
            .iter()
            .all(|b| b.is_ascii_alphabetic() || *b == b'.' || *b == b'_')
    {
        return None;
    }
    let command = std::str::from_utf8(command).ok()?.to_ascii_uppercase();
    // On other ports require a known command as well as complete RESP framing.
    if !to_redis_port
        && !matches!(
            command.as_str(),
            "PING"
                | "ECHO"
                | "HELLO"
                | "AUTH"
                | "SELECT"
                | "GET"
                | "SET"
                | "DEL"
                | "MGET"
                | "MSET"
                | "EXISTS"
                | "EXPIRE"
                | "TTL"
                | "INCR"
                | "DECR"
                | "HGET"
                | "HSET"
                | "HGETALL"
                | "LPUSH"
                | "RPUSH"
                | "LPOP"
                | "RPOP"
                | "LRANGE"
                | "SADD"
                | "SMEMBERS"
                | "ZADD"
                | "ZRANGE"
                | "SCAN"
                | "SUBSCRIBE"
                | "PSUBSCRIBE"
                | "PUBLISH"
                | "UNSUBSCRIBE"
                | "MULTI"
                | "EXEC"
                | "DISCARD"
                | "WATCH"
                | "UNWATCH"
                | "INFO"
                | "CLIENT"
                | "COMMAND"
                | "QUIT"
                | "EVAL"
                | "EVALSHA"
                | "XADD"
                | "XREAD"
        )
    {
        return None;
    }
    let requested_version = if command == "HELLO" {
        match argument {
            b"2" => Some(2),
            b"3" => Some(3),
            _ => None,
        }
    } else {
        None
    };
    let requested_database = if command == "SELECT"
        && count == 2
        && !argument.is_empty()
        && argument.iter().all(u8::is_ascii_digit)
    {
        std::str::from_utf8(argument).ok()?.parse().ok()
    } else {
        None
    };
    Some(RedisInfo {
        command,
        requested_version,
        requested_database,
    })
}

fn number(bytes: &mut &[u8]) -> Option<usize> {
    let end = bytes.iter().take(11).position(|b| *b == b'\r')?;
    let digits = &bytes[..end];
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let result = std::str::from_utf8(digits).ok()?.parse().ok()?;
    *bytes = bytes.get(end..)?.strip_prefix(b"\r\n")?;
    Some(result)
}
