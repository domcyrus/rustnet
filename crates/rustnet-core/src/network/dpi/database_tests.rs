use super::{analyze_tcp_packet, mysql, postgres, redis};
use crate::network::filter::ConnectionFilter;
use crate::network::merge::{create_connection_from_packet, merge_packet_into_connection};
use crate::network::parser::ParsedPacket;
use crate::network::types::{ApplicationProtocol, Protocol, ProtocolState, TcpState};
use std::time::SystemTime;

fn mysql_frame(body: &[u8], sequence: u8) -> Vec<u8> {
    let length = (body.len() as u32).to_le_bytes();
    let mut frame = vec![length[0], length[1], length[2], sequence];
    frame.extend_from_slice(body);
    frame
}

fn greeting(version: &[u8]) -> Vec<u8> {
    let mut body = vec![10];
    body.extend_from_slice(version);
    body.push(0);
    body.extend_from_slice(&123u32.to_le_bytes());
    body.extend_from_slice(b"12345678"); // Scramble, never retained.
    body.push(0);
    body.extend_from_slice(&0x8a00u16.to_le_bytes()); // Protocol 4.1, SSL, secure connection.
    body.push(45); // utf8mb4 charset.
    body.extend_from_slice(&2u16.to_le_bytes()); // Autocommit.
    body.extend_from_slice(&8u16.to_le_bytes()); // Plugin authentication.
    body.push(21); // Scramble length.
    body.extend_from_slice(&[0; 10]);
    body.extend_from_slice(b"abcdefghijkl\0");
    body.extend_from_slice(b"caching_sha2_password\0");
    mysql_frame(&body, 0)
}

fn ssl_request() -> Vec<u8> {
    let mut body = vec![0; 32];
    body[..4].copy_from_slice(&0x0a00u32.to_le_bytes());
    body[8] = 45;
    mysql_frame(&body, 1)
}

fn startup(minor: u16, parameters: &[u8]) -> Vec<u8> {
    let mut frame = ((9 + parameters.len()) as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&(0x0003_0000 | u32::from(minor)).to_be_bytes());
    frame.extend_from_slice(parameters);
    frame.push(0);
    frame
}

fn resp(arguments: &[&[u8]]) -> Vec<u8> {
    let mut bytes = format!("*{}\r\n", arguments.len()).into_bytes();
    for argument in arguments {
        bytes.extend_from_slice(format!("${}\r\n", argument.len()).as_bytes());
        bytes.extend_from_slice(argument);
        bytes.extend_from_slice(b"\r\n");
    }
    bytes
}

#[test]
fn mysql_greeting_exposes_only_server_metadata_on_any_port() {
    for version in [b"8.4.0".as_slice(), b"5.5.5-11.4.2-MariaDB"] {
        let frame = greeting(version);
        let info = mysql::analyze_mysql(&frame, false).unwrap();
        assert_eq!(
            info.server_version.as_deref(),
            std::str::from_utf8(version).ok()
        );
        assert_eq!(info.connection_id, Some(123));
        assert_eq!(info.tls_supported, Some(true));
        assert!(!format!("{info:?}").contains("12345678"));
        assert!(!format!("{info:?}").contains("abcdefghijkl"));
        assert!(matches!(
            analyze_tcp_packet(&frame, 40_000, 33_060, false)
                .unwrap()
                .application,
            ApplicationProtocol::MySql(_)
        ));
        for end in 0..frame.len() {
            assert!(
                mysql::analyze_mysql(&frame[..end], true).is_none(),
                "prefix {end}"
            );
        }
        let mut coalesced = frame.clone();
        coalesced.extend_from_slice(b"ignored trailing data");
        assert_eq!(
            mysql::analyze_mysql(&coalesced, false)
                .unwrap()
                .connection_id,
            Some(123)
        );
    }
}

#[test]
fn mysql_rejects_bad_sequence_filler_version_and_incomplete_extended_fields() {
    let frame = greeting(b"8.4.0");
    for (offset, value) in [(3, 1), (4, 9), (5, b'X'), (23, 1), (31, 255), (32, 1)] {
        let mut bad = frame.clone();
        bad[offset] = value;
        assert!(
            mysql::analyze_mysql(&bad, false).is_none(),
            "offset {offset}"
        );
    }
    let body = &frame[4..];
    for end in 0..body.len() {
        assert!(mysql::analyze_mysql(&mysql_frame(&body[..end], 0), false).is_none());
    }
    assert!(mysql::analyze_mysql(&greeting(b"8.4.0\x1b[31m"), false).is_none());
    assert!(mysql::analyze_mysql(&[0xff, 0xff, 0xff, 0], false).is_none());
}

#[test]
fn mysql_ssl_request_requires_destination_port_and_exact_structure() {
    let request = ssl_request();
    assert!(mysql::analyze_mysql(&request, true).unwrap().tls_requested);
    assert!(mysql::analyze_mysql(&request, false).is_none());
    assert!(matches!(
        analyze_tcp_packet(&request, 3306, 40_000, false)
            .unwrap()
            .application,
        ApplicationProtocol::MySql(_)
    ));
    let mut bad = request;
    bad[13] = 1;
    assert!(mysql::analyze_mysql(&bad, true).is_none());
}

#[test]
fn postgres_startup_recognizes_protocol_3_minor_versions_and_bounds_fields() {
    let parameters = b"user\0private-user\0database\0inventory\0application_name\0psql\0options\0private-options\0";
    for minor in [0, 1, 2] {
        let frame = startup(minor, parameters);
        let info = postgres::analyze_postgres(&frame).unwrap();
        assert_eq!(info.protocol_minor, Some(minor));
        assert_eq!(info.database.as_deref(), Some("inventory"));
        assert_eq!(info.application_name.as_deref(), Some("psql"));
        assert!(!format!("{info:?}").contains("private"));
        assert!(matches!(
            analyze_tcp_packet(&frame, 40_000, 15_432, true)
                .unwrap()
                .application,
            ApplicationProtocol::PostgreSql(_)
        ));
        for end in 0..frame.len() {
            assert!(
                postgres::analyze_postgres(&frame[..end]).is_none(),
                "prefix {end}"
            );
        }
    }
    let frame = startup(0, b"user\0u\0database\0bad\x1b[31m\0");
    assert!(
        postgres::analyze_postgres(&frame)
            .unwrap()
            .database
            .is_none()
    );
    let mut parameters = b"user\0u\0application_name\0".to_vec();
    parameters.extend_from_slice(&[b'x'; 257]);
    parameters.push(0);
    assert!(
        postgres::analyze_postgres(&startup(0, &parameters))
            .unwrap()
            .application_name
            .is_none()
    );
}

#[test]
fn postgres_requires_user_and_terminated_pairs_and_rejects_other_message_types() {
    for parameters in [
        b"".as_slice(),
        b"user\0\0",
        b"database\0db\0",
        b"user\0u\0dangling",
        b"user\0u\0user\0v\0",
        b"user\0u\0\0trailing\0",
    ] {
        assert!(
            postgres::analyze_postgres(&startup(0, parameters)).is_none(),
            "{parameters:?}"
        );
    }
    for bytes in [
        b"Q\0\0\0\x0aselect\0".as_slice(),
        b"p\0\0\0\x0bsecret\0",
        b"S",
        b"N",
        &[0xff; 8],
        &[0; 8],
    ] {
        assert!(postgres::analyze_postgres(bytes).is_none());
    }
    let request = [0, 0, 0, 8, 4, 210, 22, 47];
    assert!(postgres::analyze_postgres(&request).unwrap().tls_requested);
    let mut not_ssl = request;
    not_ssl[7] = 46; // CancelRequest, not SSLRequest.
    assert!(postgres::analyze_postgres(&not_ssl).is_none());
}

#[test]
fn redis_validates_complete_arrays_and_keeps_only_command_and_numeric_metadata() {
    for arguments in [
        vec![b"AUTH".as_slice(), b"private-user", b"private-password"],
        vec![b"SET".as_slice(), b"private-key", b"private-value\0\r\n"],
        vec![
            b"HELLO".as_slice(),
            b"3",
            b"AUTH",
            b"private-user",
            b"private-password",
        ],
        vec![b"SELECT".as_slice(), b"2"],
    ] {
        let frame = resp(&arguments);
        let info = redis::analyze_redis(&frame, false).unwrap();
        assert!(!format!("{info:?}").contains("private"));
        assert_eq!(info.command.as_bytes(), arguments[0]);
        for end in 0..frame.len() {
            assert!(
                redis::analyze_redis(&frame[..end], true).is_none(),
                "prefix {end}"
            );
        }
        assert!(matches!(
            analyze_tcp_packet(&frame, 40_000, 16_379, true)
                .unwrap()
                .application,
            ApplicationProtocol::Redis(_)
        ));
    }
    assert_eq!(
        redis::analyze_redis(&resp(&[b"hello", b"3"]), false)
            .unwrap()
            .requested_version,
        Some(3)
    );
    assert_eq!(
        redis::analyze_redis(&resp(&[b"SELECT", b"2"]), false)
            .unwrap()
            .requested_database,
        Some(2)
    );
    assert_eq!(
        redis::analyze_redis(&resp(&[b"SELECT", b"999999999999"]), false)
            .unwrap()
            .requested_database,
        None
    );
    let mut pipeline = resp(&[b"PING"]);
    pipeline.extend_from_slice(&resp(&[b"AUTH", b"private-password"]));
    assert_eq!(
        redis::analyze_redis(&pipeline, false).unwrap().command,
        "PING"
    );
}

#[test]
fn redis_rejects_replies_inline_text_invalid_lengths_and_unknown_off_port_commands() {
    for frame in [
        b"+OK\r\n".as_slice(),
        b"GET / HTTP/1.1\r\n\r\n",
        b"PING\r\n",
        b"*0\r\n",
        b"*-1\r\n",
        b"*129\r\n",
        b"*1\r\n$-1\r\n",
        b"*1\r\n$999999999999\r\n",
        b"*1\r\n$4\r\nPING\n",
        b"*1\r\n$2\r\n\x1ba\r\n",
    ] {
        assert!(redis::analyze_redis(frame, true).is_none(), "{frame:?}");
    }
    let module_command = resp(&[b"JSON.GET", b"private-key"]);
    assert!(redis::analyze_redis(&module_command, false).is_none());
    assert_eq!(
        redis::analyze_redis(&module_command, true).unwrap().command,
        "JSON.GET"
    );
}

fn packet(payload: &[u8], server_port: u16, outgoing: bool) -> ParsedPacket {
    let mut parsed = ParsedPacket::test_base(
        Protocol::Tcp,
        "192.0.2.1:40000".parse().unwrap(),
        format!("192.0.2.2:{server_port}").parse().unwrap(),
        ProtocolState::Tcp(TcpState::Established),
    );
    parsed.is_outgoing = outgoing;
    parsed.dpi_result = analyze_tcp_packet(payload, 40_000, server_port, outgoing);
    parsed
}

#[test]
fn database_metadata_survives_merge_and_tls_upgrade_and_matches_filters() {
    let now = SystemTime::now();
    let mut mysql = create_connection_from_packet(&packet(&greeting(b"8.4.0"), 3306, false), now);
    merge_packet_into_connection(&mut mysql, &packet(&ssl_request(), 3306, true), now);
    let mut tls = packet(&[], 3306, true);
    tls.dpi_result = Some(super::DpiResult {
        application: ApplicationProtocol::Https(crate::network::types::HttpsInfo {
            tls_info: Some(crate::network::types::TlsInfo {
                sni: Some("db.example".into()),
                ..Default::default()
            }),
        }),
    });
    merge_packet_into_connection(&mut mysql, &tls, now);
    let ApplicationProtocol::MySql(info) = &mysql.dpi_info.as_ref().unwrap().application else {
        panic!()
    };
    assert_eq!(info.server_version.as_deref(), Some("8.4.0"));
    assert!(info.tls_requested);
    assert_eq!(mysql.authoritative_hostname(), Some("db.example"));
    assert!(ConnectionFilter::parse("app:mysql").matches(&mysql));

    let ssl = [0, 0, 0, 8, 4, 210, 22, 47];
    let mut pg = create_connection_from_packet(&packet(&ssl, 5432, true), now);
    merge_packet_into_connection(
        &mut pg,
        &packet(&startup(0, b"user\0u\0database\0inventory\0"), 5432, true),
        now,
    );
    tls.remote_addr.set_port(5432);
    merge_packet_into_connection(&mut pg, &tls, now);
    let ApplicationProtocol::PostgreSql(info) = &pg.dpi_info.as_ref().unwrap().application else {
        panic!()
    };
    assert!(info.tls_requested);
    assert_eq!(info.database.as_deref(), Some("inventory"));
    assert_eq!(pg.authoritative_hostname(), Some("db.example"));
    assert!(ConnectionFilter::parse("app:postgresql").matches(&pg));
    assert!(ConnectionFilter::parse("inventory").matches(&pg));

    let mut redis =
        create_connection_from_packet(&packet(&resp(&[b"HELLO", b"3"]), 6379, true), now);
    for command in [resp(&[b"SELECT", b"2"]), resp(&[b"GET", b"private-key"])] {
        merge_packet_into_connection(&mut redis, &packet(&command, 6379, true), now);
    }
    let ApplicationProtocol::Redis(info) = &redis.dpi_info.as_ref().unwrap().application else {
        panic!()
    };
    assert_eq!(info.command, "GET");
    assert_eq!(info.requested_version, Some(3));
    assert_eq!(info.requested_database, Some(2));
    assert!(ConnectionFilter::parse("app:redis").matches(&redis));
    assert!(!format!("{info:?}").contains("private-key"));
}

#[test]
fn unrelated_traffic_on_database_ports_is_not_database_dpi() {
    for port in [3306, 5432, 6379] {
        for payload in [
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".as_slice(),
            b"SSH-2.0-OpenSSH_9.0\r\n",
            &[0x16, 3, 3, 0, 4, 1, 0, 0, 0],
        ] {
            let info = analyze_tcp_packet(payload, 40_000, port, true).unwrap();
            assert!(!matches!(
                info.application,
                ApplicationProtocol::MySql(_)
                    | ApplicationProtocol::Redis(_)
                    | ApplicationProtocol::PostgreSql(_)
            ));
        }
    }
    let mut state = 0x12345678u32;
    for length in 0..512 {
        let bytes: Vec<u8> = (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        assert!(mysql::analyze_mysql(&bytes, true).is_none());
        assert!(postgres::analyze_postgres(&bytes).is_none());
        assert!(redis::analyze_redis(&bytes, true).is_none());
    }
}

#[test]
fn redis_server_reply_values_do_not_become_command_metadata() {
    let reply = resp(&[b"privatevalue", b"other-result"]);
    assert!(analyze_tcp_packet(&reply, 40_000, 6379, false).is_none());
    let reply = resp(&[b"SELECT", b"123"]);
    assert!(analyze_tcp_packet(&reply, 40_000, 6379, false).is_none());
    // An incoming request to a local Redis server is still recognized.
    let command = resp(&[b"JSON.GET", b"private-key"]);
    assert!(matches!(
        analyze_tcp_packet(&command, 6379, 40_000, false)
            .unwrap()
            .application,
        ApplicationProtocol::Redis(_)
    ));
}
