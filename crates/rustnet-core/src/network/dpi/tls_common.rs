//! TLS handshake parsing shared by the TCP (`https`) and QUIC (`quic::tls`)
//! DPI paths.
//!
//! Both transports carry the same TLS handshake messages; only the framing
//! differs (TLS record layer vs QUIC CRYPTO frames). Callers strip their
//! framing and hand this module a byte slice starting at the handshake
//! header. The remaining behavioural differences between the transports are
//! captured in [`TlsParseOptions`] rather than duplicated parser code.

use crate::network::types::{TlsInfo, TlsVersion};
use log::debug;

/// Maximum TLS extensions to parse. Defense-in-depth against crafted packets
/// with many zero-length extensions designed to waste CPU.
const MAX_TLS_EXTENSIONS: usize = 100;

/// Maximum plausible TLS handshake message length. Large enough for
/// post-quantum ClientHellos, which can exceed a single 16 KB TLS record.
const MAX_HANDSHAKE_LENGTH: usize = 65536;

/// Minimum length for partial SNI extraction
const PARTIAL_SNI_MIN_LENGTH: usize = 3;

/// Marker suffix for partial SNI values
const PARTIAL_SNI_MARKER: &str = "[PARTIAL]";

/// Which transport the handshake bytes came from. The transport decides the
/// policy differences that remain after unifying the two parsers.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::network::dpi) enum TlsTransport {
    /// TLS over TCP: the caller sees at most one record at a time, so
    /// truncated data can never be completed later.
    Tcp,
    /// TLS inside QUIC CRYPTO frames: the reassembler can wait for more
    /// bytes, so incomplete extensions are left for a later parse.
    Quic,
}

/// Per-call parsing policy.
#[derive(Clone, Copy)]
pub(in crate::network::dpi) struct TlsParseOptions {
    pub transport: TlsTransport,
    /// Whether truncated SNI/ALPN values may be emitted with
    /// [`PARTIAL_SNI_MARKER`] instead of being dropped.
    pub allow_partial: bool,
}

impl TlsParseOptions {
    pub(super) fn tcp() -> Self {
        Self {
            transport: TlsTransport::Tcp,
            allow_partial: true,
        }
    }

    pub(super) fn quic(allow_partial: bool) -> Self {
        Self {
            transport: TlsTransport::Quic,
            allow_partial,
        }
    }

    /// TCP parses whatever prefix of a truncated extension it has (more data
    /// will never arrive); QUIC stops and waits for the reassembler.
    fn clamp_truncated_extensions(&self) -> bool {
        self.transport == TlsTransport::Tcp
    }

    /// The legacy version fields are meaningful on TCP; QUIC is always
    /// TLS 1.3 and its legacy fields are frozen at 0x0303, so reading them
    /// would mislabel connections as TLS 1.2.
    fn use_legacy_version(&self) -> bool {
        self.transport == TlsTransport::Tcp
    }

    /// The supported_versions extension identifies a QUIC handshake as TLS
    /// 1.3. Older versions are invalid for QUIC, and newer versions cannot be
    /// represented by [`TlsVersion`].
    fn assume_tls13(&self) -> bool {
        self.transport == TlsTransport::Quic
    }

    /// Truncated ALPN protocol names are emitted with the partial marker on
    /// TCP; QUIC silently drops them and waits for reassembly.
    fn emit_partial_alpn(&self) -> bool {
        self.transport == TlsTransport::Tcp
    }
}

/// Validate if a string looks like a valid complete hostname.
///
/// Shared by every SNI extraction path: 4..=253 ASCII alphanumeric, '.' or
/// '-' characters, at least one dot and one letter, non-empty labels of at
/// most 63 characters, no leading/trailing '.' or '-'.
pub(in crate::network::dpi) fn is_valid_hostname(hostname: &str) -> bool {
    if hostname.len() < 4 || hostname.len() > 253 {
        return false;
    }

    if !hostname.contains('.') {
        return false;
    }

    if !hostname
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return false;
    }

    if hostname.starts_with('.')
        || hostname.ends_with('.')
        || hostname.starts_with('-')
        || hostname.ends_with('-')
    {
        return false;
    }

    if hostname.contains("..") {
        return false;
    }

    // Not just numbers and dots
    if !hostname.chars().any(|c| c.is_ascii_alphabetic()) {
        return false;
    }

    if !hostname
        .split('.')
        .all(|part| !part.is_empty() && part.len() <= 63)
    {
        return false;
    }

    true
}

/// Validate if a string looks like a valid partial hostname.
///
/// Relaxed rules because the value may be truncated: no dot or trailing
/// character requirements, only a minimum length and a valid character set.
fn is_valid_partial_hostname(hostname: &str) -> bool {
    if hostname.len() < PARTIAL_SNI_MIN_LENGTH {
        return false;
    }

    if !hostname
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return false;
    }

    if !hostname.chars().any(|c| c.is_ascii_alphabetic()) {
        return false;
    }

    if hostname.starts_with('.') || hostname.starts_with('-') {
        return false;
    }

    true
}

/// Mark an SNI value as partial by appending the marker
fn mark_partial_sni(hostname: &str) -> String {
    format!("{}{}", hostname, PARTIAL_SNI_MARKER)
}

/// Check if an SNI value is marked as partial
pub fn is_partial_sni(sni: &str) -> bool {
    sni.ends_with(PARTIAL_SNI_MARKER)
}

/// Parsed SNI extension header
pub(in crate::network::dpi) struct SniHeader {
    /// Server name list length
    pub list_len: u16,
    /// Hostname length
    pub name_len: u16,
}

/// Parse the SNI extension header from raw data
///
/// Expects data starting at the SNI extension content (after extension type and length):
/// - 2 bytes: server name list length
/// - 1 byte: name type (0x00 = hostname)
/// - 2 bytes: hostname length
///
/// Returns None if data is too short or name type is not hostname
pub(in crate::network::dpi) fn parse_sni_header(data: &[u8]) -> Option<SniHeader> {
    if data.len() < 5 {
        return None;
    }

    let list_len = u16::from_be_bytes([data[0], data[1]]);
    let name_type = data[2];
    let name_len = u16::from_be_bytes([data[3], data[4]]);

    // Name type must be 0x00 (hostname)
    if name_type != 0x00 {
        return None;
    }

    if name_len == 0 || name_len > 253 {
        return None;
    }

    Some(SniHeader { list_len, name_len })
}

pub(in crate::network::dpi) fn version_from_bytes(major: u8, minor: u8) -> Option<TlsVersion> {
    match (major, minor) {
        (0x03, 0x01) => Some(TlsVersion::Tls10),
        (0x03, 0x02) => Some(TlsVersion::Tls11),
        (0x03, 0x03) => Some(TlsVersion::Tls12),
        (0x03, 0x04) => Some(TlsVersion::Tls13),
        _ => None,
    }
}

fn version_to_priority(version: TlsVersion) -> u8 {
    match version {
        TlsVersion::Tls10 => 1,
        TlsVersion::Tls11 => 2,
        TlsVersion::Tls12 => 3,
        TlsVersion::Tls13 => 4,
    }
}

/// Parse a TLS handshake message into `info`.
///
/// `data[0]` must be the handshake type byte: the caller has already stripped
/// its framing (the 5-byte record header on TCP, CRYPTO frame reassembly on
/// QUIC). Fields already set on `info` (e.g. the record-layer version on TCP)
/// are only overwritten when the handshake provides better data.
///
/// Returns `true` if a supported handshake message (ClientHello/ServerHello)
/// was recognized and parsed, `false` otherwise; `info` is untouched in the
/// `false` case.
pub(in crate::network::dpi) fn parse_handshake(
    data: &[u8],
    info: &mut TlsInfo,
    opts: TlsParseOptions,
) -> bool {
    if data.len() < 4 {
        return false;
    }

    let handshake_type = data[0];
    let handshake_length = u32::from_be_bytes([0, data[1], data[2], data[3]]) as usize;

    if handshake_length > MAX_HANDSHAKE_LENGTH {
        debug!(
            "TLS: Handshake length {} seems too large, skipping",
            handshake_length
        );
        return false;
    }

    let available_data = &data[4..];
    let parse_length = handshake_length.min(available_data.len());
    if parse_length == 0 {
        return false;
    }

    match handshake_type {
        0x01 => {
            parse_client_hello(&available_data[..parse_length], info, opts);
            true
        }
        0x02 => {
            parse_server_hello(&available_data[..parse_length], info, opts);
            true
        }
        _ => false,
    }
}

fn parse_client_hello(data: &[u8], info: &mut TlsInfo, opts: TlsParseOptions) {
    // Legacy client version; the supported_versions extension overrides it.
    if opts.use_legacy_version()
        && data.len() >= 2
        && let Some(version) = version_from_bytes(data[0], data[1])
    {
        info.version = Some(version);
    }

    let Some(mut offset) = skip_hello_prefix(data) else {
        return;
    };

    // Cipher suites
    if offset + 2 > data.len() {
        return;
    }
    let cipher_suites_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2 + cipher_suites_len;

    // Compression methods
    if offset >= data.len() {
        return;
    }
    let compression_len = data[offset] as usize;
    offset += 1 + compression_len;

    parse_extensions_block(data, offset, info, true, opts);
}

/// Skip the fields shared by ClientHello and ServerHello: legacy version
/// (2 bytes), random (32 bytes) and session id (1 length byte plus the id).
/// Returns the offset of the first hello-specific field, or `None` if the
/// data ends inside the prefix.
fn skip_hello_prefix(data: &[u8]) -> Option<usize> {
    // Need at least version (2) + random (32)
    if data.len() < 34 {
        return None;
    }
    let offset = 34;

    // Session ID
    if offset >= data.len() {
        return None;
    }
    let session_id_len = data[offset] as usize;
    Some(offset + 1 + session_id_len)
}

/// Parse the extensions block at `offset` (u16 length followed by the
/// extensions), clamping the declared length to the data actually present.
fn parse_extensions_block(
    data: &[u8],
    offset: usize,
    info: &mut TlsInfo,
    is_client: bool,
    opts: TlsParseOptions,
) {
    if offset + 2 > data.len() {
        return;
    }
    let extensions_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    let offset = offset + 2;

    let available_ext_len = (data.len() - offset).min(extensions_len);
    if available_ext_len > 0 {
        parse_extensions(
            &data[offset..offset + available_ext_len],
            info,
            is_client,
            opts,
        );
    }
}

fn parse_server_hello(data: &[u8], info: &mut TlsInfo, opts: TlsParseOptions) {
    // Legacy server version. On TCP this intentionally overwrites the
    // record-layer version even when unparseable; the supported_versions
    // extension overrides it again.
    if opts.use_legacy_version() {
        if data.len() < 2 {
            return;
        }
        info.version = version_from_bytes(data[0], data[1]);
    }

    let Some(mut offset) = skip_hello_prefix(data) else {
        return;
    };

    // Cipher suite (2 bytes)
    if offset + 2 > data.len() {
        return;
    }
    let cipher = u16::from_be_bytes([data[offset], data[offset + 1]]);
    info.cipher_suite = Some(cipher);
    offset += 2;

    // Compression method (1 byte)
    if offset >= data.len() {
        return;
    }
    offset += 1;

    // Extensions (optional)
    parse_extensions_block(data, offset, info, false, opts);
}

fn parse_extensions(data: &[u8], info: &mut TlsInfo, is_client: bool, opts: TlsParseOptions) {
    let mut offset = 0;
    let mut extensions_parsed = 0;

    while offset + 4 <= data.len() {
        extensions_parsed += 1;
        if extensions_parsed > MAX_TLS_EXTENSIONS {
            break;
        }
        let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let ext_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;

        let available_ext_len = data.len() - offset - 4;
        if ext_len > available_ext_len && !opts.clamp_truncated_extensions() {
            // Extension data is incomplete and more may arrive later (QUIC).
            // Try to salvage a partial SNI before waiting for more data.
            if opts.allow_partial && ext_type == 0x0000 && is_client && available_ext_len > 5 {
                debug!(
                    "TLS: SNI extension is incomplete (need {} bytes, have {}), attempting partial extraction",
                    ext_len, available_ext_len
                );
                if let Some(sni) = parse_sni_extension(&data[offset + 4..], true) {
                    info.sni = Some(sni);
                }
            }
            break;
        }

        let ext_data_len = ext_len.min(available_ext_len);
        if ext_data_len > 0 {
            let ext_data = &data[offset + 4..offset + 4 + ext_data_len];

            match ext_type {
                0x0000 if is_client => {
                    // SNI (Server Name Indication)
                    if let Some(sni) = parse_sni_extension(ext_data, opts.allow_partial) {
                        info.sni = Some(sni);
                    }
                }
                0x0010 => {
                    // ALPN (Application-Layer Protocol Negotiation)
                    if let Some(alpn) = parse_alpn_extension(ext_data, opts.emit_partial_alpn()) {
                        info.alpn = alpn;
                    }
                }
                0x002b => {
                    // Supported Versions
                    if opts.assume_tls13() {
                        info.version = Some(TlsVersion::Tls13);
                    } else if let Some(version) = parse_supported_versions(ext_data, is_client) {
                        info.version = Some(version);
                    }
                }
                _ => {}
            }
        }

        // Move to next extension (use declared length, not actual)
        offset += 4 + ext_len;
    }
}

/// Parse SNI extension content (after the extension type/length header)
pub(in crate::network::dpi) fn parse_sni_extension(
    data: &[u8],
    allow_partial: bool,
) -> Option<String> {
    let header = parse_sni_header(data)?;

    let name_len = header.name_len as usize;
    let hostname_start = 5; // After header (2 + 1 + 2 bytes)

    if hostname_start + name_len <= data.len() {
        // Full hostname available
        let sni_data = &data[hostname_start..hostname_start + name_len];

        match std::str::from_utf8(sni_data) {
            Ok(sni) if is_valid_hostname(sni) => Some(sni.to_string()),
            Ok(sni) => {
                debug!("TLS: SNI doesn't look like a valid hostname: {}", sni);
                None
            }
            Err(e) => {
                debug!("TLS: SNI data is not valid UTF-8: {}", e);
                None
            }
        }
    } else if allow_partial && data.len() > hostname_start {
        let available = &data[hostname_start..];
        if let Ok(partial) = std::str::from_utf8(available)
            && is_valid_partial_hostname(partial)
        {
            return Some(mark_partial_sni(partial));
        }
        None
    } else {
        // SNI data is incomplete and partial extraction is not allowed
        None
    }
}

/// Parse ALPN extension content (after the extension type/length header)
///
/// `emit_partial` controls whether a protocol name truncated by the available
/// data is emitted with the partial marker or silently dropped.
pub(in crate::network::dpi) fn parse_alpn_extension(
    data: &[u8],
    emit_partial: bool,
) -> Option<Vec<String>> {
    if data.len() < 2 {
        return None;
    }

    let mut protocols = Vec::new();

    // ALPN list length
    let alpn_len = u16::from_be_bytes([data[0], data[1]]) as usize;

    let mut offset = 2;
    let list_end = 2 + alpn_len.min(data.len() - 2);

    while offset < list_end {
        let proto_len = data[offset] as usize;
        offset += 1;

        let actual_len = proto_len.min(list_end - offset);
        if actual_len > 0
            && let Ok(proto) = std::str::from_utf8(&data[offset..offset + actual_len])
        {
            if actual_len == proto_len {
                protocols.push(proto.to_string());
            } else if emit_partial {
                protocols.push(mark_partial_sni(proto));
            }
        }

        offset += proto_len;
    }

    if protocols.is_empty() {
        None
    } else {
        Some(protocols)
    }
}

/// Parse supported_versions extension content
///
/// Returns the best version actually observed in the extension, or None.
fn parse_supported_versions(data: &[u8], is_client: bool) -> Option<TlsVersion> {
    if is_client {
        // Client sends a list of supported versions
        if data.is_empty() {
            return None;
        }

        let list_len = data[0] as usize;
        let mut offset = 1;
        let mut best_version: Option<TlsVersion> = None;

        while offset + 1 < data.len() && offset < 1 + list_len {
            if let Some(version) = version_from_bytes(data[offset], data[offset + 1]) {
                best_version = match best_version {
                    None => Some(version),
                    Some(current) => {
                        if version_to_priority(version) > version_to_priority(current) {
                            Some(version)
                        } else {
                            Some(current)
                        }
                    }
                };
            }
            offset += 2;
        }

        best_version
    } else {
        // Server sends a single selected version
        if data.len() < 2 {
            return None;
        }
        version_from_bytes(data[0], data[1])
    }
}

/// TLS wire-format builders and fixtures shared by the TLS-family DPI tests
/// (`https`, `quic`): the QUIC parser reuses the SNI extension layout and both
/// transports exercise the RFC 9001 ClientHello, so they are encoded here.
#[cfg(test)]
pub(crate) mod test_fixtures {
    /// RFC 9001 Appendix A.2 ClientHello (the payload of the client Initial's
    /// CRYPTO frame, 241 bytes): SNI example.com, ALPN "alpn", TLS 1.3 via
    /// supported_versions.
    pub(crate) const RFC9001_CLIENT_HELLO: &str = "
        010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868
        04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578
        616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e
        0005000501000000000033002600
        24001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e9
        94ec74d748002b0003020304000d0010000e04030503060302030804080508
        06002d00020101001c00024001003900320408ffffffffffffffff0504800
        0ffff07048000ffff0801100104800075300901100f088394c8f03e5157080
        6048000ffff";

    /// Decode a hex string, ignoring whitespace
    pub(crate) fn from_hex(s: &str) -> Vec<u8> {
        let cleaned: Vec<u8> = s.bytes().filter(u8::is_ascii_hexdigit).collect();
        cleaned
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    /// Build a minimal SNI extension structure for `hostname`.
    pub(crate) fn build_sni_extension(hostname: &str) -> Vec<u8> {
        let name_len = hostname.len() as u16;
        let list_len = name_len + 3;
        let mut ext = Vec::new();
        ext.extend_from_slice(&0x0000u16.to_be_bytes()); // type: SNI
        ext.extend_from_slice(&(list_len + 2).to_be_bytes()); // extension length
        ext.extend_from_slice(&list_len.to_be_bytes());
        ext.push(0x00); // name type
        ext.extend_from_slice(&name_len.to_be_bytes());
        ext.extend_from_slice(hostname.as_bytes());
        ext
    }

    /// Build a hello handshake message (type + length header included): the
    /// shared prefix (legacy version TLS 1.2, zero random, empty session id),
    /// the hello-specific `middle` bytes, then the extensions block.
    fn build_hello(handshake_type: u8, middle: &[u8], extensions: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy version TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session id length
        body.extend_from_slice(middle);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);

        let mut msg = vec![handshake_type];
        msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        msg.extend_from_slice(&body);
        msg
    }

    /// Build a minimal ClientHello handshake message (type + length header
    /// included) carrying the given extensions blob.
    pub(crate) fn build_client_hello(extensions: &[u8]) -> Vec<u8> {
        // Cipher suites: length 2, TLS_AES_128_GCM_SHA256; compression
        // methods: length 1, null.
        build_hello(0x01, &[0x00, 0x02, 0x13, 0x01, 0x01, 0x00], extensions)
    }

    /// Build a minimal ServerHello handshake message (type + length header
    /// included) carrying the given extensions blob.
    pub(crate) fn build_server_hello(extensions: &[u8]) -> Vec<u8> {
        // Cipher suite TLS_AES_128_GCM_SHA256, null compression.
        build_hello(0x02, &[0x13, 0x01, 0x00], extensions)
    }
}

#[cfg(test)]
mod tests {
    use super::test_fixtures::{build_client_hello, build_server_hello, build_sni_extension};
    use super::*;

    #[test]
    fn test_partial_sni_extraction() {
        // Simulate a truncated SNI extension
        let partial_sni = vec![
            0x00, 0x10, // List length: 16
            0x00, // Name type: host_name
            0x00, 0x0d, // Name length: 13
            b'e', b'x', b'a', b'm', b'p', // Only 5 bytes of "example.com"
        ];

        let result = parse_sni_extension(&partial_sni, true);
        assert_eq!(result, Some("examp[PARTIAL]".to_string()));

        // Without allow_partial the truncated name is dropped
        assert_eq!(parse_sni_extension(&partial_sni, false), None);
    }

    #[test]
    fn test_partial_alpn_extraction() {
        // Simulate a truncated ALPN extension
        let partial_alpn = vec![
            0x00, 0x0e, // List length: 14
            0x08, b'h', b't', b't', b'p', // Only partial "http/1.1"
        ];

        let result = parse_alpn_extension(&partial_alpn, true);
        assert_eq!(result, Some(vec!["http[PARTIAL]".to_string()]));

        // QUIC-style parsing silently drops truncated protocols
        assert_eq!(parse_alpn_extension(&partial_alpn, false), None);
    }

    #[test]
    fn test_parse_sni_extension_complete() {
        // Build SNI extension data (without the extension type/length header)
        let hostname = "test.example.org";
        let name_bytes = hostname.as_bytes();
        let name_len = name_bytes.len() as u16;
        let list_len = name_len + 3;

        let mut data = Vec::new();
        data.extend_from_slice(&list_len.to_be_bytes());
        data.push(0x00); // name type
        data.extend_from_slice(&name_len.to_be_bytes());
        data.extend_from_slice(name_bytes);

        let result = parse_sni_extension(&data, false);
        assert_eq!(result, Some("test.example.org".to_string()));
    }

    #[test]
    fn test_parse_sni_extension_partial() {
        // Build partial SNI extension data
        let mut data = Vec::new();
        data.extend_from_slice(&20u16.to_be_bytes()); // list_len
        data.push(0x00); // name type
        data.extend_from_slice(&15u16.to_be_bytes()); // declared name_len
        data.extend_from_slice(b"example.co"); // only 10 chars

        // With allow_partial=false, returns None
        let result = parse_sni_extension(&data, false);
        assert_eq!(result, None);

        // With allow_partial=true, returns partial SNI
        let result = parse_sni_extension(&data, true);
        assert_eq!(result, Some("example.co[PARTIAL]".to_string()));
    }

    #[test]
    fn test_parse_alpn_extension() {
        // Build ALPN extension data (without the extension type/length header)
        let mut data = Vec::new();
        let protocols = vec!["h3", "h2"];

        let mut proto_list = Vec::new();
        for proto in &protocols {
            proto_list.push(proto.len() as u8);
            proto_list.extend_from_slice(proto.as_bytes());
        }

        data.extend_from_slice(&(proto_list.len() as u16).to_be_bytes());
        data.extend_from_slice(&proto_list);

        let result = parse_alpn_extension(&data, false);
        assert_eq!(result, Some(vec!["h3".to_string(), "h2".to_string()]));
    }

    #[test]
    fn test_is_valid_hostname() {
        assert!(is_valid_hostname("example.com"));
        assert!(is_valid_hostname("www.example.com"));
        assert!(is_valid_hostname("sub.domain.example.org"));
        assert!(is_valid_hostname("my-site.io"));

        // Invalid hostnames
        assert!(!is_valid_hostname("com")); // No dot
        assert!(!is_valid_hostname(".example.com")); // Starts with dot
        assert!(!is_valid_hostname("example.com.")); // Ends with dot
        assert!(!is_valid_hostname("-example.com")); // Starts with hyphen
        assert!(!is_valid_hostname("example..com")); // Consecutive dots
        assert!(!is_valid_hostname("ab")); // Too short
    }

    #[test]
    fn test_truncated_extension_clamp_vs_wait() {
        // One SNI extension whose declared length exceeds the available data:
        // TCP clamps and parses the prefix (partial SNI), QUIC waits.
        let mut ext = build_sni_extension("www.example.com");
        ext.truncate(ext.len() - 6); // cut into the hostname
        // Restore nothing: declared lengths still claim the full name.
        let msg = build_client_hello(&ext);

        let mut tcp_info = TlsInfo::new();
        assert!(parse_handshake(&msg, &mut tcp_info, TlsParseOptions::tcp()));
        assert_eq!(tcp_info.sni, Some("www.examp[PARTIAL]".to_string()));

        let mut quic_wait = TlsInfo::new();
        assert!(parse_handshake(
            &msg,
            &mut quic_wait,
            TlsParseOptions::quic(false)
        ));
        assert_eq!(quic_wait.sni, None);

        let mut quic_partial = TlsInfo::new();
        assert!(parse_handshake(
            &msg,
            &mut quic_partial,
            TlsParseOptions::quic(true)
        ));
        assert_eq!(quic_partial.sni, Some("www.examp[PARTIAL]".to_string()));
    }

    #[test]
    fn test_extension_count_cap() {
        // 200 zero-length grease-like extensions before the SNI: the cap
        // stops parsing before the SNI is reached on both transports.
        let mut ext = Vec::new();
        for _ in 0..200 {
            ext.extend_from_slice(&0xffffu16.to_be_bytes());
            ext.extend_from_slice(&0u16.to_be_bytes());
        }
        ext.extend_from_slice(&build_sni_extension("www.example.com"));
        let msg = build_client_hello(&ext);

        for opts in [TlsParseOptions::tcp(), TlsParseOptions::quic(true)] {
            let mut info = TlsInfo::new();
            assert!(parse_handshake(&msg, &mut info, opts));
            assert_eq!(info.sni, None);
        }
    }

    #[test]
    fn test_large_handshake_accepted() {
        // A ClientHello larger than 16 KB (post-quantum key shares get close
        // to this) must still parse.
        let mut ext = build_sni_extension("www.example.com");
        let padding_len = 20_000u16;
        ext.extend_from_slice(&0x0015u16.to_be_bytes()); // padding extension
        ext.extend_from_slice(&padding_len.to_be_bytes());
        ext.extend_from_slice(&vec![0u8; padding_len as usize]);
        let msg = build_client_hello(&ext);
        assert!(msg.len() > 16384);

        let mut info = TlsInfo::new();
        assert!(parse_handshake(&msg, &mut info, TlsParseOptions::tcp()));
        assert_eq!(info.sni, Some("www.example.com".to_string()));
    }

    /// Parse `msg` on both transports: QUIC must report TLS 1.3 from the
    /// supported_versions extension regardless of its value, while TCP falls
    /// back to the legacy version (TLS 1.2) from the hello body.
    fn assert_quic_tls13_tcp_tls12(msg: &[u8]) {
        let mut quic_info = TlsInfo::new();
        assert!(parse_handshake(
            msg,
            &mut quic_info,
            TlsParseOptions::quic(false)
        ));
        assert_eq!(quic_info.version, Some(TlsVersion::Tls13));

        let mut tcp_info = TlsInfo::new();
        assert!(parse_handshake(msg, &mut tcp_info, TlsParseOptions::tcp()));
        assert_eq!(tcp_info.version, Some(TlsVersion::Tls12));
    }

    #[test]
    fn test_supported_versions_assume_tls13_on_quic() {
        // supported_versions extension present but with an unrecognized
        // version: QUIC assumes TLS 1.3, TCP reports nothing from it.
        let mut ext = Vec::new();
        ext.extend_from_slice(&0x002bu16.to_be_bytes());
        ext.extend_from_slice(&3u16.to_be_bytes());
        ext.push(2); // list length
        ext.extend_from_slice(&[0x7f, 0x1c]); // a draft version
        assert_quic_tls13_tcp_tls12(&build_client_hello(&ext));
    }

    #[test]
    fn test_quic_client_supported_versions_reports_tls13_for_older_value() {
        let extensions = [
            0x00, 0x2b, // supported_versions
            0x00, 0x03, // extension length
            0x02, // version list length
            0x03, 0x03, // TLS 1.2, invalid for QUIC
        ];
        assert_quic_tls13_tcp_tls12(&build_client_hello(&extensions));
    }

    #[test]
    fn test_quic_server_supported_versions_reports_tls13_for_older_value() {
        let extensions = [
            0x00, 0x2b, // supported_versions
            0x00, 0x02, // extension length
            0x03, 0x03, // TLS 1.2, invalid for QUIC
        ];
        assert_quic_tls13_tcp_tls12(&build_server_hello(&extensions));
    }

    #[test]
    fn test_legacy_version_ignored_on_quic() {
        // No supported_versions extension: TCP reads the legacy version,
        // QUIC leaves it unset instead of mislabeling as TLS 1.2.
        let msg = build_client_hello(&build_sni_extension("www.example.com"));

        let mut tcp_info = TlsInfo::new();
        assert!(parse_handshake(&msg, &mut tcp_info, TlsParseOptions::tcp()));
        assert_eq!(tcp_info.version, Some(TlsVersion::Tls12));

        let mut quic_info = TlsInfo::new();
        assert!(parse_handshake(
            &msg,
            &mut quic_info,
            TlsParseOptions::quic(false)
        ));
        assert_eq!(quic_info.version, None);
        assert_eq!(quic_info.sni, Some("www.example.com".to_string()));
    }
}
