use ring::aead;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey};

use super::crypto::{
    InitialKeys, aes_ecb_encrypt, derive_client_initial_secret, derive_initial_keys,
};
use super::packet::{parse_long_header_packet_with_length, parse_quic_packet};
use crate::network::dpi::tls_common::test_fixtures::{RFC9001_CLIENT_HELLO, from_hex};
use crate::network::types::{QuicConnectionState, QuicPacketType, TlsVersion};

/// RFC 9001 Appendix A.2: the complete protected client Initial packet
/// (DCID 0x8394c8f03e515708, packet number 2, 1200 bytes).
const RFC9001_CLIENT_INITIAL: &str = "
    c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11
    d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399
    1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c
    8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212
    30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5
    457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208
    4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec
    4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3
    485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db
    059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c
    7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8
    9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556
    be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74
    68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a
    c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00
    f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632
    291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964
    25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd
    14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff
    ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198
    e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd
    c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73
    203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f
    cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e
    fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade
    a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047
    90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2
    162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4
    40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0
    6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e
    8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0
    be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400
    54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab
    760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9
    f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4
    056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064
    7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241
    e221af44860018ab0856972e194cd934";

/// RFC 9001 Appendix A.3: the protected server Initial packet
/// (zero-length DCID, SCID 0xf067a5502a4262b5).
const RFC9001_SERVER_INITIAL: &str = "
    cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a
    5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3
    dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84
    022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4
    2158407dd074ee";

/// RFC 9001 Appendix A.4: a Retry packet responding to the client Initial.
const RFC9001_RETRY: &str =
    "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba";

#[test]
fn test_rfc9001_a1_initial_key_derivation() {
    let dcid = from_hex("8394c8f03e515708");
    let client_secret = derive_client_initial_secret(&dcid, 1).expect("client secret");
    assert_eq!(
        client_secret.to_vec(),
        from_hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
    );

    let keys = derive_initial_keys(&client_secret, 1).expect("initial keys");
    assert_eq!(
        keys.key.to_vec(),
        from_hex("1f369613dd76d5467730efcbe3b1a22d")
    );
    assert_eq!(keys.iv.to_vec(), from_hex("fa044b2f42a3fd3b46fb255c"));
    assert_eq!(
        keys.hp.to_vec(),
        from_hex("9f50449e04a0e810283a1e9933adedd2")
    );
}

#[test]
fn test_rfc9001_a2_client_initial_end_to_end() {
    let packet = from_hex(RFC9001_CLIENT_INITIAL);
    assert_eq!(packet.len(), 1200);

    let info = parse_quic_packet(&packet).expect("client Initial should parse");
    assert_eq!(info.packet_type, QuicPacketType::Initial);
    assert_eq!(info.connection_state, QuicConnectionState::Initial);
    assert_eq!(info.connection_id, from_hex("8394c8f03e515708"));
    assert!(
        info.connection_id_hex.is_some(),
        "decrypted client Initial should be marked for connection tracking"
    );

    let tls = info
        .tls_info
        .expect("decryption should yield ClientHello TLS info");
    assert_eq!(tls.sni.as_deref(), Some("example.com"));
    assert_eq!(tls.alpn, vec!["alpn".to_string()]);
    assert_eq!(tls.version, Some(TlsVersion::Tls13));
}

#[test]
fn test_rfc9001_a3_server_initial_parses_without_tls() {
    let packet = from_hex(RFC9001_SERVER_INITIAL);

    let info = parse_quic_packet(&packet).expect("server Initial should parse");
    assert_eq!(info.packet_type, QuicPacketType::Initial);
    // The server Initial has a zero-length DCID; Initial keys derive from
    // the client's original DCID, which this packet does not carry, so no
    // TLS info can be extracted.
    assert!(info.connection_id.is_empty());
    assert!(info.tls_info.is_none());
}

#[test]
fn test_retry_packet_consumes_rest_of_datagram() {
    let retry = from_hex(RFC9001_RETRY);

    let (info, consumed) = parse_long_header_packet_with_length(&retry);
    let info = info.expect("Retry packet should parse");
    assert_eq!(info.packet_type, QuicPacketType::Retry);
    assert_eq!(
        consumed,
        retry.len(),
        "Retry has no Length field, must consume the whole datagram"
    );

    // Retry token bytes must not be misparsed as coalesced packets: a token
    // byte with the short-header bit pattern must not flip the connection
    // state to Connected.
    let mut datagram = retry.clone();
    datagram.extend_from_slice(&[0x42; 32]);
    let info = parse_quic_packet(&datagram).expect("datagram should parse");
    assert_eq!(info.packet_type, QuicPacketType::Retry);
    assert_eq!(info.connection_state, QuicConnectionState::Initial);
}

/// Protect (encrypt) a client Initial packet with a 4-byte packet number
/// the way a real client would, so tests can exercise decryption end to
/// end (RFC 9001 §5.3, §5.4).
fn protect_client_initial(dcid: &[u8], packet_number: u32, frames: &[u8]) -> Vec<u8> {
    let client_secret = derive_client_initial_secret(dcid, 1).expect("client secret");
    let InitialKeys { key, iv, hp } = derive_initial_keys(&client_secret, 1).expect("initial keys");

    let mut header = vec![0xc3]; // long header, Initial, pn_len = 4
    header.extend_from_slice(&1u32.to_be_bytes());
    header.push(dcid.len() as u8);
    header.extend_from_slice(dcid);
    header.push(0); // SCID len = 0
    header.push(0); // token length = 0
    let length = (4 + frames.len() + 16) as u16; // pn + frames + AEAD tag
    header.extend_from_slice(&(0x4000u16 | length).to_be_bytes());
    let pn_offset = header.len();
    header.extend_from_slice(&packet_number.to_be_bytes());

    let aead_key = LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, &key).unwrap());
    let mut nonce_bytes = iv;
    for i in 0..4 {
        nonce_bytes[11 - i] ^= ((u64::from(packet_number) >> (i * 8)) & 0xff) as u8;
    }
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut ciphertext = frames.to_vec();
    aead_key
        .seal_in_place_append_tag(nonce, Aad::from(&header), &mut ciphertext)
        .unwrap();

    // With a 4-byte packet number the header protection sample is the
    // first 16 bytes of the ciphertext.
    let mask = aes_ecb_encrypt(&hp, &ciphertext[..16]).unwrap();
    let mut packet = header;
    packet[0] ^= mask[0] & 0x0f;
    for i in 0..4 {
        packet[pn_offset + i] ^= mask[1 + i];
    }
    packet.extend_from_slice(&ciphertext);
    packet
}

/// A large ClientHello (e.g. with post-quantum key shares) is split
/// across multiple Initial packets that are coalesced into one datagram.
/// The CRYPTO fragments of every coalesced packet must be merged before
/// extracting the SNI - neither packet alone contains the full hostname.
#[test]
fn test_coalesced_initials_with_split_crypto_yield_sni() {
    let client_hello = from_hex(RFC9001_CLIENT_HELLO);

    // Split inside the SNI hostname so packet 1 alone cannot yield it
    let split = 60;
    let (part1, part2) = client_hello.split_at(split);

    let mut frames1 = vec![0x06, 0x00, part1.len() as u8]; // CRYPTO, offset 0
    frames1.extend_from_slice(part1);
    let mut frames2 = vec![0x06, split as u8]; // CRYPTO, offset 60
    frames2.extend_from_slice(&(0x4000u16 | part2.len() as u16).to_be_bytes());
    frames2.extend_from_slice(part2);

    let dcid = from_hex("8394c8f03e515708");
    let mut datagram = protect_client_initial(&dcid, 0, &frames1);
    datagram.extend_from_slice(&protect_client_initial(&dcid, 1, &frames2));

    let info = parse_quic_packet(&datagram).expect("coalesced datagram should parse");
    assert_eq!(info.packet_type, QuicPacketType::Initial);
    let tls = info
        .tls_info
        .expect("merged CRYPTO fragments should yield TLS info");
    assert_eq!(tls.sni.as_deref(), Some("example.com"));
    assert_eq!(tls.alpn, vec!["alpn".to_string()]);
}
