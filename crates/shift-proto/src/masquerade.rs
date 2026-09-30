use bytes::{Buf, BufMut, BytesMut};
use rand_core::{OsRng, RngCore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Result, ShiftError};

pub const RECORD_HEADER_LEN: usize = 5;
pub const MAX_RECORD_PAYLOAD: usize = 0x4000;

pub const RECORD_HANDSHAKE: u8 = 0x16;
pub const RECORD_APPLICATION_DATA: u8 = 0x17;
const LEGACY_RECORD_VERSION: [u8; 2] = [0x03, 0x03];
const CLIENT_HELLO_RECORD_VERSION: [u8; 2] = [0x03, 0x01];
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const LEGACY_CLIENT_VERSION: [u8; 2] = [0x03, 0x03];

const EXT_SERVER_NAME: u16 = 0;
const EXT_STATUS_REQUEST: u16 = 5;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_EC_POINT_FORMATS: u16 = 11;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_ALPN: u16 = 16;
const EXT_SCT: u16 = 18;
const EXT_SESSION_TICKET: u16 = 35;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;
const EXT_KEY_SHARE: u16 = 51;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

const GROUP_X25519: u16 = 0x001d;
const GROUP_SECP256R1: u16 = 0x0017;

const GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// Picks a random GREASE value per RFC 8701. Real TLS clients (Chrome,
/// Firefox, most mobile stacks) insert these reserved values at several
/// points in the ClientHello and change them on every connection, so their
/// *absence*, or a value that never changes, is itself a fingerprint.
fn random_grease() -> u16 {
    GREASE_VALUES[fastrand::usize(0..GREASE_VALUES.len())]
}

/// Two independent GREASE draws are used because real implementations
/// (BoringSSL, and Chrome/Firefox which build on similar logic) do not
/// reuse a single value everywhere: one covers the cipher suite, the
/// supported_groups entry, the supported_versions entry, and the leading
/// GREASE extension, while a second, separate one is used for the
/// GREASE key_share entry.
fn random_grease_pair() -> (u16, u16) {
    let a = random_grease();
    let mut b = random_grease();
    while b == a {
        b = random_grease();
    }
    (a, b)
}

/// Wraps `payload` in a single fake TLS 1.3 `application_data` record
/// header, so the byte shape on the wire matches genuine post-handshake
/// TLS traffic. `payload` must already be a complete Shift frame (or
/// handshake message); this function does not fragment it.
pub fn wrap_application_data(payload: &[u8], out: &mut BytesMut) -> Result<()> {
    if payload.len() > MAX_RECORD_PAYLOAD {
        return Err(ShiftError::InvalidFrame("record payload too large"));
    }
    out.reserve(RECORD_HEADER_LEN + payload.len());
    out.put_u8(RECORD_APPLICATION_DATA);
    out.put_slice(&LEGACY_RECORD_VERSION);
    out.put_u16(payload.len() as u16);
    out.put_slice(payload);
    Ok(())
}

/// Reads exactly one TLS record from `reader`: a 5-byte header followed by
/// its declared payload. Returns an error if the record type does not
/// match `expected_type` or the declared length exceeds `max_payload`.
pub async fn read_record<R>(
    reader: &mut R,
    expected_type: u8,
    max_payload: usize,
) -> std::io::Result<BytesMut>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; RECORD_HEADER_LEN];
    reader.read_exact(&mut header).await?;
    if header[0] != expected_type {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected TLS record type",
        ));
    }
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if len == 0 || len > max_payload {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TLS record length out of range",
        ));
    }
    let mut payload = BytesMut::with_capacity(len);
    payload.resize(len, 0);
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}

pub async fn write_application_data<W>(writer: &mut W, payload: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut out = BytesMut::new();
    wrap_application_data(payload, &mut out)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
    writer.write_all(&out).await
}

fn put_extension(out: &mut Vec<u8>, kind: u16, body: &[u8]) {
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
}

/// Builds a complete, spec-shaped TLS 1.3 ClientHello record for `sni`,
/// using a realistic Chrome-like extension set for camouflage. This is a
/// pure framing/shape exercise: the key share is never used for a real
/// ECDHE exchange, since Shift's own X25519+PSK handshake (see
/// `handshake.rs`) carries the real cryptographic authentication as the
/// very next record.
pub fn build_client_hello(sni: &str) -> Result<BytesMut> {
    if sni.is_empty() || sni.len() > 253 || !sni.is_ascii() {
        return Err(ShiftError::InvalidConfig(
            "camouflage SNI must be a short ASCII hostname",
        ));
    }

    let mut random = [0u8; 32];
    OsRng.fill_bytes(&mut random);
    let mut session_id = [0u8; 32];
    OsRng.fill_bytes(&mut session_id);
    let mut key_share_x25519 = [0u8; 32];
    OsRng.fill_bytes(&mut key_share_x25519);
    let mut grease_key_share_byte = [0u8; 1];
    OsRng.fill_bytes(&mut grease_key_share_byte);
    let (grease_a, grease_b) = random_grease_pair();

    let mut body = Vec::with_capacity(512);
    body.extend_from_slice(&LEGACY_CLIENT_VERSION);
    body.extend_from_slice(&random);
    body.push(session_id.len() as u8);
    body.extend_from_slice(&session_id);

    let cipher_suites: &[u16] = &[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030];
    body.extend_from_slice(&(((cipher_suites.len() + 1) * 2) as u16).to_be_bytes());
    body.extend_from_slice(&grease_a.to_be_bytes());
    for suite in cipher_suites {
        body.extend_from_slice(&suite.to_be_bytes());
    }

    body.push(1);
    body.push(0x00);

    let mut extensions = Vec::with_capacity(400);

    put_extension(&mut extensions, grease_a, &[]);

    let mut sni_body = Vec::with_capacity(sni.len() + 5);
    sni_body.extend_from_slice(&((sni.len() + 3) as u16).to_be_bytes());
    sni_body.push(0);
    sni_body.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    sni_body.extend_from_slice(sni.as_bytes());
    put_extension(&mut extensions, EXT_SERVER_NAME, &sni_body);

    put_extension(&mut extensions, EXT_EC_POINT_FORMATS, &[1, 0]);

    let groups: &[u16] = &[GROUP_X25519, GROUP_SECP256R1];
    let mut groups_body = Vec::with_capacity(2 + (groups.len() + 1) * 2);
    groups_body.extend_from_slice(&(((groups.len() + 1) * 2) as u16).to_be_bytes());
    groups_body.extend_from_slice(&grease_a.to_be_bytes());
    for group in groups {
        groups_body.extend_from_slice(&group.to_be_bytes());
    }
    put_extension(&mut extensions, EXT_SUPPORTED_GROUPS, &groups_body);

    put_extension(&mut extensions, EXT_SESSION_TICKET, &[]);

    let alpn: &[&[u8]] = &[b"h2", b"http/1.1"];
    let mut alpn_body = Vec::with_capacity(16);
    let protocols_len: usize = alpn.iter().map(|p| p.len() + 1).sum();
    alpn_body.extend_from_slice(&(protocols_len as u16).to_be_bytes());
    for proto in alpn {
        alpn_body.push(proto.len() as u8);
        alpn_body.extend_from_slice(proto);
    }
    put_extension(&mut extensions, EXT_ALPN, &alpn_body);

    put_extension(&mut extensions, EXT_STATUS_REQUEST, &[1, 0, 0, 0, 0]);

    let sig_algs: &[u16] = &[
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];
    let mut sig_body = Vec::with_capacity(2 + sig_algs.len() * 2);
    sig_body.extend_from_slice(&((sig_algs.len() * 2) as u16).to_be_bytes());
    for alg in sig_algs {
        sig_body.extend_from_slice(&alg.to_be_bytes());
    }
    put_extension(&mut extensions, EXT_SIGNATURE_ALGORITHMS, &sig_body);

    put_extension(&mut extensions, EXT_SCT, &[]);

    let mut key_share_body = Vec::with_capacity(46);
    key_share_body.extend_from_slice(&0u16.to_be_bytes());
    key_share_body.extend_from_slice(&grease_b.to_be_bytes());
    key_share_body.extend_from_slice(&(grease_key_share_byte.len() as u16).to_be_bytes());
    key_share_body.extend_from_slice(&grease_key_share_byte);
    key_share_body.extend_from_slice(&GROUP_X25519.to_be_bytes());
    key_share_body.extend_from_slice(&32u16.to_be_bytes());
    key_share_body.extend_from_slice(&key_share_x25519);
    let entries_len = (key_share_body.len() - 2) as u16;
    key_share_body[0..2].copy_from_slice(&entries_len.to_be_bytes());
    put_extension(&mut extensions, EXT_KEY_SHARE, &key_share_body);

    put_extension(&mut extensions, EXT_PSK_KEY_EXCHANGE_MODES, &[1, 1]);

    put_extension(
        &mut extensions,
        EXT_SUPPORTED_VERSIONS,
        &[
            4,
            grease_a.to_be_bytes()[0],
            grease_a.to_be_bytes()[1],
            0x03,
            0x04,
        ],
    );

    put_extension(&mut extensions, EXT_RENEGOTIATION_INFO, &[0]);

    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    if body.len() > 0xff_ffff {
        return Err(ShiftError::InvalidConfig("client hello body too large"));
    }
    let mut handshake = Vec::with_capacity(body.len() + 4);
    handshake.push(HANDSHAKE_CLIENT_HELLO);
    let body_len = body.len() as u32;
    handshake.extend_from_slice(&body_len.to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);

    if handshake.len() > MAX_RECORD_PAYLOAD {
        return Err(ShiftError::InvalidConfig(
            "client hello record too large to send unfragmented",
        ));
    }
    let mut record = BytesMut::with_capacity(RECORD_HEADER_LEN + handshake.len());
    record.put_u8(RECORD_HANDSHAKE);
    record.put_slice(&CLIENT_HELLO_RECORD_VERSION);
    record.put_u16(handshake.len() as u16);
    record.put_slice(&handshake);
    Ok(record)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedClientHello {
    pub server_name: Option<String>,
}

/// Parses the handshake-message bytes of a ClientHello (i.e. the payload
/// already stripped of the 5-byte record header) far enough to recover
/// the SNI. Does not validate cipher suites or key shares: any well-formed
/// ClientHello is accepted, since this is only used to pick a believable
/// fallback target, never as an authentication step.
pub fn parse_client_hello(mut msg: &[u8]) -> Result<ParsedClientHello> {
    let err = || ShiftError::InvalidFrame("malformed ClientHello");

    if msg.len() < 4 || msg[0] != HANDSHAKE_CLIENT_HELLO {
        return Err(err());
    }
    let declared = u32::from_be_bytes([0, msg[1], msg[2], msg[3]]) as usize;
    msg = &msg[4..];
    if msg.len() < declared {
        return Err(err());
    }
    let mut body = &msg[..declared];

    if body.len() < 2 + 32 + 1 {
        return Err(err());
    }
    body.advance(2 + 32);
    let session_id_len = body[0] as usize;
    body.advance(1);
    if body.len() < session_id_len {
        return Err(err());
    }
    body.advance(session_id_len);

    if body.len() < 2 {
        return Err(err());
    }
    let cipher_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    body.advance(2);
    if body.len() < cipher_len {
        return Err(err());
    }
    body.advance(cipher_len);

    if body.is_empty() {
        return Err(err());
    }
    let compression_len = body[0] as usize;
    body.advance(1);
    if body.len() < compression_len {
        return Err(err());
    }
    body.advance(compression_len);

    if body.is_empty() {
        return Ok(ParsedClientHello::default());
    }
    if body.len() < 2 {
        return Err(err());
    }
    let extensions_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    body.advance(2);
    if body.len() < extensions_len {
        return Err(err());
    }
    let mut extensions = &body[..extensions_len];

    let mut server_name = None;
    while extensions.len() >= 4 {
        let ext_type = u16::from_be_bytes([extensions[0], extensions[1]]);
        let ext_len = u16::from_be_bytes([extensions[2], extensions[3]]) as usize;
        extensions.advance(4);
        if extensions.len() < ext_len {
            return Err(err());
        }
        let ext_body = &extensions[..ext_len];
        if ext_type == EXT_SERVER_NAME {
            server_name = parse_server_name(ext_body);
        }
        extensions.advance(ext_len);
    }

    Ok(ParsedClientHello { server_name })
}

fn parse_server_name(mut ext_body: &[u8]) -> Option<String> {
    if ext_body.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([ext_body[0], ext_body[1]]) as usize;
    ext_body.advance(2);
    if ext_body.len() < list_len || list_len < 3 {
        return None;
    }
    let mut list = &ext_body[..list_len];
    if list[0] != 0 {
        return None;
    }
    list.advance(1);
    if list.len() < 2 {
        return None;
    }
    let name_len = u16::from_be_bytes([list[0], list[1]]) as usize;
    list.advance(2);
    if list.len() < name_len {
        return None;
    }
    std::str::from_utf8(&list[..name_len])
        .ok()
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_roundtrips_sni() {
        for sni in ["www.cloudflare.com", "example.org", "a.b-c.example"] {
            let record = build_client_hello(sni).unwrap();
            assert_eq!(record[0], RECORD_HANDSHAKE);
            let declared_len = u16::from_be_bytes([record[3], record[4]]) as usize;
            assert_eq!(declared_len, record.len() - RECORD_HEADER_LEN);

            let parsed = parse_client_hello(&record[RECORD_HEADER_LEN..]).unwrap();
            assert_eq!(parsed.server_name.as_deref(), Some(sni));
        }
    }

    #[test]
    fn client_hello_is_randomized_each_time() {
        let a = build_client_hello("example.com").unwrap();
        let b = build_client_hello("example.com").unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn client_hello_carries_grease_values() {
        let is_grease = |v: u16| (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff);
        for _ in 0..20 {
            let record = build_client_hello("example.com").unwrap();
            let msg = &record[RECORD_HEADER_LEN..];
            let declared = u32::from_be_bytes([0, msg[1], msg[2], msg[3]]) as usize;
            let mut body = &msg[4..4 + declared];
            body.advance(2 + 32);
            let sid_len = body[0] as usize;
            body.advance(1 + sid_len);
            let cipher_len = u16::from_be_bytes([body[0], body[1]]) as usize;
            let first_suite = u16::from_be_bytes([body[2], body[3]]);
            assert!(
                is_grease(first_suite),
                "first cipher suite should be GREASE"
            );
            body.advance(2 + cipher_len);
            body.advance(1 + body[0] as usize);
            let ext_len = u16::from_be_bytes([body[0], body[1]]) as usize;
            body.advance(2);
            let extensions = &body[..ext_len];
            let first_ext_type = u16::from_be_bytes([extensions[0], extensions[1]]);
            assert!(
                is_grease(first_ext_type),
                "first extension should be GREASE"
            );

            let mut cursor = extensions;
            let mut key_share_entries = 0;
            let mut groups_first_grease = false;
            while cursor.len() >= 4 {
                let ext_type = u16::from_be_bytes([cursor[0], cursor[1]]);
                let len = u16::from_be_bytes([cursor[2], cursor[3]]) as usize;
                let ext_body = &cursor[4..4 + len];
                if ext_type == EXT_KEY_SHARE {
                    let mut ks = &ext_body[2..];
                    while ks.len() >= 4 {
                        key_share_entries += 1;
                        let klen = u16::from_be_bytes([ks[2], ks[3]]) as usize;
                        ks = &ks[4 + klen..];
                    }
                }
                if ext_type == EXT_SUPPORTED_GROUPS {
                    let first_group = u16::from_be_bytes([ext_body[2], ext_body[3]]);
                    groups_first_grease = is_grease(first_group);
                }
                cursor = &cursor[4 + len..];
            }
            assert_eq!(
                key_share_entries, 2,
                "expected a GREASE + a real x25519 key_share entry"
            );
            assert!(
                groups_first_grease,
                "first supported_group should be GREASE"
            );
        }
    }

    #[test]
    fn rejects_bad_sni() {
        assert!(build_client_hello("").is_err());
        assert!(build_client_hello(&"a".repeat(300)).is_err());
        assert!(build_client_hello("café.example").is_err());
    }

    #[test]
    fn parser_rejects_truncated_input() {
        let record = build_client_hello("example.com").unwrap();
        let msg = &record[RECORD_HEADER_LEN..];
        for cut in 0..msg.len() {
            let _ = parse_client_hello(&msg[..cut]);
        }
        assert!(parse_client_hello(&msg[..4]).is_err());
        assert!(parse_client_hello(&[]).is_err());
        let mut wrong_type = msg.to_vec();
        wrong_type[0] = 0x02;
        assert!(parse_client_hello(&wrong_type).is_err());
    }

    #[test]
    fn parser_handles_no_extensions() {
        let mut msg = vec![HANDSHAKE_CLIENT_HELLO, 0, 0, 0];
        let mut body = Vec::new();
        body.extend_from_slice(&LEGACY_CLIENT_VERSION);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&0u16.to_be_bytes());
        body.push(0);
        let len = (body.len() as u32).to_be_bytes();
        msg[1..4].copy_from_slice(&len[1..]);
        msg.extend_from_slice(&body);
        let parsed = parse_client_hello(&msg).unwrap();
        assert_eq!(parsed.server_name, None);
    }

    #[tokio::test]
    async fn record_roundtrip_over_duplex() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        write_application_data(&mut a, b"hello shift")
            .await
            .unwrap();
        let payload = read_record(&mut b, RECORD_APPLICATION_DATA, 4096)
            .await
            .unwrap();
        assert_eq!(&payload[..], b"hello shift");
    }

    #[tokio::test]
    async fn record_reader_rejects_wrong_type() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        write_application_data(&mut a, b"payload").await.unwrap();
        assert!(read_record(&mut b, RECORD_HANDSHAKE, 4096).await.is_err());
    }

    #[tokio::test]
    async fn record_reader_rejects_oversized_declared_length() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        a.write_all(&[RECORD_APPLICATION_DATA, 3, 3, 0xff, 0xff])
            .await
            .unwrap();
        assert!(read_record(&mut b, RECORD_APPLICATION_DATA, 4096)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn multiple_records_stream_in_order() {
        let (mut a, mut b) = tokio::io::duplex(8192);
        for round in 0u8..10 {
            let payload = vec![round; 100 + round as usize * 13];
            write_application_data(&mut a, &payload).await.unwrap();
        }
        for round in 0u8..10 {
            let expected = vec![round; 100 + round as usize * 13];
            let got = read_record(&mut b, RECORD_APPLICATION_DATA, MAX_RECORD_PAYLOAD)
                .await
                .unwrap();
            assert_eq!(&got[..], &expected[..]);
        }
    }
}
