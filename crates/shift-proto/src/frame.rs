use bytes::{Buf, BufMut, BytesMut};

use crate::crypto::{DirectionState, SessionKeys, TAG_LEN};
use crate::{Result, ShiftError, INNER_HEADER_LEN, LENGTH_FIELD_LEN, MAX_BODY_LEN};

pub struct FrameEncoder {
    state: DirectionState,
}

impl FrameEncoder {
    pub fn new(state: DirectionState) -> Self {
        FrameEncoder { state }
    }

    pub fn max_payload(padding: usize) -> usize {
        MAX_BODY_LEN.saturating_sub(INNER_HEADER_LEN + padding)
    }

    pub fn encode(&mut self, payload: &[u8], padding: usize, dst: &mut BytesMut) -> Result<()> {
        let body_len = INNER_HEADER_LEN + payload.len() + padding;
        if body_len > MAX_BODY_LEN {
            return Err(ShiftError::FrameTooLarge {
                len: body_len,
                max: MAX_BODY_LEN,
            });
        }

        let wire_len = (body_len as u16 ^ self.state.length_mask()).to_be_bytes();
        let start = dst.len();
        dst.reserve(LENGTH_FIELD_LEN + body_len + TAG_LEN);
        dst.put_slice(&wire_len);
        dst.put_u16(payload.len() as u16);
        dst.put_u16(padding as u16);
        dst.put_slice(payload);
        dst.put_bytes(0, padding);

        let body_start = start + LENGTH_FIELD_LEN;
        match self
            .state
            .seal(&wire_len, &mut dst[body_start..body_start + body_len])
        {
            Ok(tag) => {
                dst.put_slice(&tag);
                Ok(())
            }
            Err(err) => {
                dst.truncate(start);
                Err(err)
            }
        }
    }

    pub fn encode_cover(&mut self, padding: usize, dst: &mut BytesMut) -> Result<()> {
        self.encode(&[], padding, dst)
    }
}

pub struct FrameDecoder {
    state: DirectionState,
    pending_body_len: Option<usize>,
    poisoned: bool,
}

impl FrameDecoder {
    pub fn new(state: DirectionState) -> Self {
        FrameDecoder {
            state,
            pending_body_len: None,
            poisoned: false,
        }
    }

    pub fn decode(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>> {
        if self.poisoned {
            return Err(ShiftError::InvalidFrame("decoder is poisoned"));
        }
        loop {
            let body_len = match self.pending_body_len {
                Some(len) => len,
                None => {
                    if src.len() < LENGTH_FIELD_LEN {
                        return Ok(None);
                    }
                    let masked = u16::from_be_bytes([src[0], src[1]]);
                    let len = (masked ^ self.state.length_mask()) as usize;
                    if !(INNER_HEADER_LEN..=MAX_BODY_LEN).contains(&len) {
                        self.poisoned = true;
                        return Err(ShiftError::InvalidFrame("body length out of range"));
                    }
                    self.pending_body_len = Some(len);
                    len
                }
            };

            let total = LENGTH_FIELD_LEN + body_len + TAG_LEN;
            if src.len() < total {
                src.reserve(total - src.len());
                return Ok(None);
            }
            self.pending_body_len = None;

            let mut frame = src.split_to(total);
            let aad = [frame[0], frame[1]];
            frame.advance(LENGTH_FIELD_LEN);
            let mut tag = [0u8; TAG_LEN];
            tag.copy_from_slice(&frame[body_len..]);
            frame.truncate(body_len);

            if let Err(err) = self.state.open(&aad, &mut frame[..], &tag) {
                self.poisoned = true;
                return Err(err);
            }

            let payload_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
            let padding_len = u16::from_be_bytes([frame[2], frame[3]]) as usize;
            if INNER_HEADER_LEN + payload_len + padding_len != body_len {
                self.poisoned = true;
                return Err(ShiftError::InvalidFrame("inner lengths do not match body"));
            }

            frame.advance(INNER_HEADER_LEN);
            frame.truncate(payload_len);
            if payload_len == 0 {
                continue;
            }
            return Ok(Some(frame));
        }
    }
}

pub fn codec_pair(keys: SessionKeys) -> (FrameEncoder, FrameDecoder) {
    let SessionKeys { send, recv, suite } = keys;
    (
        FrameEncoder::new(DirectionState::new(send, suite)),
        FrameDecoder::new(DirectionState::new(recv, suite)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CipherSuite, DirectionKeys};

    fn pair(suite: CipherSuite, rekey: Option<u64>) -> (FrameEncoder, FrameDecoder) {
        let keys = || DirectionKeys::new([5u8; 32], [6u8; 32]);
        let mut tx = DirectionState::new(keys(), suite);
        let mut rx = DirectionState::new(keys(), suite);
        if let Some(interval) = rekey {
            tx = tx.with_rekey_interval(interval);
            rx = rx.with_rekey_interval(interval);
        }
        (FrameEncoder::new(tx), FrameDecoder::new(rx))
    }

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    #[test]
    fn roundtrip_with_and_without_padding() {
        for suite in [CipherSuite::ChaCha20Poly1305, CipherSuite::Aes256Gcm] {
            let (mut enc, mut dec) = pair(suite, None);
            let mut wire = BytesMut::new();
            let sizes = [
                (1usize, 0usize),
                (100, 16),
                (1400, 0),
                (5, 127),
                (16380, 0),
                (10, 900),
            ];
            for (index, (len, pad)) in sizes.iter().enumerate() {
                enc.encode(&pattern(*len, index as u8), *pad, &mut wire)
                    .unwrap();
            }
            for (index, (len, _)) in sizes.iter().enumerate() {
                let got = dec.decode(&mut wire).unwrap().unwrap();
                assert_eq!(&got[..], &pattern(*len, index as u8)[..]);
            }
            assert!(dec.decode(&mut wire).unwrap().is_none());
            assert!(wire.is_empty());
        }
    }

    #[test]
    fn survives_byte_by_byte_delivery() {
        let (mut enc, mut dec) = pair(CipherSuite::ChaCha20Poly1305, None);
        let mut wire = BytesMut::new();
        for index in 0..8u8 {
            enc.encode(
                &pattern(200 + index as usize * 37, index),
                16 + index as usize,
                &mut wire,
            )
            .unwrap();
        }
        let raw = wire.to_vec();
        let mut inbound = BytesMut::new();
        let mut received = Vec::new();
        for byte in raw {
            inbound.put_u8(byte);
            while let Some(frame) = dec.decode(&mut inbound).unwrap() {
                received.push(frame.to_vec());
            }
        }
        assert_eq!(received.len(), 8);
        for (index, frame) in received.iter().enumerate() {
            assert_eq!(frame, &pattern(200 + index * 37, index as u8));
        }
    }

    #[test]
    fn cover_frames_are_skipped() {
        let (mut enc, mut dec) = pair(CipherSuite::ChaCha20Poly1305, None);
        let mut wire = BytesMut::new();
        enc.encode_cover(64, &mut wire).unwrap();
        enc.encode_cover(0, &mut wire).unwrap();
        enc.encode(b"real", 8, &mut wire).unwrap();
        enc.encode_cover(32, &mut wire).unwrap();
        let got = dec.decode(&mut wire).unwrap().unwrap();
        assert_eq!(&got[..], b"real");
        assert!(dec.decode(&mut wire).unwrap().is_none());
    }

    #[test]
    fn bit_flips_anywhere_are_detected() {
        let (mut enc, _) = pair(CipherSuite::ChaCha20Poly1305, None);
        let mut wire = BytesMut::new();
        enc.encode(&pattern(300, 1), 20, &mut wire).unwrap();
        let clean = wire.to_vec();
        for position in 0..clean.len() {
            let (_, mut dec) = pair(CipherSuite::ChaCha20Poly1305, None);
            let mut damaged = BytesMut::from(&clean[..]);
            damaged[position] ^= 0x80;
            let outcome = dec.decode(&mut damaged);
            assert!(
                matches!(outcome, Err(_) | Ok(None)),
                "flip at {position} produced data"
            );
        }
    }

    #[test]
    fn length_field_looks_different_each_frame() {
        let (mut enc, _) = pair(CipherSuite::ChaCha20Poly1305, None);
        let mut wire = BytesMut::new();
        for _ in 0..32 {
            enc.encode(&[7u8; 64], 0, &mut wire).unwrap();
        }
        let frame_len = LENGTH_FIELD_LEN + INNER_HEADER_LEN + 64 + TAG_LEN;
        let mut distinct = std::collections::HashSet::new();
        for chunk in wire.chunks(frame_len) {
            distinct.insert([chunk[0], chunk[1]]);
        }
        assert!(distinct.len() > 24);
    }

    #[test]
    fn oversized_frames_are_refused() {
        let (mut enc, _) = pair(CipherSuite::ChaCha20Poly1305, None);
        let mut wire = BytesMut::new();
        let err = enc
            .encode(&vec![0u8; MAX_BODY_LEN], 0, &mut wire)
            .unwrap_err();
        assert!(matches!(err, ShiftError::FrameTooLarge { .. }));
        assert!(wire.is_empty());
    }

    #[test]
    fn rekey_boundary_is_transparent() {
        let (mut enc, mut dec) = pair(CipherSuite::Aes256Gcm, Some(7));
        let mut wire = BytesMut::new();
        for index in 0..100u8 {
            enc.encode(
                &pattern(50 + index as usize, index),
                (index % 5) as usize,
                &mut wire,
            )
            .unwrap();
            let got = dec.decode(&mut wire).unwrap().unwrap();
            assert_eq!(&got[..], &pattern(50 + index as usize, index)[..]);
        }
    }

    #[test]
    fn replayed_frame_is_rejected() {
        let (mut enc, mut dec) = pair(CipherSuite::ChaCha20Poly1305, None);
        let mut wire = BytesMut::new();
        enc.encode(b"once", 4, &mut wire).unwrap();
        let copy = wire.clone();
        assert!(dec.decode(&mut wire).unwrap().is_some());
        let mut again = copy;
        assert!(!matches!(dec.decode(&mut again), Ok(Some(_))));
    }
}
