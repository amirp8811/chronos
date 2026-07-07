//! CHRONOS v7 local handshake packet flow.
//!
//! This module turns the X25519, ML-KEM-768, HKDF, and key-store primitives into
//! a concrete handshake transcript with downgrade protection and key
//! confirmation. It is intentionally small and deterministic at the packet layer:
//! cryptographic randomness is provided by ML-KEM encapsulation and node keys.

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use hkdf::Hkdf;
use ml_kem::{EncapsulationKey, MlKem768, kem::KeyExport};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::handshake::{X25519NodePublic, X25519NodeSecret};
use crate::hybrid_route::{MlKem768Ciphertext, encapsulate_route_secret};
use crate::key_store::NodeKeyMaterial;
use crate::pow_admission::{PowAdmissionError, PowChallenge};
use crate::route_layer::RouteHopSecret;

pub const HANDSHAKE_MAGIC: [u8; 4] = *b"CHS7";
pub const HANDSHAKE_VERSION: u8 = 1;
pub const HANDSHAKE_SUITE_MLKEM768_X25519_CHACHA20POLY1305: u8 = 1;
pub const KEY_CONFIRM_SIZE: usize = 32;
pub const MLKEM768_PUBLIC_KEY_BYTES: usize = 1184;
pub const MLKEM768_CIPHERTEXT_BYTES: usize = 1088;
pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;
pub const ED25519_SIGNATURE_BYTES: usize = 64;
pub const SERVER_HELLO_PAYLOAD_BYTES: usize =
    32 + MLKEM768_PUBLIC_KEY_BYTES + ED25519_PUBLIC_KEY_BYTES + ED25519_SIGNATURE_BYTES;
pub const CLIENT_KEY_SHARE_PAYLOAD_BYTES: usize = 32 + MLKEM768_CIPHERTEXT_BYTES;
const HANDSHAKE_CONFIRM_INFO: &[u8] = b"chronos-v7/handshake/key-confirmation";

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakePacketType {
    ServerHello = 1,
    ClientKeyShare = 2,
    ServerKeyConfirm = 3,
    Error = 4,
    PowChallenge = 5,
    PowSolution = 6,
}

impl TryFrom<u8> for HandshakePacketType {
    type Error = HandshakeError;

    fn try_from(value: u8) -> Result<Self, HandshakeError> {
        match value {
            1 => Ok(Self::ServerHello),
            2 => Ok(Self::ClientKeyShare),
            3 => Ok(Self::ServerKeyConfirm),
            4 => Ok(Self::Error),
            5 => Ok(Self::PowChallenge),
            6 => Ok(Self::PowSolution),
            other => Err(HandshakeError::UnknownPacketType(other)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    InvalidLength {
        declared: usize,
        available: usize,
    },
    PayloadTooLarge {
        got: usize,
        max: usize,
    },
    InvalidMagic,
    UnsupportedVersion(u8),
    UnsupportedSuite(u8),
    UnknownPacketType(u8),
    WrongPacketType {
        expected: HandshakePacketType,
        got: HandshakePacketType,
    },
    InvalidPublicKey,
    InvalidSignature,
    IdentityMismatch,
    InvalidCiphertext,
    KeyDerivation,
    KeyConfirmationFailed,
    Pow(PowAdmissionError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakePacket {
    pub packet_type: HandshakePacketType,
    pub suite: u8,
    pub payload: Vec<u8>,
}

impl HandshakePacket {
    pub fn new(packet_type: HandshakePacketType, payload: Vec<u8>) -> Result<Self, HandshakeError> {
        if payload.len() > u16::MAX as usize {
            return Err(HandshakeError::PayloadTooLarge {
                got: payload.len(),
                max: u16::MAX as usize,
            });
        }
        Ok(Self {
            packet_type,
            suite: HANDSHAKE_SUITE_MLKEM768_X25519_CHACHA20POLY1305,
            payload,
        })
    }

    pub fn pow_challenge(challenge: &PowChallenge) -> Result<Self, HandshakeError> {
        let mut payload = Vec::with_capacity(60);
        payload.extend_from_slice(&challenge.relay_id);
        payload.extend_from_slice(&challenge.unix_window.to_be_bytes());
        payload.extend_from_slice(&challenge.difficulty_zero_bits.to_be_bytes());
        payload.extend_from_slice(&challenge.token);
        Self::new(HandshakePacketType::PowChallenge, payload)
    }

    pub fn decode_pow_challenge(&self) -> Result<PowChallenge, HandshakeError> {
        if self.packet_type != HandshakePacketType::PowChallenge {
            return Err(HandshakeError::WrongPacketType {
                expected: HandshakePacketType::PowChallenge,
                got: self.packet_type,
            });
        }
        if self.payload.len() != 60 {
            return Err(HandshakeError::InvalidLength {
                declared: 60,
                available: self.payload.len(),
            });
        }
        let mut relay_id = [0u8; 16];
        relay_id.copy_from_slice(&self.payload[0..16]);
        let unix_window = u64::from_be_bytes(self.payload[16..24].try_into().expect("fixed slice"));
        let difficulty_zero_bits =
            u32::from_be_bytes(self.payload[24..28].try_into().expect("fixed slice"));
        let mut token = [0u8; 32];
        token.copy_from_slice(&self.payload[28..60]);
        Ok(PowChallenge {
            relay_id,
            unix_window,
            difficulty_zero_bits,
            token,
        })
    }

    pub fn pow_solution(nonce: Vec<u8>) -> Result<Self, HandshakeError> {
        Self::new(HandshakePacketType::PowSolution, nonce)
    }

    pub fn encode(&self) -> Result<Vec<u8>, HandshakeError> {
        if self.payload.len() > u16::MAX as usize {
            return Err(HandshakeError::PayloadTooLarge {
                got: self.payload.len(),
                max: u16::MAX as usize,
            });
        }
        let mut out = Vec::with_capacity(10 + self.payload.len());
        out.extend_from_slice(&HANDSHAKE_MAGIC);
        out.push(HANDSHAKE_VERSION);
        out.push(self.packet_type as u8);
        out.push(self.suite);
        out.push(0); // reserved
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, HandshakeError> {
        if bytes.len() < 10 {
            return Err(HandshakeError::InvalidLength {
                declared: 10,
                available: bytes.len(),
            });
        }
        if bytes[0..4] != HANDSHAKE_MAGIC {
            return Err(HandshakeError::InvalidMagic);
        }
        if bytes[4] != HANDSHAKE_VERSION {
            return Err(HandshakeError::UnsupportedVersion(bytes[4]));
        }
        let packet_type = HandshakePacketType::try_from(bytes[5])?;
        let suite = bytes[6];
        if suite != HANDSHAKE_SUITE_MLKEM768_X25519_CHACHA20POLY1305 {
            return Err(HandshakeError::UnsupportedSuite(suite));
        }
        if bytes[7] != 0 {
            return Err(HandshakeError::InvalidLength {
                declared: 0,
                available: bytes[7] as usize,
            });
        }
        let declared = u16::from_be_bytes(bytes[8..10].try_into().expect("fixed slice")) as usize;
        let available = bytes.len() - 10;
        if declared != available {
            return Err(HandshakeError::InvalidLength {
                declared,
                available,
            });
        }
        Ok(Self {
            packet_type,
            suite,
            payload: bytes[10..].to_vec(),
        })
    }
}

fn ensure_supported_suite(packet: &HandshakePacket) -> Result<(), HandshakeError> {
    if packet.suite != HANDSHAKE_SUITE_MLKEM768_X25519_CHACHA20POLY1305 {
        return Err(HandshakeError::UnsupportedSuite(packet.suite));
    }
    Ok(())
}

#[derive(Clone)]
pub struct HandshakePublicKeys {
    pub x25519_public: X25519NodePublic,
    pub ml_kem_public: EncapsulationKey<MlKem768>,
    pub identity_public: [u8; 32],
    pub signature: [u8; 64],
}

impl HandshakePublicKeys {
    pub fn from_node_keys(keys: &NodeKeyMaterial) -> Self {
        let x25519_public = keys.x25519.public();
        let ml_kem_public = keys.ml_kem_768.encapsulation_key.clone();
        let identity_public = keys.identity_signing.verifying_key().to_bytes();
        let signature = sign_server_hello_fields(
            &x25519_public,
            &ml_kem_public,
            &identity_public,
            &keys.identity_signing,
        );
        Self {
            x25519_public,
            ml_kem_public,
            identity_public,
            signature,
        }
    }

    pub fn unsigned_for_tests(
        x25519_public: X25519NodePublic,
        ml_kem_public: EncapsulationKey<MlKem768>,
    ) -> Self {
        Self {
            x25519_public,
            ml_kem_public,
            identity_public: [0u8; 32],
            signature: [0u8; 64],
        }
    }

    pub fn to_server_hello_packet(&self) -> Result<HandshakePacket, HandshakeError> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&self.x25519_public.0);
        payload.extend_from_slice(self.ml_kem_public.to_bytes().as_ref());
        payload.extend_from_slice(&self.identity_public);
        payload.extend_from_slice(&self.signature);
        HandshakePacket::new(HandshakePacketType::ServerHello, payload)
    }

    pub fn from_server_hello_packet_for_identity(
        packet: &HandshakePacket,
        expected_identity: &[u8; 32],
    ) -> Result<Self, HandshakeError> {
        let parsed = Self::from_server_hello_packet(packet)?;
        if &parsed.identity_public != expected_identity {
            return Err(HandshakeError::IdentityMismatch);
        }
        Ok(parsed)
    }

    pub fn from_server_hello_packet(packet: &HandshakePacket) -> Result<Self, HandshakeError> {
        ensure_supported_suite(packet)?;
        if packet.packet_type != HandshakePacketType::ServerHello {
            return Err(HandshakeError::WrongPacketType {
                expected: HandshakePacketType::ServerHello,
                got: packet.packet_type,
            });
        }
        if packet.payload.len() != SERVER_HELLO_PAYLOAD_BYTES {
            return Err(HandshakeError::InvalidLength {
                declared: SERVER_HELLO_PAYLOAD_BYTES,
                available: packet.payload.len(),
            });
        }
        let mut x = [0u8; 32];
        x.copy_from_slice(&packet.payload[..32]);
        let kem_start = 32;
        let kem_end = kem_start + MLKEM768_PUBLIC_KEY_BYTES;
        let id_start = kem_end;
        let sig_start = id_start + ED25519_PUBLIC_KEY_BYTES;
        let key_bytes = ml_kem::kem::Key::<EncapsulationKey<MlKem768>>::try_from(
            &packet.payload[kem_start..kem_end],
        )
        .map_err(|_| HandshakeError::InvalidPublicKey)?;
        let ml_kem_public = EncapsulationKey::<MlKem768>::new(&key_bytes)
            .map_err(|_| HandshakeError::InvalidPublicKey)?;
        let mut identity_public = [0u8; 32];
        identity_public.copy_from_slice(&packet.payload[id_start..sig_start]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&packet.payload[sig_start..sig_start + ED25519_SIGNATURE_BYTES]);
        verify_server_hello_signature(
            &X25519NodePublic(x),
            &ml_kem_public,
            &identity_public,
            &signature,
        )?;
        Ok(Self {
            x25519_public: X25519NodePublic(x),
            ml_kem_public,
            identity_public,
            signature,
        })
    }
}

fn server_hello_signing_message(
    x25519_public: &X25519NodePublic,
    ml_kem_public: &EncapsulationKey<MlKem768>,
    identity_public: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"CHS7 server hello identity signature v1");
    msg.push(HANDSHAKE_VERSION);
    msg.push(HANDSHAKE_SUITE_MLKEM768_X25519_CHACHA20POLY1305);
    msg.extend_from_slice(&x25519_public.0);
    msg.extend_from_slice(ml_kem_public.to_bytes().as_ref());
    msg.extend_from_slice(identity_public);
    msg
}

fn sign_server_hello_fields(
    x25519_public: &X25519NodePublic,
    ml_kem_public: &EncapsulationKey<MlKem768>,
    identity_public: &[u8; 32],
    signing_key: &ed25519_dalek::SigningKey,
) -> [u8; 64] {
    signing_key
        .sign(&server_hello_signing_message(
            x25519_public,
            ml_kem_public,
            identity_public,
        ))
        .to_bytes()
}

fn verify_server_hello_signature(
    x25519_public: &X25519NodePublic,
    ml_kem_public: &EncapsulationKey<MlKem768>,
    identity_public: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), HandshakeError> {
    let vk =
        VerifyingKey::from_bytes(identity_public).map_err(|_| HandshakeError::InvalidPublicKey)?;
    let sig = Signature::from_bytes(signature);
    vk.verify(
        &server_hello_signing_message(x25519_public, ml_kem_public, identity_public),
        &sig,
    )
    .map_err(|_| HandshakeError::InvalidSignature)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHandshakeState {
    pub route_secret: RouteHopSecret,
    transcript_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHandshakeState {
    pub route_secret: RouteHopSecret,
    transcript_hash: [u8; 32],
}

pub fn client_begin_handshake(
    server_hello: &HandshakePacket,
    client_x25519: &X25519NodeSecret,
) -> Result<(HandshakePacket, ClientHandshakeState), HandshakeError> {
    ensure_supported_suite(server_hello)?;
    let server_keys = HandshakePublicKeys::from_server_hello_packet(server_hello)?;
    let server_hello_bytes = server_hello.encode()?;
    let init = encapsulate_route_secret(
        &server_keys.ml_kem_public,
        client_x25519,
        server_keys.x25519_public,
        &server_hello_bytes,
    )
    .map_err(|_| HandshakeError::KeyDerivation)?;

    let mut payload = Vec::new();
    payload.extend_from_slice(&init.sender_x25519_public.0);
    payload.extend_from_slice(init.ml_kem_ciphertext.as_ref());
    let client_share = HandshakePacket::new(HandshakePacketType::ClientKeyShare, payload)?;
    let transcript_hash = transcript_hash(&server_hello.encode()?, &client_share.encode()?);

    Ok((
        client_share,
        ClientHandshakeState {
            route_secret: init.route_secret,
            transcript_hash,
        },
    ))
}

pub fn server_accept_handshake(
    server_hello: &HandshakePacket,
    client_share: &HandshakePacket,
    server_keys: &NodeKeyMaterial,
) -> Result<(HandshakePacket, ServerHandshakeState), HandshakeError> {
    ensure_supported_suite(server_hello)?;
    ensure_supported_suite(client_share)?;
    if client_share.packet_type != HandshakePacketType::ClientKeyShare {
        return Err(HandshakeError::WrongPacketType {
            expected: HandshakePacketType::ClientKeyShare,
            got: client_share.packet_type,
        });
    }
    if client_share.payload.len() != CLIENT_KEY_SHARE_PAYLOAD_BYTES {
        return Err(HandshakeError::InvalidLength {
            declared: CLIENT_KEY_SHARE_PAYLOAD_BYTES,
            available: client_share.payload.len(),
        });
    }
    let mut sender_x = [0u8; 32];
    sender_x.copy_from_slice(&client_share.payload[..32]);
    let ciphertext = MlKem768Ciphertext::try_from(&client_share.payload[32..])
        .map_err(|_| HandshakeError::InvalidCiphertext)?;
    let route_secret = server_keys
        .ml_kem_768
        .decapsulate_route_secret(
            &ciphertext,
            X25519NodePublic(sender_x),
            &server_keys.x25519,
            &server_hello.encode()?,
        )
        .map_err(|_| HandshakeError::KeyDerivation)?;
    let transcript_hash = transcript_hash(&server_hello.encode()?, &client_share.encode()?);
    let confirmation = key_confirmation(&route_secret, &transcript_hash)?;
    let confirm_packet =
        HandshakePacket::new(HandshakePacketType::ServerKeyConfirm, confirmation.to_vec())?;
    Ok((
        confirm_packet,
        ServerHandshakeState {
            route_secret,
            transcript_hash,
        },
    ))
}

pub fn client_verify_server_confirm(
    state: &ClientHandshakeState,
    confirm_packet: &HandshakePacket,
) -> Result<(), HandshakeError> {
    ensure_supported_suite(confirm_packet)?;
    if confirm_packet.packet_type != HandshakePacketType::ServerKeyConfirm {
        return Err(HandshakeError::WrongPacketType {
            expected: HandshakePacketType::ServerKeyConfirm,
            got: confirm_packet.packet_type,
        });
    }
    if confirm_packet.payload.len() != KEY_CONFIRM_SIZE {
        return Err(HandshakeError::InvalidLength {
            declared: KEY_CONFIRM_SIZE,
            available: confirm_packet.payload.len(),
        });
    }
    let expected = key_confirmation(&state.route_secret, &state.transcript_hash)?;
    if confirm_packet.payload.ct_eq(&expected).unwrap_u8() == 0 {
        return Err(HandshakeError::KeyConfirmationFailed);
    }
    Ok(())
}

fn transcript_hash(server_hello: &[u8], client_share: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"chronos-v7-handshake-transcript");
    hasher.update(server_hello);
    hasher.update(client_share);
    hasher.finalize().into()
}

fn key_confirmation(
    route_secret: &RouteHopSecret,
    transcript_hash: &[u8; 32],
) -> Result<[u8; KEY_CONFIRM_SIZE], HandshakeError> {
    let hk = Hkdf::<Sha256>::new(Some(transcript_hash), &route_secret.0);
    let mut out = [0u8; KEY_CONFIRM_SIZE];
    hk.expand(HANDSHAKE_CONFIRM_INFO, &mut out)
        .map_err(|_| HandshakeError::KeyDerivation)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid_route::MlKem768RouteKeypair;

    fn server_keys() -> NodeKeyMaterial {
        NodeKeyMaterial {
            x25519: X25519NodeSecret::from_bytes([0xA7; 32]),
            ml_kem_768: MlKem768RouteKeypair::from_seed_bytes([0xB8; 64]),
            identity_signing: ed25519_dalek::SigningKey::from_bytes(&[0xC7; 32]),
        }
    }

    fn client_x() -> X25519NodeSecret {
        X25519NodeSecret::from_bytes([0xC9; 32])
    }

    #[test]
    fn handshake_establishes_same_route_secret_and_confirms() {
        let server_keys = server_keys();
        let server_hello = HandshakePublicKeys::from_node_keys(&server_keys)
            .to_server_hello_packet()
            .expect("hello");
        let (client_share, client_state) =
            client_begin_handshake(&server_hello, &client_x()).expect("client begin");
        let (confirm, server_state) =
            server_accept_handshake(&server_hello, &client_share, &server_keys).expect("server");

        assert_eq!(client_state.route_secret, server_state.route_secret);
        client_verify_server_confirm(&client_state, &confirm).expect("confirm");
    }

    #[test]
    fn handshake_rejects_downgraded_suite_in_confirm() {
        let server_keys = server_keys();
        let mut server_hello = HandshakePublicKeys::from_node_keys(&server_keys)
            .to_server_hello_packet()
            .expect("hello");
        let (client_share, client_state) =
            client_begin_handshake(&server_hello, &client_x()).expect("client begin");
        server_hello.suite = 99;
        assert!(matches!(
            server_accept_handshake(&server_hello, &client_share, &server_keys),
            Err(HandshakeError::UnsupportedSuite(99))
        ));
        // Original state is still not confirmable with a random/tampered tag.
        let bad_confirm =
            HandshakePacket::new(HandshakePacketType::ServerKeyConfirm, vec![0u8; 32])
                .expect("bad confirm");
        assert_eq!(
            client_verify_server_confirm(&client_state, &bad_confirm),
            Err(HandshakeError::KeyConfirmationFailed)
        );
    }

    #[test]
    fn security_handshake_rejects_unsigned_server_hello() {
        let server_keys = server_keys();
        let unsigned = HandshakePublicKeys::unsigned_for_tests(
            server_keys.x25519.public(),
            server_keys.ml_kem_768.encapsulation_key.clone(),
        )
        .to_server_hello_packet()
        .expect("unsigned hello");

        assert!(
            client_begin_handshake(&unsigned, &client_x()).is_err(),
            "CHS7 accepted an unsigned ServerHello; ephemeral server shares must be identity-authenticated"
        );
    }

    #[test]
    fn handshake_rejects_unexpected_identity() {
        let server_keys = server_keys();
        let hello = HandshakePublicKeys::from_node_keys(&server_keys)
            .to_server_hello_packet()
            .expect("hello");
        assert!(matches!(
            HandshakePublicKeys::from_server_hello_packet_for_identity(&hello, &[0xEE; 32]),
            Err(HandshakeError::IdentityMismatch)
        ));
    }

    #[test]
    fn handshake_rejects_trailing_garbage_in_key_packets() {
        let server_keys = server_keys();
        let mut server_hello = HandshakePublicKeys::from_node_keys(&server_keys)
            .to_server_hello_packet()
            .expect("hello");
        server_hello.payload.push(0);
        assert!(matches!(
            HandshakePublicKeys::from_server_hello_packet(&server_hello),
            Err(HandshakeError::InvalidLength { .. })
        ));
    }

    #[test]
    fn handshake_packet_round_trips_and_rejects_bad_magic() {
        let packet = HandshakePacket::new(HandshakePacketType::Error, b"ERR".to_vec()).expect("p");
        let encoded = packet.encode().expect("enc");
        assert_eq!(HandshakePacket::decode(&encoded).expect("dec"), packet);
        let mut bad = encoded;
        bad[0] = b'X';
        assert_eq!(
            HandshakePacket::decode(&bad),
            Err(HandshakeError::InvalidMagic)
        );
    }

    #[test]
    fn handshake_pow_challenge_round_trips() {
        let challenge = PowChallenge {
            relay_id: [0xA5; 16],
            unix_window: 12345,
            difficulty_zero_bits: 8,
            token: [0x5A; 32],
        };
        let packet = HandshakePacket::pow_challenge(&challenge).expect("challenge packet");
        let decoded = HandshakePacket::decode(&packet.encode().expect("encode"))
            .expect("decode")
            .decode_pow_challenge()
            .expect("decode challenge");
        assert_eq!(decoded, challenge);
        let solution = HandshakePacket::pow_solution(vec![1, 2, 3]).expect("solution");
        assert_eq!(solution.packet_type, HandshakePacketType::PowSolution);
    }

    #[test]
    fn handshake_rejects_wrong_confirm_packet_type() {
        let server_keys = server_keys();
        let server_hello = HandshakePublicKeys::from_node_keys(&server_keys)
            .to_server_hello_packet()
            .expect("hello");
        let (_, client_state) =
            client_begin_handshake(&server_hello, &client_x()).expect("client begin");
        let wrong =
            HandshakePacket::new(HandshakePacketType::Error, b"no".to_vec()).expect("wrong");
        assert_eq!(
            client_verify_server_confirm(&client_state, &wrong),
            Err(HandshakeError::WrongPacketType {
                expected: HandshakePacketType::ServerKeyConfirm,
                got: HandshakePacketType::Error,
            })
        );
    }
}
