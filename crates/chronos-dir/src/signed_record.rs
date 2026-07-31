//! Ed25519-authenticated relay records for the local directory API.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
#[cfg(test)]
use ed25519_dalek::{Signer, SigningKey};

use crate::store::{RelayRecord, RelayRecordError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRelayRecord {
    pub record: RelayRecord,
    /// The production API requires this to match `record.node_id`: a relay
    /// self-authenticates its descriptor rather than accepting an arbitrary
    /// signer label.
    pub signer_id: String,
    pub verifying_key: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedRecordError {
    SignerDoesNotMatchNodeId,
    InvalidSignature,
    Record(RelayRecordError),
}

#[cfg(test)]
pub fn sign_record(
    record: RelayRecord,
    signer_id: &str,
    signing_key: &SigningKey,
) -> SignedRelayRecord {
    let message = record_message(&record, signer_id);
    let signature = signing_key.sign(&message).to_bytes();
    SignedRelayRecord {
        record,
        signer_id: signer_id.to_string(),
        verifying_key: signing_key.verifying_key().to_bytes(),
        signature,
    }
}

pub fn verify_record_at(
    signed: &SignedRelayRecord,
    now_unix: u64,
    max_lifetime_seconds: u64,
) -> Result<(), SignedRecordError> {
    if signed.signer_id != signed.record.node_id {
        return Err(SignedRecordError::SignerDoesNotMatchNodeId);
    }
    signed
        .record
        .validate_public_material()
        .map_err(SignedRecordError::Record)?;
    signed
        .record
        .validate_freshness(now_unix, max_lifetime_seconds)
        .map_err(SignedRecordError::Record)?;
    let verifying_key = VerifyingKey::from_bytes(&signed.verifying_key)
        .map_err(|_| SignedRecordError::InvalidSignature)?;
    let signature = Signature::from_bytes(&signed.signature);
    verifying_key
        .verify(
            &record_message(&signed.record, &signed.signer_id),
            &signature,
        )
        .map_err(|_| SignedRecordError::InvalidSignature)
}

pub fn record_message(record: &RelayRecord, signer_id: &str) -> Vec<u8> {
    // Length-prefixing prevents field-boundary ambiguity in signed input.
    let mut message = Vec::new();
    message.extend_from_slice(b"chronos-dir-record-v3");
    append_field(&mut message, signer_id.as_bytes());
    append_field(&mut message, record.node_id.as_bytes());
    append_field(&mut message, record.address.to_string().as_bytes());
    append_field(&mut message, &record.x25519_public);
    append_field(&mut message, &record.ml_kem_public_hash);
    message.extend_from_slice(&record.expires_at_unix.to_be_bytes());
    message
}

fn append_field(message: &mut Vec<u8>, field: &[u8]) {
    message.extend_from_slice(&(field.len() as u32).to_be_bytes());
    message.extend_from_slice(field);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(expiry: u64) -> RelayRecord {
        RelayRecord {
            node_id: "n1".into(),
            address: "127.0.0.1:7".parse().expect("address"),
            x25519_public: [1; 32],
            ml_kem_public_hash: [2; 32],
            expires_at_unix: expiry,
        }
    }

    #[test]
    fn signed_record_verifies_and_detects_tampering() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut signed = sign_record(record(20), "n1", &signing);
        assert!(verify_record_at(&signed, 10, 30).is_ok());
        signed.record.expires_at_unix = 21;
        assert_eq!(
            verify_record_at(&signed, 10, 30),
            Err(SignedRecordError::InvalidSignature)
        );
    }

    #[test]
    fn signed_record_requires_matching_relay_identity_and_freshness() {
        let signing = SigningKey::from_bytes(&[8u8; 32]);
        let mut signed = sign_record(record(10), "n1", &signing);
        signed.signer_id = "other".into();
        assert_eq!(
            verify_record_at(&signed, 1, 30),
            Err(SignedRecordError::SignerDoesNotMatchNodeId)
        );
        let expired = sign_record(record(10), "n1", &signing);
        assert!(matches!(
            verify_record_at(&expired, 10, 30),
            Err(SignedRecordError::Record(RelayRecordError::Expired { .. }))
        ));
    }
}
