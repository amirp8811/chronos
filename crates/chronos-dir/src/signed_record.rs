//! Ed25519 signed relay records for local directory authorization.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::store::RelayRecord;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRelayRecord {
    pub record: RelayRecord,
    pub signer_id: String,
    pub verifying_key: [u8; 32],
    pub signature: [u8; 64],
}

pub fn sign_record(
    record: RelayRecord,
    signer_id: &str,
    signing_key: &SigningKey,
) -> SignedRelayRecord {
    let msg = record_message(&record, signer_id);
    let sig = signing_key.sign(&msg).to_bytes();
    SignedRelayRecord {
        record,
        signer_id: signer_id.to_string(),
        verifying_key: signing_key.verifying_key().to_bytes(),
        signature: sig,
    }
}

pub fn verify_record(signed: &SignedRelayRecord) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(&signed.verifying_key) else {
        return false;
    };
    let sig = Signature::from_bytes(&signed.signature);
    vk.verify(&record_message(&signed.record, &signed.signer_id), &sig)
        .is_ok()
}

fn record_message(record: &RelayRecord, signer_id: &str) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"chronos-dir-record-v2");
    msg.extend_from_slice(signer_id.as_bytes());
    msg.extend_from_slice(record.node_id.as_bytes());
    msg.extend_from_slice(record.address.to_string().as_bytes());
    msg.extend_from_slice(&record.x25519_public);
    msg.extend_from_slice(&record.ml_kem_public_hash);
    msg.extend_from_slice(&record.expires_at_unix.to_be_bytes());
    msg
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_record_verifies_and_detects_tampering() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let record = RelayRecord {
            node_id: "n1".into(),
            address: "127.0.0.1:7".parse().unwrap(),
            x25519_public: [1; 32],
            ml_kem_public_hash: [2; 32],
            expires_at_unix: 9,
        };
        let mut signed = sign_record(record, "validator-a", &signing);
        assert!(verify_record(&signed));
        signed.record.expires_at_unix = 10;
        assert!(!verify_record(&signed));
    }
}
