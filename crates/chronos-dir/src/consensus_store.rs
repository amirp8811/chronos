//! Quorum-backed directory record commit prototype.
//!
//! This is not a full HotStuff implementation, but it adds the missing
//! consensus-backed directory boundary: validator identities, signed votes,
//! quorum certificates, and commit into the local `DirectoryStore` only after a
//! threshold of valid validator signatures.

use std::collections::{HashMap, HashSet};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::store::{DirectoryStore, RelayRecord};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorPublicKey {
    pub validator_id: String,
    pub verifying_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryVote {
    pub validator_id: String,
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumCertificate {
    pub record_digest: [u8; 32],
    pub signer_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusStoreError {
    UnknownValidator(String),
    InvalidSignature(String),
    DuplicateVote(String),
    InsufficientQuorum { got: usize, need: usize },
}

pub struct ConsensusDirectory {
    validators: HashMap<String, VerifyingKey>,
    threshold: usize,
    store: DirectoryStore,
}

impl ConsensusDirectory {
    pub fn new(
        validators: Vec<ValidatorPublicKey>,
        threshold: usize,
    ) -> Result<Self, ConsensusStoreError> {
        let mut map = HashMap::new();
        for validator in validators {
            let key = VerifyingKey::from_bytes(&validator.verifying_key).map_err(|_| {
                ConsensusStoreError::UnknownValidator(validator.validator_id.clone())
            })?;
            map.insert(validator.validator_id, key);
        }
        Ok(Self {
            validators: map,
            threshold: threshold.max(1),
            store: DirectoryStore::new(),
        })
    }

    pub fn commit_with_votes(
        &mut self,
        record: RelayRecord,
        votes: &[DirectoryVote],
    ) -> Result<QuorumCertificate, ConsensusStoreError> {
        let digest = record_digest(&record);
        let mut seen = HashSet::new();
        let mut signers = Vec::new();
        for vote in votes {
            if !seen.insert(vote.validator_id.clone()) {
                return Err(ConsensusStoreError::DuplicateVote(
                    vote.validator_id.clone(),
                ));
            }
            let key = self
                .validators
                .get(&vote.validator_id)
                .ok_or_else(|| ConsensusStoreError::UnknownValidator(vote.validator_id.clone()))?;
            let sig = Signature::from_bytes(&vote.signature);
            key.verify(&digest, &sig)
                .map_err(|_| ConsensusStoreError::InvalidSignature(vote.validator_id.clone()))?;
            signers.push(vote.validator_id.clone());
        }
        if signers.len() < self.threshold {
            return Err(ConsensusStoreError::InsufficientQuorum {
                got: signers.len(),
                need: self.threshold,
            });
        }
        signers.sort();
        self.store.upsert(record);
        Ok(QuorumCertificate {
            record_digest: digest,
            signer_ids: signers,
        })
    }

    pub fn get(&self, node_id: &str, now: u64) -> Option<&RelayRecord> {
        self.store.get(node_id, now)
    }
}

pub fn sign_directory_vote(
    record: &RelayRecord,
    validator_id: &str,
    key: &SigningKey,
) -> DirectoryVote {
    let signature = key.sign(&record_digest(record)).to_bytes();
    DirectoryVote {
        validator_id: validator_id.to_string(),
        signature,
    }
}

pub fn validator_public_key(validator_id: &str, key: &SigningKey) -> ValidatorPublicKey {
    ValidatorPublicKey {
        validator_id: validator_id.to_string(),
        verifying_key: key.verifying_key().to_bytes(),
    }
}

fn record_digest(record: &RelayRecord) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"chronos-dir-consensus-record-v1");
    h.update(record.node_id.as_bytes());
    h.update(record.address.to_string().as_bytes());
    h.update(record.x25519_public);
    h.update(record.ml_kem_public_hash);
    h.update(record.expires_at_unix.to_be_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> RelayRecord {
        RelayRecord {
            node_id: "relay-1".into(),
            address: "127.0.0.1:7777".parse().unwrap(),
            x25519_public: [1; 32],
            ml_kem_public_hash: [2; 32],
            expires_at_unix: 100,
        }
    }

    #[test]
    fn consensus_directory_commits_after_threshold_votes() {
        let k1 = SigningKey::from_bytes(&[1; 32]);
        let k2 = SigningKey::from_bytes(&[2; 32]);
        let k3 = SigningKey::from_bytes(&[3; 32]);
        let validators = vec![
            validator_public_key("v1", &k1),
            validator_public_key("v2", &k2),
            validator_public_key("v3", &k3),
        ];
        let mut dir = ConsensusDirectory::new(validators, 2).expect("dir");
        let rec = record();
        let votes = vec![
            sign_directory_vote(&rec, "v1", &k1),
            sign_directory_vote(&rec, "v2", &k2),
        ];
        let qc = dir.commit_with_votes(rec.clone(), &votes).expect("qc");
        assert_eq!(qc.signer_ids, vec!["v1".to_string(), "v2".to_string()]);
        assert_eq!(dir.get("relay-1", 99).unwrap().address, rec.address);
    }

    #[test]
    fn consensus_directory_rejects_insufficient_quorum() {
        let k1 = SigningKey::from_bytes(&[1; 32]);
        let validators = vec![validator_public_key("v1", &k1)];
        let mut dir = ConsensusDirectory::new(validators, 2).expect("dir");
        let rec = record();
        let votes = vec![sign_directory_vote(&rec, "v1", &k1)];
        assert_eq!(
            dir.commit_with_votes(rec, &votes),
            Err(ConsensusStoreError::InsufficientQuorum { got: 1, need: 2 })
        );
    }

    #[test]
    fn consensus_directory_rejects_tampered_record() {
        let k1 = SigningKey::from_bytes(&[1; 32]);
        let validators = vec![validator_public_key("v1", &k1)];
        let mut dir = ConsensusDirectory::new(validators, 1).expect("dir");
        let rec = record();
        let votes = vec![sign_directory_vote(&rec, "v1", &k1)];
        let mut tampered = rec;
        tampered.expires_at_unix = 101;
        assert_eq!(
            dir.commit_with_votes(tampered, &votes),
            Err(ConsensusStoreError::InvalidSignature("v1".to_string()))
        );
    }
}
