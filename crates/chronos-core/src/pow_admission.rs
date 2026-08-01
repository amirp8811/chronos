//! Simple PoW admission boundary for CHS7 handshakes.

use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowChallenge {
    pub relay_id: [u8; 16],
    pub unix_window: u64,
    pub difficulty_zero_bits: u32,
    pub token: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PowAdmissionError {
    InvalidDifficulty,
    InvalidServerSecret,
    InvalidNonce,
    Replay,
}

impl PowChallenge {
    /// Creates a stateless challenge bound to non-empty, non-zero server key
    /// material. Empty or all-zero material would make the token publicly
    /// reproducible and is rejected.
    pub fn new_stateless(
        relay_id: [u8; 16],
        unix_window: u64,
        difficulty_zero_bits: u32,
        client_id: &[u8],
        server_secret: &[u8],
    ) -> Result<Self, PowAdmissionError> {
        if difficulty_zero_bits > 255 {
            return Err(PowAdmissionError::InvalidDifficulty);
        }
        if server_secret.is_empty() || server_secret.iter().all(|byte| *byte == 0) {
            return Err(PowAdmissionError::InvalidServerSecret);
        }
        let mut h = Sha256::new();
        h.update(b"chronos-v7-pow-token");
        h.update(relay_id);
        h.update(unix_window.to_be_bytes());
        h.update(difficulty_zero_bits.to_be_bytes());
        h.update(client_id);
        h.update(server_secret);
        Ok(Self {
            relay_id,
            unix_window,
            difficulty_zero_bits,
            token: h.finalize().into(),
        })
    }

    pub fn verify(&self, nonce: &[u8]) -> Result<(), PowAdmissionError> {
        if self.difficulty_zero_bits > 255 {
            return Err(PowAdmissionError::InvalidDifficulty);
        }
        let mut h = Sha256::new();
        h.update(b"chronos-v7-pow-admission");
        h.update(self.relay_id);
        h.update(self.unix_window.to_be_bytes());
        h.update(self.difficulty_zero_bits.to_be_bytes());
        h.update(self.token);
        h.update(nonce);
        let digest = h.finalize();
        if leading_zero_bits(&digest) >= self.difficulty_zero_bits {
            Ok(())
        } else {
            Err(PowAdmissionError::InvalidNonce)
        }
    }
}

pub fn solve_pow_for_tests(challenge: &PowChallenge, max_iters: u64) -> Option<Vec<u8>> {
    for i in 0..max_iters {
        let nonce = i.to_be_bytes().to_vec();
        if challenge.verify(&nonce).is_ok() {
            return Some(nonce);
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct PowAdmissionCache {
    ttl: Duration,
    max_entries: usize,
    seen: HashMap<Vec<u8>, Instant>,
    order: VecDeque<Vec<u8>>,
}

impl PowAdmissionCache {
    pub fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            ttl,
            max_entries: max_entries.max(1),
            seen: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    pub fn verify_and_insert(
        &mut self,
        challenge: &PowChallenge,
        nonce: &[u8],
    ) -> Result<(), PowAdmissionError> {
        self.prune_expired();
        let mut key = Vec::with_capacity(challenge.token.len() + nonce.len());
        key.extend_from_slice(&challenge.token);
        key.extend_from_slice(nonce);
        if self.seen.contains_key(&key) {
            return Err(PowAdmissionError::Replay);
        }
        challenge.verify(nonce)?;
        self.seen.insert(key.clone(), Instant::now());
        self.order.push_back(key);
        while self.seen.len() > self.max_entries {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            } else {
                break;
            }
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    fn prune_expired(&mut self) {
        let now = Instant::now();
        while let Some(front) = self.order.front() {
            let expired = self
                .seen
                .get(front)
                .map(|t| now.duration_since(*t) >= self.ttl)
                .unwrap_or(true);
            if expired {
                if let Some(old) = self.order.pop_front() {
                    self.seen.remove(&old);
                }
            } else {
                break;
            }
        }
    }
}

fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut out = 0;
    for &b in bytes {
        if b == 0 {
            out += 8;
        } else {
            out += b.leading_zeros();
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pow_admission_accepts_solved_nonce() {
        let c = PowChallenge {
            relay_id: [7; 16],
            unix_window: 123,
            difficulty_zero_bits: 8,
            token: [0; 32],
        };
        let nonce = solve_pow_for_tests(&c, 100_000).expect("solve");
        c.verify(&nonce).expect("verify");
    }
    #[test]
    fn challenge_token_binds_secret_client_difficulty_and_window() {
        let relay_id = [6; 16];
        let a =
            PowChallenge::new_stateless(relay_id, 10, 8, b"client-a", b"alpha").expect("challenge");
        let changed_secret =
            PowChallenge::new_stateless(relay_id, 10, 8, b"client-a", b"bravo").expect("challenge");
        let changed_client =
            PowChallenge::new_stateless(relay_id, 10, 8, b"client-b", b"alpha").expect("challenge");
        let changed_difficulty =
            PowChallenge::new_stateless(relay_id, 10, 9, b"client-a", b"alpha").expect("challenge");
        let changed_window =
            PowChallenge::new_stateless(relay_id, 11, 8, b"client-a", b"alpha").expect("challenge");
        assert_ne!(a.token, changed_secret.token);
        assert_ne!(a.token, changed_client.token);
        assert_ne!(a.token, changed_difficulty.token);
        assert_ne!(a.token, changed_window.token);
    }

    #[test]
    fn challenge_rejects_empty_or_zero_server_secret() {
        assert_eq!(
            PowChallenge::new_stateless([1; 16], 1, 8, b"client", b""),
            Err(PowAdmissionError::InvalidServerSecret)
        );
        assert_eq!(
            PowChallenge::new_stateless([1; 16], 1, 8, b"client", &[0; 32]),
            Err(PowAdmissionError::InvalidServerSecret)
        );
        assert_eq!(
            PowChallenge::new_stateless([1; 16], 1, 256, b"client", b"key"),
            Err(PowAdmissionError::InvalidDifficulty)
        );
    }

    #[test]
    fn pow_cache_rejects_replay() {
        let c = PowChallenge {
            relay_id: [8; 16],
            unix_window: 1,
            difficulty_zero_bits: 4,
            token: [0; 32],
        };
        let nonce = solve_pow_for_tests(&c, 10_000).expect("solve");
        let mut cache = PowAdmissionCache::new(8, Duration::from_secs(60));
        cache.verify_and_insert(&c, &nonce).expect("first");
        assert_eq!(
            cache.verify_and_insert(&c, &nonce),
            Err(PowAdmissionError::Replay)
        );
    }

    #[test]
    fn pow_cache_expires_entries() {
        let c = PowChallenge {
            relay_id: [9; 16],
            unix_window: 1,
            difficulty_zero_bits: 4,
            token: [0; 32],
        };
        let nonce = solve_pow_for_tests(&c, 10_000).expect("solve");
        let mut cache = PowAdmissionCache::new(8, Duration::from_secs(0));
        cache.verify_and_insert(&c, &nonce).expect("first");
        cache
            .verify_and_insert(&c, &nonce)
            .expect("expired allows reuse");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn pow_admission_rejects_bad_nonce() {
        let c = PowChallenge {
            relay_id: [7; 16],
            unix_window: 123,
            difficulty_zero_bits: 16,
            token: [0; 32],
        };
        assert_eq!(c.verify(b"bad"), Err(PowAdmissionError::InvalidNonce));
    }
}
