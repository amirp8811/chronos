//! X25519 link handshake primitive.
//!
//! This is not the final hybrid ML-KEM-768 + X25519 handshake from the full
//! CHRONOS spec. It implements the classical X25519 half now and provides a
//! typed shared-secret boundary that feeds the AEAD/HKDF cell layer.

use x25519_dalek::{PublicKey, StaticSecret};

use crate::secure_cell::{SecureCellError, derive_link_key};

#[derive(Clone)]
pub struct X25519NodeSecret {
    secret: StaticSecret,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X25519NodePublic(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkSharedSecret(pub [u8; 32]);

impl X25519NodeSecret {
    /// Construct a node secret from existing key material.
    ///
    /// Production callers should fill this with OS-CSPRNG bytes and persist it
    /// through the node key-management layer; tests use deterministic bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            secret: StaticSecret::from(bytes),
        }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    pub fn public(&self) -> X25519NodePublic {
        X25519NodePublic(PublicKey::from(&self.secret).to_bytes())
    }

    pub fn diffie_hellman(&self, peer: X25519NodePublic) -> LinkSharedSecret {
        let peer_public = PublicKey::from(peer.0);
        LinkSharedSecret(self.secret.diffie_hellman(&peer_public).to_bytes())
    }
}

impl LinkSharedSecret {
    pub fn derive_cell_key(self, route_tag: &[u8; 16]) -> Result<[u8; 32], SecureCellError> {
        derive_link_key(&self.0, route_tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_cell::SecureShardCell;

    #[test]
    fn x25519_peers_derive_same_link_secret() {
        let alice = X25519NodeSecret::from_bytes([0xA1; 32]);
        let bob = X25519NodeSecret::from_bytes([0xB2; 32]);

        let alice_secret = alice.diffie_hellman(bob.public());
        let bob_secret = bob.diffie_hellman(alice.public());

        assert_eq!(alice_secret, bob_secret);
        assert_ne!(alice_secret.0, [0u8; 32]);
    }

    #[test]
    fn x25519_derived_cell_key_encrypts_between_peers() {
        let alice = X25519NodeSecret::from_bytes([0x11; 32]);
        let bob = X25519NodeSecret::from_bytes([0x22; 32]);
        let route_tag = [0x33; 16];

        let alice_key = alice
            .diffie_hellman(bob.public())
            .derive_cell_key(&route_tag)
            .expect("alice key");
        let bob_key = bob
            .diffie_hellman(alice.public())
            .derive_cell_key(&route_tag)
            .expect("bob key");
        assert_eq!(alice_key, bob_key);

        let cell = SecureShardCell::encrypt(&alice_key, route_tag, 1, 0, b"x25519 link cell")
            .expect("encrypt");
        assert_eq!(
            cell.decrypt(&bob_key).expect("decrypt"),
            b"x25519 link cell"
        );
    }

    #[test]
    fn route_tag_context_separates_cell_keys() {
        let alice = X25519NodeSecret::from_bytes([0x44; 32]);
        let bob = X25519NodeSecret::from_bytes([0x55; 32]);
        let shared = alice.diffie_hellman(bob.public());

        let key_a = shared.derive_cell_key(&[1u8; 16]).expect("key a");
        let key_b = shared.derive_cell_key(&[2u8; 16]).expect("key b");
        assert_ne!(key_a, key_b);
    }
}
