//! Hybrid ML-KEM-768 + X25519 route-secret setup.
//!
//! This module adds the PQ half that was missing from the route-layer prototype.
//! It derives a `RouteHopSecret` by combining an ML-KEM-768 shared secret with an
//! X25519 shared secret under HKDF-SHA256. The resulting secret is suitable for
//! the authenticated route-layer prototype in `route_layer.rs`.

use hkdf::Hkdf;
use ml_kem::{
    DecapsulationKey, EncapsulationKey, MlKem768,
    kem::{Decapsulate, Encapsulate, Kem, KeyExport},
};
use sha2::Sha256;

use crate::handshake::{X25519NodePublic, X25519NodeSecret};
use crate::route_layer::RouteHopSecret;

const HYBRID_ROUTE_INFO: &[u8] = b"chronos-v7/hybrid-mlkem768-x25519-route-hop";

pub type MlKem768Ciphertext = ml_kem::Ciphertext<MlKem768>;

#[derive(Clone)]
pub struct MlKem768RouteKeypair {
    decapsulation_key: DecapsulationKey<MlKem768>,
    pub encapsulation_key: EncapsulationKey<MlKem768>,
}

pub struct HybridRouteEncapsulation {
    pub ml_kem_ciphertext: MlKem768Ciphertext,
    pub sender_x25519_public: X25519NodePublic,
    pub route_secret: RouteHopSecret,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HybridRouteError {
    KeyDerivation,
}

impl MlKem768RouteKeypair {
    pub fn generate() -> Self {
        let (decapsulation_key, encapsulation_key) = MlKem768::generate_keypair();
        Self {
            decapsulation_key,
            encapsulation_key,
        }
    }

    pub fn from_seed_bytes(seed: [u8; 64]) -> Self {
        let decapsulation_key = DecapsulationKey::<MlKem768>::from_seed(ml_kem::Seed::from(seed));
        let encapsulation_key = decapsulation_key.encapsulation_key().clone();
        Self {
            decapsulation_key,
            encapsulation_key,
        }
    }

    pub fn to_seed_bytes(&self) -> [u8; 64] {
        let seed = self.decapsulation_key.to_bytes();
        let mut out = [0u8; 64];
        out.copy_from_slice(seed.as_ref());
        out
    }

    pub fn decapsulate_route_secret(
        &self,
        ml_kem_ciphertext: &MlKem768Ciphertext,
        sender_x25519_public: X25519NodePublic,
        receiver_x25519_secret: &X25519NodeSecret,
        route_context: &[u8],
    ) -> Result<RouteHopSecret, HybridRouteError> {
        let pq_shared = self.decapsulation_key.decapsulate(ml_kem_ciphertext);
        let x_shared = receiver_x25519_secret.diffie_hellman(sender_x25519_public);
        combine_hybrid_route_secret(pq_shared.as_ref(), &x_shared.0, route_context)
    }
}

pub fn encapsulate_route_secret(
    receiver_ml_kem_public: &EncapsulationKey<MlKem768>,
    sender_x25519_secret: &X25519NodeSecret,
    receiver_x25519_public: X25519NodePublic,
    route_context: &[u8],
) -> Result<HybridRouteEncapsulation, HybridRouteError> {
    let (ml_kem_ciphertext, pq_shared) = receiver_ml_kem_public.encapsulate();
    let x_shared = sender_x25519_secret.diffie_hellman(receiver_x25519_public);
    let route_secret = combine_hybrid_route_secret(pq_shared.as_ref(), &x_shared.0, route_context)?;
    Ok(HybridRouteEncapsulation {
        ml_kem_ciphertext,
        sender_x25519_public: sender_x25519_secret.public(),
        route_secret,
    })
}

fn combine_hybrid_route_secret(
    ml_kem_shared: &[u8],
    x25519_shared: &[u8; 32],
    route_context: &[u8],
) -> Result<RouteHopSecret, HybridRouteError> {
    let mut ikm = Vec::with_capacity(ml_kem_shared.len() + x25519_shared.len());
    ikm.extend_from_slice(ml_kem_shared);
    ikm.extend_from_slice(x25519_shared);

    let hk = Hkdf::<Sha256>::new(Some(route_context), &ikm);
    let mut out = [0u8; 32];
    hk.expand(HYBRID_ROUTE_INFO, &mut out)
        .map_err(|_| HybridRouteError::KeyDerivation)?;
    Ok(RouteHopSecret(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_layer::{RouteCommand, build_layered_route_packet, peel_route_layer};

    #[test]
    fn hybrid_mlkem_x25519_route_secret_matches_on_both_sides() {
        let receiver_mlkem = MlKem768RouteKeypair::generate();
        let sender_x = X25519NodeSecret::from_bytes([0x51; 32]);
        let receiver_x = X25519NodeSecret::from_bytes([0x52; 32]);
        let context = b"route-hop-0/session-123";

        let init = encapsulate_route_secret(
            &receiver_mlkem.encapsulation_key,
            &sender_x,
            receiver_x.public(),
            context,
        )
        .expect("encapsulate");
        let recv = receiver_mlkem
            .decapsulate_route_secret(
                &init.ml_kem_ciphertext,
                init.sender_x25519_public,
                &receiver_x,
                context,
            )
            .expect("decapsulate");

        assert_eq!(init.route_secret, recv);
    }

    #[test]
    fn hybrid_route_secret_can_drive_route_layer() {
        let receiver_mlkem = MlKem768RouteKeypair::generate();
        let sender_x = X25519NodeSecret::from_bytes([0x61; 32]);
        let receiver_x = X25519NodeSecret::from_bytes([0x62; 32]);
        let context = b"single-hop-route";
        let init = encapsulate_route_secret(
            &receiver_mlkem.encapsulation_key,
            &sender_x,
            receiver_x.public(),
            context,
        )
        .expect("encapsulate");
        let recv_secret = receiver_mlkem
            .decapsulate_route_secret(
                &init.ml_kem_ciphertext,
                init.sender_x25519_public,
                &receiver_x,
                context,
            )
            .expect("decapsulate");

        let command = [RouteCommand {
            next_stream_id: 7,
            flags: 1,
        }];
        let packet =
            build_layered_route_packet(777, &[init.route_secret], &command, b"hybrid payload")
                .expect("route packet");
        let peeled = peel_route_layer(&packet, 0, &recv_secret).expect("peel");
        assert_eq!(peeled.payload.expect("payload"), b"hybrid payload");
    }

    #[test]
    fn hybrid_route_context_domain_separates_secrets() {
        let receiver_mlkem = MlKem768RouteKeypair::generate();
        let sender_x = X25519NodeSecret::from_bytes([0x71; 32]);
        let receiver_x = X25519NodeSecret::from_bytes([0x72; 32]);

        let a = encapsulate_route_secret(
            &receiver_mlkem.encapsulation_key,
            &sender_x,
            receiver_x.public(),
            b"context-a",
        )
        .expect("a");
        let b = receiver_mlkem
            .decapsulate_route_secret(
                &a.ml_kem_ciphertext,
                a.sender_x25519_public,
                &receiver_x,
                b"context-b",
            )
            .expect("b");

        assert_ne!(a.route_secret, b);
    }
}
