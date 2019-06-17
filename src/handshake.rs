use crate::common::PROTOCOL_NAME;
use crate::symmetric_state::SymmetricState;
use crate::types::{PublicKey, SecretKey};
use crate::Result;
use hex;
use secp256k1::rand::rngs::OsRng;
use secp256k1::{self, Secp256k1};
use std::str::FromStr;

pub struct HandshakeState {
    pub(crate) symmetric: SymmetricState,
    pub(crate) initiator: bool,
    pub(crate) local_static: SecretKey,
    pub(crate) local_ephemeral: SecretKey,
    pub(crate) remote_static: PublicKey,
    pub(crate) remote_ephemeral: PublicKey,
    pub generate_key: fn() -> Result<SecretKey>,
}

impl HandshakeState {
    pub(crate) fn new(
        initiator: bool,
        prologue: &str,
        local_pub: SecretKey,
        remote_pub: Option<PublicKey>,
    ) -> Self {
        let remote_public_key: PublicKey;

        if let Some(remote_pub_ok) = remote_pub {
            remote_public_key = remote_pub_ok
        } else {
            remote_public_key = PublicKey::empty();
        }

        let mut state = HandshakeState {
            initiator,
            local_static: local_pub,
            remote_static: remote_public_key,
            symmetric: SymmetricState::new(PROTOCOL_NAME),
            local_ephemeral: SecretKey::empty(),
            remote_ephemeral: PublicKey::empty(),
            generate_key: || {
                let secp = Secp256k1::new();
                let mut rng = OsRng::new().expect("OsRng");
                let (secret_key, _) = secp.generate_keypair(&mut rng);

                let key = SecretKey::from_str(secret_key.to_string().as_ref())?;

                Ok(key)
            },
        };

        state.symmetric.mix_digest(prologue.as_bytes(), None);

        //TODO review this logic.
        if initiator {
            state.symmetric.mix_digest(&state.remote_static, None);
        } else {
            let secp = Secp256k1::new();

            let secret_key = secp256k1::SecretKey::from_slice(&state.local_static)
                .expect("32 bytes, within curve order");
            let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

            state
                .symmetric
                .mix_digest(&hex::decode(public_key.to_string()).unwrap(), None);
        }

        state
    }
}
