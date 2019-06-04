use crate::common::PROTOCOL_NAME;
use crate::symmetric_state::SymmetricState;
use secp256k1::rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

pub struct HandshakeState {
    symmetric: SymmetricState,
    initiator: bool,
    //TODO again all these should be custom
    local_static: [u8; 32],
    local_ephemeral: [u8; 32],
    remote_static: [u8; 32],
    remote_ephemeral: [u8; 32],
}

impl HandshakeState {
    pub fn generate_key() -> [u8; 32] {
        let secp = Secp256k1::new();
        let mut rng = OsRng::new().expect("OsRng");
        let (secret_key, _) = secp.generate_keypair(&mut rng);

        //TODO redo this.
        let mut key = [0_u8; 32];
        key.copy_from_slice(secret_key.to_string().as_bytes());

        key
    }

    pub fn init_state(
        &mut self,
        initiator: bool,
        prologue: &str,
        local_pub: [u8; 32],
        remote_pub: Option<[u8; 32]>,
    ) {
        let remote_public_key: [u8; 32];
        self.initiator = initiator;
        //TODO might not have to do this.
        self.local_static.copy_from_slice(&local_pub);
        if let Some(remote_pub_ok) = remote_pub {
            remote_public_key = remote_pub_ok
        } else {
            //Should be zero key not buffer new, TODO
            remote_public_key = [0_u8; 32];
        }

        self.remote_static = remote_public_key;

        self.symmetric = SymmetricState::new(PROTOCOL_NAME);

        //Might have to make sure this works as ascii TODO
        self.symmetric.mix_digest(prologue.as_bytes(), None);

        if initiator {
            //TODO we need to test this behavior, but I think the general idea is we want to mix
            //this with a zero hash buffer. so 32 bytes of 0s.
            self.symmetric.mix_digest(&remote_public_key, None)
        } else {
            //Switch this with the get public function TODO
            let secp = Secp256k1::new();
            //TODO handle this error correctly.
            let secret_key =
                SecretKey::from_slice(&local_pub).expect("32 bytes, within curve order");
            let public_key = PublicKey::from_secret_key(&secp, &secret_key);
            //TODO review this, not sure I trust converting the public key to string then reading
            //it in the buffer.
            self.symmetric
                .mix_digest(public_key.to_string().as_bytes(), None);
        }
    }
}
