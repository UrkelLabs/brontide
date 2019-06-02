use crate::cipher_state::CipherState;
use crate::util::expand;
use sha2::{Digest, Sha256};

pub struct SymmetricState {
    cipher: CipherState,
    chaining_key: [u8; 32],
    // temp: Buffer,   // temp key
    digest: [u8; 32], // handshake digest
}

impl SymmetricState {
    pub fn new(protocol_name: &str) -> Self {
        //Again rename this as empty. TODO
        let mut digest = [0_u8; 32];
        let hash = Sha256::digest(protocol_name.as_bytes());

        digest.copy_from_slice(hash.as_slice());

        SymmetricState {
            //TODO make this a constant of empty key.
            cipher: CipherState::new([0_u8; 32], [0_u8; 32]),
            chaining_key: digest.clone(),
            digest,
        }
    }

    pub fn mix_key(&mut self, input: &[u8]) {
        // let secret = input;
        // let salt = self.chaining_key;

        let (chain, temp) = expand(input, &self.chaining_key);

        let mut temp_key = [0; 32];
        temp_key.copy_from_slice(&temp);

        //TODO it's probably more effective to copy this from slice isntead of equal it.
        //That would require us to change the return signature of expand to slices, which I'm
        //totally open to do. Once we finish the bulk of things come back to this.
        self.chaining_key = chain;

        self.cipher = CipherState::new([0_u8; 32], temp_key);
    }

    //TODO test if tag as an option handles this behavior correctly.
    pub fn mix_hash(&mut self, data: Buffer, tag: Option<Buffer>) {
        self.digest = self.mix_digest(data, tag);
    }

    //TODO review
    pub fn mix_digest(&mut self, data: Buffer, tag: Option<Buffer>) -> Buffer {
        let mut hasher = Sha256::new();

        hasher.input(self.digest);
        hasher.input(data);
        if let Some(tag_ok) = tag {
            hasher.input(tag_ok);
        };

        let result = hasher.result();

        Buffer::from(result.as_slice().to_vec())
    }

    //pt = plaintext, let's make that more verbose TODO so the code is more readable.
    pub fn encrypt_hash(&mut self, pt: Buffer) -> Buffer {
        let tag = self.cipher.encrypt(pt, self.digest);

        self.mix_hash(pt, Some(tag));

        tag
    }

    //ct == CipherText, make this more verbose as above TODO
    pub fn decrypt_hash(&mut self, ct: Buffer, tag: Buffer) -> bool {
        let digest = self.mix_digest(ct, Some(tag));

        let result = self.cipher.decrypt(ct, tag, self.digest);

        if result {
            self.digest = digest;
            true
        } else {
            false
        }
    }
}
