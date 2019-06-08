use crate::cipher_state::CipherState;
use crate::util::expand;
use sha2::{Digest, Sha256};

//TODO manually impl this.
#[derive(Debug)]
pub struct SymmetricState {
    cipher: CipherState,
    pub(crate) chaining_key: [u8; 32],
    // temp: Buffer,   // temp key
    digest: [u8; 32], // handshake digest
}

//TODO make these pub crate only
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

        self.cipher = CipherState::new(temp_key, [0_u8; 32]);
    }

    //TODO test if tag as an option handles this behavior correctly.
    // pub fn mix_hash(&mut self, data: &[u8], tag: Option<&[u8]>) {
    //     let digest = self.mix_digest(data, tag);

    //     self.digest.copy_from_slice(&digest);
    // }

    //TODO review
    //Not sure we need the tag here
    //this applies to the above function as well, but we can essentially just add the tag
    //to the end of the data, and it should work fine.
    pub fn mix_digest(&mut self, data: &[u8], tag: Option<&[u8]>) {
        let mut hasher = Sha256::new();

        hasher.input(&self.digest);
        hasher.input(data);
        if let Some(tag_ok) = tag {
            hasher.input(tag_ok);
        };

        let result = hasher.result();

        self.digest.copy_from_slice(&result);
    }

    //pt = plaintext, let's make that more verbose TODO so the code is more readable.
    //
    ////TODO should return custom tag type.
    pub fn encrypt_hash(&mut self, plain_text: &[u8], cipher_text: &mut Vec<u8>) -> [u8; 16] {
        //TODO remove this, and have this function return a result
        let tag = self
            .cipher
            .encrypt(plain_text, &self.digest, cipher_text)
            .unwrap();

        self.mix_digest(cipher_text, Some(&tag));

        let mut return_tag = [0_u8; 16];

        return_tag.copy_from_slice(&tag);

        return_tag
    }

    //ct == CipherText, make this more verbose as above TODO
    //TODO, make this it's own type - tag - as MAC.
    pub fn decrypt_hash(&mut self, cipher_text: &[u8], tag: [u8; 16]) -> bool {
        let result = self.cipher.decrypt(cipher_text, &tag, &self.digest);

        if result {
            //TODO this is different than in HSD, test that this works (Calling mix_digest *after*
            //the decrypt call. If it does, open a PR for this.
            self.mix_digest(cipher_text, Some(&tag));
            //TODO double check this.
            // self.digest.copy_from_slice(&digest);
            true
        } else {
            false
        }
    }
}
