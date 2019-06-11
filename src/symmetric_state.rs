use crate::cipher_state::CipherState;
use crate::types;
use crate::types::{Salt, SecretKey, Tag};
use crate::util::expand;
use crate::Result;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct SymmetricState {
    cipher: CipherState,
    pub(crate) chaining_key: SecretKey,
    digest: types::Digest,
}

impl SymmetricState {
    pub(crate) fn new(protocol_name: &str) -> Self {
        let hash = Sha256::digest(protocol_name.as_bytes());

        let digest = types::Digest::from(hash.as_slice());

        SymmetricState {
            cipher: CipherState::new(SecretKey::empty(), Salt::empty()),
            chaining_key: digest.clone(),
            digest,
        }
    }

    pub(crate) fn mix_key(&mut self, input: &[u8]) {
        let (chain, temp) = expand(input, &self.chaining_key);

        self.chaining_key = chain;

        self.cipher = CipherState::new(temp, Salt::empty());
    }

    pub(crate) fn mix_digest(&mut self, data: &[u8], tag: Option<Tag>) {
        let mut hasher = Sha256::new();

        hasher.input(&self.digest);
        hasher.input(data);

        if let Some(tag_ok) = tag {
            hasher.input(tag_ok);
        };

        let result = hasher.result();

        self.digest = types::Digest::from(result.as_slice());
    }

    pub fn encrypt_hash(&mut self, plain_text: &[u8], cipher_text: &mut Vec<u8>) -> Result<Tag> {
        let tag = self.cipher.encrypt(plain_text, &self.digest, cipher_text)?;

        self.mix_digest(cipher_text, Some(tag));

        Ok(tag)
    }

    pub fn decrypt_hash(&mut self, cipher_text: &[u8], tag: Tag, plain_text: &mut Vec<u8>) -> bool {
        let result = self
            .cipher
            .decrypt(cipher_text, tag, &self.digest, plain_text);

        if result {
            //TODO this is different than in HSD, test that this works (Calling mix_digest *after*
            //the decrypt call. If it does, open a PR for this.
            self.mix_digest(cipher_text, Some(tag));
            true
        } else {
            false
        }
    }
}
