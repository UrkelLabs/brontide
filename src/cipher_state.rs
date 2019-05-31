use chacha20_poly1305_aead;

use crate::common::ROTATION_INTERVAL;
use crate::util::expand;

pub(crate) struct CipherState {
    secret_key: [u8; 32],
    salt: [u8; 32],
    //ChaCha20_poly1305 calls for a 96 bit nonce, with a 32 bit counter. Therefore we are only
    //going to use u32 as our counter as opposed to u64.
    inner_nonce: u32,
    //See note above, this represents the 96 bit nonce as a byte array (8 * 12) = 96
    //TODO remove this I think
    nonce: [u8; 12],
}

impl CipherState {
    pub(crate) fn new(key: [u8; 32], salt: [u8; 32]) -> Self {
        CipherState {
            secret_key: key,
            salt,
            inner_nonce: 0,
            nonce: [0; 12],
        }
    }

    fn update(&mut self) -> [u8; 12] {
        self.nonce[4..8].copy_from_slice(&self.inner_nonce.to_le_bytes());
        self.nonce
    }

    pub fn rotate_key(&mut self) {
        let old = self.secret_key;
        let (salt, next) = expand(old, self.salt);

        self.salt.copy_from_slice(&salt);
        self.secret_key.copy_from_slice(&next);

        self.inner_nonce = 0;
        self.update();
    }

    //TODO this needs heavy testing.
    pub fn encrypt(&mut self, pt: &[u8], ad: &[u8]) -> Vec<u8> {
        let mut ciphertext = Vec::with_capacity(pt.len());

        //TODO can't unwrap, need actual error handling here
        let tag = chacha20_poly1305_aead::encrypt(
            &self.secret_key,
            &self.nonce,
            &ad,
            &pt,
            &mut ciphertext,
        )
        .unwrap();

        self.inner_nonce += 1;
        self.update();

        if self.inner_nonce == ROTATION_INTERVAL {
            self.rotate_key();
        }

        tag.to_vec()
    }

    pub fn decrypt(&mut self, ct: &[u8], tag: &[u8], ad: &[u8]) -> bool {
        let mut plaintext = Vec::with_capacity(ct.len());

        let result = chacha20_poly1305_aead::decrypt(
            &self.secret_key,
            &self.nonce,
            &ad,
            &tag,
            &ct,
            &mut plaintext,
        );

        match result {
            Ok(_) => {
                self.inner_nonce += 1;
                self.update();

                if self.inner_nonce == ROTATION_INTERVAL {
                    self.rotate_key();
                }

                true
            }
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use hex;

    #[test]
    fn test_cipher_state_new() {
        //TODO use random bytes
        let mut key = [0_u8; 32];
        key.copy_from_slice(
            &hex::decode("2121212121212121212121212121212121212121212121212121212121212121")
                .unwrap(),
        );

        let mut salt = [0_u8; 32];
        salt.copy_from_slice(
            &hex::decode("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap(),
        );

        let cipher = CipherState::new(key, salt);

        assert_eq!(cipher.secret_key, key);

        assert_eq!(cipher.salt, salt);
    }

    #[test]
    fn test_cipher_state_rotate_key() {
        //TODO use random bytes here.
        //TODO one test with random bytes, one not
        let mut key = [0_u8; 32];
        key.copy_from_slice(
            &hex::decode("2121212121212121212121212121212121212121212121212121212121212121")
                .unwrap(),
        );

        let mut salt = [0_u8; 32];
        salt.copy_from_slice(
            &hex::decode("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap(),
        );

        let mut cipher = CipherState::new(key, salt);

        cipher.rotate_key();

        dbg!(&cipher.secret_key);

        //Key and salt should be different.
        assert_ne!(cipher.secret_key, key);
        assert_ne!(cipher.salt, salt);

        //Counter should be reset
        assert_eq!(cipher.inner_nonce, 0);
    }

    // #[test]
    // fn test_cipher_state_rotate_key() {}
}
