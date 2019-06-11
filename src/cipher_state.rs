use crate::common::ROTATION_INTERVAL;
use crate::types::{Nonce, Salt, SecretKey, Tag};
use crate::util::expand;
use crate::Result;
use chacha20_poly1305_aead;

#[derive(Debug)]
pub(crate) struct CipherState {
    secret_key: SecretKey,
    salt: Salt,
    //ChaCha20_poly1305 calls for a 96 bit nonce, with a 32 bit counter. Therefore we are only
    //going to use u32 as our counter as opposed to u64.
    counter: u32,
}

impl CipherState {
    pub(crate) fn new(key: SecretKey, salt: Salt) -> Self {
        CipherState {
            secret_key: key,
            salt,
            counter: 0,
        }
    }

    fn rotate_key(&mut self) {
        let old = self.secret_key;
        let (salt, next) = expand(&old, &self.salt);

        self.salt = salt;
        self.secret_key = next;

        self.counter = 0;
    }

    pub(crate) fn encrypt(&mut self, pt: &[u8], ad: &[u8], ct: &mut Vec<u8>) -> Result<Tag> {
        let nonce = Nonce::from_counter(self.counter);

        let tag = chacha20_poly1305_aead::encrypt(&self.secret_key, &nonce, &ad, &pt, ct)?;

        self.counter += 1;

        if self.counter == ROTATION_INTERVAL {
            self.rotate_key();
        }

        Ok(Tag::from(tag))
    }

    pub(crate) fn decrypt(&mut self, ct: &[u8], tag: Tag, ad: &[u8], pt: &mut Vec<u8>) -> bool {
        let nonce = Nonce::from_counter(self.counter);

        let result = chacha20_poly1305_aead::decrypt(&self.secret_key, &nonce, &ad, &ct, &tag, pt);

        match result {
            Ok(_) => {
                self.counter += 1;

                if self.counter == ROTATION_INTERVAL {
                    self.rotate_key();
                }

                true
            }
            Err(_) => false,
        }
    }

    #[cfg(test)]
    pub fn secret_key(&self) -> SecretKey {
        self.secret_key
    }

    #[cfg(test)]
    pub fn salt(&self) -> Salt {
        self.salt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    fn cipher_state_setup() -> (CipherState, SecretKey, Salt) {
        let key =
            SecretKey::from_str("2121212121212121212121212121212121212121212121212121212121212121")
                .expect("invalid private key");

        let salt =
            Salt::from_str("1111111111111111111111111111111111111111111111111111111111111111")
                .expect("invalid salt");

        (CipherState::new(key, salt), key, salt)
    }

    #[test]
    fn test_cipher_state_new() {
        let key =
            SecretKey::from_str("2121212121212121212121212121212121212121212121212121212121212121")
                .expect("invalid private key");

        let salt =
            Salt::from_str("1111111111111111111111111111111111111111111111111111111111111111")
                .expect("invalid salt");

        let cipher = CipherState::new(key, salt);

        assert_eq!(cipher.secret_key, key);

        assert_eq!(cipher.salt, salt);
    }

    #[test]
    fn test_cipher_state_rotate_key() {
        let key =
            SecretKey::from_str("2121212121212121212121212121212121212121212121212121212121212121")
                .expect("invalid private key");

        let salt =
            SecretKey::from_str("1111111111111111111111111111111111111111111111111111111111111111")
                .expect("invalid salt");

        let mut cipher = CipherState::new(key, salt);

        cipher.rotate_key();

        //Key and salt should be different.
        assert_ne!(cipher.secret_key, key);
        assert_ne!(cipher.salt, salt);

        //Counter should be reset
        assert_eq!(cipher.counter, 0);
    }

    #[test]
    fn test_cipher_state_encrypt() {
        let (mut cipher, _, _) = cipher_state_setup();

        let plain_text = b"hello";

        let mut cipher_text = Vec::with_capacity(plain_text.len());

        let result = cipher.encrypt(plain_text, &[], &mut cipher_text);

        assert!(result.is_ok());

        let tag = result.unwrap();

        assert_ne!(plain_text, cipher_text.as_slice());

        //Round 2

        let mut cipher_text2 = Vec::with_capacity(plain_text.len());

        let result = cipher.encrypt(plain_text, &[], &mut cipher_text2);

        assert!(result.is_ok());

        let tag2 = result.unwrap();

        assert_ne!(cipher_text2, plain_text);

        //Ensure nonce rotates and data isn't the same.
        assert_ne!(cipher_text, cipher_text2);

        assert_ne!(tag, tag2);

        //Test associated data
        let (mut cipher, _, _) = cipher_state_setup();

        let plain_text = b"hello";

        let associated_data = b"testtest123";

        let mut cipher_text3 = Vec::with_capacity(plain_text.len());

        let result = cipher.encrypt(plain_text, associated_data, &mut cipher_text3);

        assert!(result.is_ok());

        let tag3 = result.unwrap();

        assert_ne!(cipher_text3, plain_text);

        assert_ne!(tag, tag3);
    }

    #[test]
    fn test_cipher_state_encrypt_key_rotate() {
        let (mut cipher, key, salt) = cipher_state_setup();

        let plain_text = b"hello, friends";

        let associated_data = b"test123";

        cipher.counter = 999;

        let mut cipher_text = Vec::with_capacity(plain_text.len());

        let result = cipher.encrypt(plain_text, associated_data, &mut cipher_text);

        assert!(result.is_ok());

        assert_ne!(cipher.secret_key, key);

        assert_ne!(cipher.salt, salt);

        assert_eq!(cipher.counter, 0);
    }

    #[test]
    fn test_cipher_state_decrypt() {
        let (mut cipher, _, _) = cipher_state_setup();

        let plain_text = b"hello, friends";

        let mut cipher_text = Vec::with_capacity(plain_text.len());

        let result = cipher.encrypt(plain_text, &[], &mut cipher_text);

        assert!(result.is_ok());

        let tag = result.unwrap();

        let (mut cipher2, _, _) = cipher_state_setup();

        let mut plain_text_decrypted = Vec::with_capacity(plain_text.len());

        assert!(cipher2.decrypt(&cipher_text, tag, &[], &mut plain_text_decrypted));

        assert_eq!(plain_text, plain_text_decrypted.as_slice());
    }

    #[test]
    fn test_cipher_state_decrypt_rotation() {
        let (mut cipher, _, _) = cipher_state_setup();
        let (mut cipher2, _, _) = cipher_state_setup();

        for _ in 0..1001 {
            let plain_text = b"hello, friends";

            let mut cipher_text = Vec::with_capacity(plain_text.len());

            let result = cipher.encrypt(plain_text, &[], &mut cipher_text);

            assert!(result.is_ok());

            let tag = result.unwrap();

            let mut plain_text_decrypted = Vec::with_capacity(plain_text.len());

            assert!(cipher2.decrypt(&cipher_text, tag, &[], &mut plain_text_decrypted));

            assert_eq!(plain_text, plain_text_decrypted.as_slice());
        }
    }
}
