use chacha20_poly1305_aead;

use crate::common::ROTATION_INTERVAL;
use crate::util::expand;
use crate::Result;

//TODO more tests
//TODO make keys their own types
//TODO benchmarks
//
//TODO manually implement debug and print hex of the keys not bytes

#[derive(Debug)]
pub struct CipherState {
    secret_key: [u8; 32],
    salt: [u8; 32],
    //ChaCha20_poly1305 calls for a 96 bit nonce, with a 32 bit counter. Therefore we are only
    //going to use u32 as our counter as opposed to u64.
    counter: u32,
}

impl CipherState {
    pub fn new(key: [u8; 32], salt: [u8; 32]) -> Self {
        CipherState {
            secret_key: key,
            salt,
            counter: 0,
        }
    }

    fn get_nonce(&self) -> [u8; 12] {
        let mut nonce = [0_u8; 12];
        nonce[4..8].copy_from_slice(&self.counter.to_le_bytes());
        nonce
    }

    pub fn rotate_key(&mut self) {
        let old = self.secret_key;
        let (salt, next) = expand(&old, &self.salt);

        self.salt.copy_from_slice(&salt);
        self.secret_key.copy_from_slice(&next);

        self.counter = 0;
    }

    //TODO this needs heavy testing.
    //TODO test if the available size for cipher text makes a difference.
    //Empty Vec vs Vec with capactiy TODO test tomorrow
    pub fn encrypt(&mut self, pt: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
        let mut ciphertext = Vec::with_capacity(pt.len());

        let nonce = self.get_nonce();

        //TODO implement chacha20 ourselves, and place heavy importances on benchmarking
        let tag =
            chacha20_poly1305_aead::encrypt(&self.secret_key, &nonce, &ad, &pt, &mut ciphertext)?;

        self.counter += 1;

        if self.counter == ROTATION_INTERVAL {
            self.rotate_key();
        }

        Ok(tag.to_vec())
    }

    pub fn decrypt(&mut self, ct: &[u8], tag: &[u8], ad: &[u8]) -> bool {
        let mut plaintext = Vec::with_capacity(ct.len());

        let nonce = self.get_nonce();

        let result = chacha20_poly1305_aead::decrypt(
            &self.secret_key,
            &nonce,
            &ad,
            &tag,
            &ct,
            &mut plaintext,
        );

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    fn cipher_state_setup() -> (CipherState, [u8; 32], [u8; 32]) {
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

        (CipherState::new(key, salt), key, salt)
    }

    //TODO Intergrate random tests
    // fn cipher_state_setup_random() {

    // }

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

        //Key and salt should be different.
        assert_ne!(cipher.secret_key, key);
        assert_ne!(cipher.salt, salt);

        //Counter should be reset
        assert_eq!(cipher.counter, 0);
    }

    #[test]
    fn test_cipher_state_encrypt() {
        let (mut cipher, key, salt) = cipher_state_setup();

        let plain_text = b"hello";

        let associated_data = b"hello";

        let result = cipher.encrypt(plain_text, associated_data);

        assert!(result.is_ok());

        let cipher_data = result.unwrap();

        assert_ne!(cipher_data, plain_text);

        //Round 2

        let result = cipher.encrypt(plain_text, associated_data);

        assert!(result.is_ok());

        let cipher_data2 = result.unwrap();

        assert_ne!(cipher_data, plain_text);

        //Ensure nonce rotates and data isn't the same.
        assert_ne!(cipher_data, cipher_data2);

        //Test Cipher is deterministic
        let (mut cipher, key, salt) = cipher_state_setup();

        let plain_text = b"hello";

        let associated_data = b"hello";

        let result = cipher.encrypt(plain_text, associated_data);

        assert!(result.is_ok());

        let cipher_data2 = result.unwrap();

        assert_ne!(cipher_data2, plain_text);

        assert_eq!(cipher_data, cipher_data2);
    }

    #[test]
    fn test_cipher_state_encrypt_key_rotate() {
        let (mut cipher, key, salt) = cipher_state_setup();

        let plain_text = b"hello, friends";

        let associated_data = b"test123";

        cipher.counter = 999;

        let result = cipher.encrypt(plain_text, associated_data);

        assert!(result.is_ok());

        let cipher_data = result.unwrap();

        assert_ne!(cipher_data, plain_text);

        assert_ne!(cipher.secret_key, key);

        assert_ne!(cipher.salt, salt);

        assert_eq!(cipher.counter, 0);
    }

    //#[test]
    //fn test_cipher_state_decrypt() {
    //    //TODO put this in a test setup function.
    //    //Or hardcode the encrypted stuff.
    //    let (mut cipher, key, salt) = cipher_state_setup();

    //    let plain_text = b"hello, friends";

    //    let associated_data = b"test123";

    //    cipher.counter = 999;

    //    let result = cipher.encrypt(plain_text, associated_data);

    //    assert!(result.is_ok());

    //    let cipher_data = result.unwrap();
    //}

    //TODO test decrypt nonce rotation.
    //
    //TODO test panics as well, apparently there is a macro for this.
    //TODO fuzzing -> See rust bitcoin lib
}
