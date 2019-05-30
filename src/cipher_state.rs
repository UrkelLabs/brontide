use chacha20_poly1305_aead;
use hkdf::Hkdf;

use crate::common::ROTATION_INTERVAL;
use crate::util::expand;

//TODO does this need to be public?
struct CipherState {
    secret_key: [u8; 32],
    salt: [u8; 32],
    inner_nonce: u32,
    nonce: [u8; 12],
}

impl CipherState {
    fn update(&mut self) -> [u8; 12] {
        self.nonce[4..].copy_from_slice(&self.inner_nonce.to_le_bytes());
        self.nonce
    }

    //Todo maybe this a new function.
    pub fn init_key(&mut self, key: Buffer) {
        self.secret_key = key;
        self.nonce = 0;
        self.update();
    }

    //New with salt
    pub fn init_salt(&mut self, key: Buffer, salt: Buffer) {
        self.salt = salt;
        self.init_key(key);
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
    pub fn encrypt(&mut self, pt: Buffer, ad: Buffer) -> Buffer {
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

        Buffer::from(tag.to_vec())
    }

    pub fn decrypt(&mut self, ct: Buffer, tag: Buffer, ad: Buffer) -> bool {
        let mut plaintext = Vec::with_capacity(ct.len());

        let result = chacha20_poly1305_aead::decrypt(
            &self.secret_key,
            &self.iv,
            &ad,
            &tag,
            &ct,
            &mut plaintext,
        );

        match result {
            Err(_) => false,
            Ok(_) => {
                self.nonce += 1;
                self.update();

                if self.nonce == ROTATION_INTERVAL {
                    self.rotate_key();
                }

                true
            }
        }
    }
}
