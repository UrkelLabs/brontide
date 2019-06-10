use hex;
use std::fmt;
use std::ops;

//TODO only public types inside of this file.
//I take this back possibly>
//Implement debug
pub struct SecretKey([u8; 32]);

impl From<&[u8]> for SecretKey {
    fn from(slice: &[u8]) -> Self {
        let mut array = [0; 32];
        array.copy_from_slice(slice);

        SecretKey(array)
    }
}

impl From<[u8; 32]> for SecretKey {
    fn from(array: [u8; 32]) -> Self {
        SecretKey(array)
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SecretKey: {}", hex::encode(self.0))
    }
}

impl ops::Deref for SecretKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

//Crate public Structs
pub(crate) struct Nonce([u8; 12]);

impl Nonce {
    pub(crate) fn from_counter(counter: u32) -> Self {
        let mut nonce = [0_u8; 12];
        nonce[4..8].copy_from_slice(&counter.to_le_bytes());

        Nonce(nonce)
    }
}

impl ops::Deref for Nonce {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// impl AsRef<[u8]> for SecretKey {
//     fn as_ref(&self) -> &[u8] {
//         &self.0
//     }
// }

// impl AsMut<[u8]> for SecretKey {
//     fn as_mut(&mut self) -> &mut [u8] {
//         &mut self.0
//     }
// }

pub struct PublicKey([u8; 32]);

// impl AsRef<[u8]> for PublicKey {
//     fn as_ref(&self) -> &[u8] {
//         &self.0
//     }
// }

// impl AsMut<[u8]> for PublicKey {
//     fn as_mut(&mut self) -> &mut [u8] {
//         &mut self.0
//     }
// }
