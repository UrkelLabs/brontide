use hex;
use std::{fmt, ops, str::FromStr};

#[derive(Eq, PartialEq, Copy, Clone)]
pub enum ActState {
    None,
    One,
    Two,
    Done,
}

#[derive(Debug, Copy, Clone)]
pub enum PacketSize {
    U16,
    U32,
}

//TODO the &[u8]'s should be converted to TryFrom not From. The error should then be Invalid Secret
//Key/ Invalid Public Key;

/// The number of bytes used to prefix encode the length of a message payload.
/// Can be either 2 bytes (u16) - LND - or 4 bytes (u32) - Handshake
impl PacketSize {
    pub fn max(self) -> usize {
        match self {
            PacketSize::U16 => std::u16::MAX as usize,
            PacketSize::U32 => std::u32::MAX as usize,
        }
    }

    pub fn size(self) -> usize {
        match self {
            PacketSize::U16 => 2,
            PacketSize::U32 => 4,
        }
    }

    ///Returns the length as big endian bytes depending on the packet size.
    pub fn length_buffer(self, length: usize) -> Vec<u8> {
        match self {
            PacketSize::U16 => {
                let length_shortened = length as u16;
                //This might be unneccesary sp?
                let mut buffer = [0; 2];
                buffer.copy_from_slice(&length_shortened.to_be_bytes());
                buffer.to_vec()
            }
            PacketSize::U32 => {
                let length_shortened = length as u32;
                let mut buffer = [0; 4];
                buffer.copy_from_slice(&length_shortened.to_le_bytes());
                buffer.to_vec()
            }
        }
    }

    pub fn length(self, length_buffer: &[u8]) -> usize {
        match self {
            PacketSize::U16 => {
                let length: u16;
                let mut length_bytes = [0; 2];
                length_bytes.copy_from_slice(length_buffer);
                length = u16::from_be_bytes(length_bytes);
                length as usize
            }
            PacketSize::U32 => {
                let length: u32;
                let mut length_bytes = [0; 4];
                length_bytes.copy_from_slice(length_buffer);
                length = u32::from_le_bytes(length_bytes);
                length as usize
            }
        }
    }
}

//TODO only public types inside of this file.
//I take this back possibly>
//Implement debug
#[derive(Eq, PartialEq, Clone, Copy)]
pub struct SecretKey([u8; 32]);

pub type Digest = SecretKey;

pub type Salt = SecretKey;

pub type SharedSecret = SecretKey;

impl SecretKey {
    pub fn empty() -> Self {
        Default::default()
    }
}

impl Default for SecretKey {
    fn default() -> Self {
        SecretKey([0_u8; 32])
    }
}

//This should probably be removed as it could possibly fail.
//TODO likewise
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

impl FromStr for SecretKey {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let string = hex::decode(s)?;

        Ok(SecretKey::from(string.as_slice()))
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

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for SecretKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

#[derive(Eq, PartialEq, Copy, Clone)]
pub struct Tag([u8; 16]);

impl From<[u8; 16]> for Tag {
    fn from(tag: [u8; 16]) -> Self {
        Tag(tag)
    }
}

impl From<&[u8]> for Tag {
    fn from(slice: &[u8]) -> Self {
        let mut array = [0; 16];
        array.copy_from_slice(slice);

        Tag(array)
    }
}

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Tag {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl ops::Deref for Tag {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Tag: {}", hex::encode(self.0))
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

#[derive(Clone, Copy)]
pub struct PublicKey([u8; 33]);

impl PublicKey {
    pub fn empty() -> Self {
        Default::default()
    }
}

impl From<&[u8]> for PublicKey {
    fn from(slice: &[u8]) -> Self {
        let mut array = [0; 33];
        array.copy_from_slice(slice);

        PublicKey(array)
    }
}

impl From<[u8; 33]> for PublicKey {
    fn from(array: [u8; 33]) -> Self {
        PublicKey(array)
    }
}

impl FromStr for PublicKey {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let string = hex::decode(s)?;

        Ok(PublicKey::from(string.as_slice()))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PublicKey: {}", hex::encode(self.0.to_vec()))
    }
}

impl Default for PublicKey {
    fn default() -> Self {
        PublicKey([0_u8; 33])
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for PublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl ops::Deref for PublicKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
