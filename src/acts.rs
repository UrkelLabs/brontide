use crate::common::ACT_ONE_SIZE;
use crate::types::{PublicKey, Tag};
use std::ops;

pub struct ActOne([u8; ACT_ONE_SIZE]);

impl ActOne {}

impl From<[u8; ACT_ONE_SIZE]> for ActOne {
    fn from(array: [u8; ACT_ONE_SIZE]) -> Self {
        ActOne(array)
    }
}

impl Default for ActOne {
    fn default() -> Self {
        ActOne([0_u8; ACT_ONE_SIZE])
    }
}

//Need to string for this.

impl ActOne {
    pub fn new(version: u8, key: PublicKey, tag: Tag) -> Self {
        let mut inner = [0_u8; ACT_ONE_SIZE];

        inner[0] = version;
        inner[1..34].copy_from_slice(&key);
        inner[34..].copy_from_slice(&tag);

        ActOne(inner)
    }

    pub fn version(&self) -> u8 {
        self.0[0]
    }

    pub fn key(&self) -> PublicKey {
        let mut inner = [0; 33];
        inner.copy_from_slice(&self.0[1..34]);

        PublicKey::from(inner)
    }

    pub fn tag(&self) -> Tag {
        let mut inner = [0; 16];
        inner.copy_from_slice(&self.0[34..]);

        Tag::from(inner)
    }
}

impl ops::Deref for ActOne {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
