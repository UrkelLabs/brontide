use crate::common::{ACT_ONE_SIZE, ACT_THREE_SIZE};
use crate::types::{PublicKey, Tag};
use std::ops;

//TODO I wonder if I can implement these all programmatically with a macro.
//So we have a marco called impl_act, and it just takes the name of the act and the size.
//That way we can remove all this boilerplate code here.

pub struct ActOne([u8; ACT_ONE_SIZE]);

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

//ActOne and ActTwo are of the act same structure, so we can just reimplement by type here.
pub type ActTwo = ActOne;

pub struct ActThree([u8; ACT_THREE_SIZE]);

impl From<[u8; ACT_THREE_SIZE]> for ActThree {
    fn from(array: [u8; ACT_THREE_SIZE]) -> Self {
        ActThree(array)
    }
}

impl Default for ActThree {
    fn default() -> Self {
        ActThree([0_u8; ACT_THREE_SIZE])
    }
}

//Need to string for this. TODO

impl ActThree {
    //TODO fix this Vec here
    pub fn new(version: u8, key: Vec<u8>, tag: Tag, tag_two: Tag) -> Self {
        let mut inner = [0_u8; ACT_THREE_SIZE];

        inner[0] = version;
        inner[1..34].copy_from_slice(&key);
        inner[34..50].copy_from_slice(&tag);
        inner[50..].copy_from_slice(&tag_two);

        ActThree(inner)
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
        inner.copy_from_slice(&self.0[34..50]);

        Tag::from(inner)
    }

    pub fn tag_two(&self) -> Tag {
        let mut inner = [0; 16];
        inner.copy_from_slice(&self.0[50..]);

        Tag::from(inner)
    }
}

impl ops::Deref for ActThree {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
