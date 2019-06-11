use crate::types;
use hex;
use hkdf::Hkdf;
use secp256k1::{ecdh::SharedSecret, PublicKey, Secp256k1, SecretKey};
use sha2::Sha256;
use std::convert::TryInto;

//TODO see if we need this to be a hardcoded array of 32, or if it can be variable.
pub(crate) fn expand(secret: &[u8], salt: &[u8]) -> (types::SecretKey, types::SecretKey) {
    //TODO test this logic.
    //TODO test and benchmark this, transfer those to HSd.
    //hk.prk
    let hk = Hkdf::<Sha256>::extract(Some(&salt), &secret);
    let mut out = [0u8; 64];
    //TODO remove unwrap
    hk.expand(&[], &mut out).unwrap();

    //TODO catch these errors instead, but try into is the way to go here.
    (
        out[..32].try_into().expect("slice not sized correctly"),
        out[32..].try_into().expect("slice not sized correctly"),
    )
}

pub(crate) fn get_public_key(private_key: [u8; 32]) -> [u8; 33] {
    let secp = Secp256k1::new();
    //TODO handle this error correctly.
    let secret_key = SecretKey::from_slice(&private_key).expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    let mut key = [0_u8; 33];

    //TODO remove this unwrap and handle accordingly.
    key.copy_from_slice(&hex::decode(public_key.to_string()).unwrap());

    key
}

//TODO double check the shared secret is 32 bits
//Return a Result TODO
pub(crate) fn ecdh(public_key: [u8; 33], private_key: [u8; 32]) -> [u8; 32] {
    //TODO super ugly, let's clean this up with better error handling
    let secret = SharedSecret::new(
        &PublicKey::from_slice(&public_key).unwrap(),
        &SecretKey::from_slice(&private_key).unwrap(),
    );

    //TODO this is how we use the FFI library better, use this example for the rest of the code.
    let secret_vec = secret[..].to_vec();

    let mut return_digest = [0_u8; 32];

    return_digest.copy_from_slice(secret_vec.as_slice());

    return_digest
}
