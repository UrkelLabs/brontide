use crate::types::{PublicKey, SecretKey, SharedSecret};
use crate::Result;
use hkdf::Hkdf;
use secp256k1::{self, ecdh, Secp256k1};
use sha2::Sha256;
use std::convert::TryInto;
use std::str::FromStr;

//TODO see if we need this to be a hardcoded array of 32, or if it can be variable.
pub(crate) fn expand(secret: &[u8], salt: &[u8]) -> (SecretKey, SecretKey) {
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

pub(crate) fn get_public_key(key: SecretKey) -> Result<PublicKey> {
    let secp = Secp256k1::new();

    let secret_key = secp256k1::SecretKey::from_slice(&key)?;
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

    let key = PublicKey::from_str(&public_key.to_string())?;

    Ok(key)
}

pub(crate) fn ecdh(public_key: PublicKey, private_key: SecretKey) -> Result<SharedSecret> {
    let secret = ecdh::SharedSecret::new(
        &secp256k1::PublicKey::from_slice(&public_key)?,
        &secp256k1::SecretKey::from_slice(&private_key)?,
    );

    let shared_secret = SharedSecret::from(secret[..].to_vec().as_ref());

    Ok(shared_secret)
}
