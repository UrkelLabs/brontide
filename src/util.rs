use hkdf::Hkdf;
use sha2::Sha256;
use std::convert::TryInto;

//TODO see if we need this to be a hardcoded array of 32, or if it can be variable.
pub(crate) fn expand(secret: &[u8], salt: &[u8]) -> ([u8; 32], [u8; 32]) {
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
