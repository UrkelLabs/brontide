use hkdf::Hkdf;
use sha2::Sha256;

pub(crate) fn expand(secret: [u8; 32], salt: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
    //hk.prk
    let hk = Hkdf::<Sha256>::extract(Some(&salt), &secret);
    let mut out = [0u8; 64];
    //TODO remove unwrap
    hk.expand(&[], &mut out).unwrap();

    //TODO double check this
    (out[0..32].to_vec(), out[32..64].to_vec())
}
