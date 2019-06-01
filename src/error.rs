use chacha20_poly1305_aead::DecryptError;
use std::io;

#[derive(Debug)]
pub enum Error {
    ChaCha20Decrypt(DecryptError),
    Io(io::Error),
}
