use chacha20_poly1305_aead::DecryptError;
use std::fmt;
use std::io;

#[derive(Debug)]
pub enum Error {
    ChaCha20Decrypt(DecryptError),
    Io(io::Error),
}

impl From<DecryptError> for Error {
    fn from(e: DecryptError) -> Error {
        Error::ChaCha20Decrypt(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::ChaCha20Decrypt(ref e) => write!(f, "ChaCha20 decryption error: {}", e),
            Error::Io(ref e) => write!(f, "IO error: {}", e),
        }
    }
}
