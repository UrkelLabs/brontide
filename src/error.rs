use hex::FromHexError;
use secp256k1;
use std;
use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Hex(FromHexError),
    Secp256k1(secp256k1::Error),
    //TODO naming on these. - technically all "bad-xyz"
    Version(String),
    BadKey(String),
    BadTag(String),
    DataTooLarge(String),
    NoCipher(String),
    //TODO build more packet errors
    PacketBadSize(String),
    StreamNotReady,
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<FromHexError> for Error {
    fn from(e: FromHexError) -> Self {
        Error::Hex(e)
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Self {
        Error::Secp256k1(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref e) => write!(f, "IO error: {}", e),
            Error::Hex(ref e) => write!(f, "Hex error: {}", e),
            Error::Secp256k1(ref e) => write!(f, "Secp256k1 error: {}", e),
            Error::Version(ref e) => write!(f, "Version error: {}", e),
            Error::BadKey(ref e) => write!(f, "Bad Key error: {}", e),
            Error::BadTag(ref e) => write!(f, "Bad Tag error: {}", e),
            Error::DataTooLarge(ref e) => write!(f, "Data too large error: {}", e),
            Error::NoCipher(ref e) => write!(f, "No Cipher: {}", e),
            Error::PacketBadSize(ref e) => write!(f, "Packet Bad Size: {}", e),
            Error::StreamNotReady => write!(f, "Brontide Stream not ready"),
        }
    }
}
