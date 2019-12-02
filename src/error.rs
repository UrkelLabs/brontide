#[cfg(feature = "stream")]
use async_std::future::TimeoutError;
use hex::FromHexError;
use secp256k1;
use std;
use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Hex(FromHexError),
    Secp256k1(secp256k1::Error),
    ActOneBadVersion,
    ActOneBadKey,
    ActOneBadTag,
    ActTwoBadVersion,
    ActTwoBadKey,
    ActTwoBadTag,
    ActThreeBadVersion,
    ActThreeBadKey,
    ActThreeBadTag,
    BadTag(String),
    DataTooLarge(String),
    NoCipher(String),
    //TODO build more packet errors
    PacketBadSize(String),
    PacketBadTag,
    HandshakeNotComplete,
    StreamClosed,
    #[cfg(feature = "stream")]
    Timeout,
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

#[cfg(feature = "stream")]
impl From<TimeoutError> for Error {
    fn from(_e: TimeoutError) -> Self {
        Error::Timeout
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref e) => write!(f, "IO error: {}", e),
            Error::Hex(ref e) => write!(f, "Hex error: {}", e),
            Error::Secp256k1(ref e) => write!(f, "Secp256k1 error: {}", e),
            Error::BadTag(ref e) => write!(f, "Bad Tag error: {}", e),
            Error::DataTooLarge(ref e) => write!(f, "Data too large error: {}", e),
            Error::NoCipher(ref e) => write!(f, "No Cipher: {}", e),
            Error::PacketBadSize(ref e) => write!(f, "Packet Bad Size: {}", e),
            Error::ActOneBadVersion => write!(f, "Act One Bad Version"),
            Error::ActOneBadKey => write!(f, "Act One Bad Key"),
            Error::ActOneBadTag => write!(f, "Act One Bad Tag"),
            Error::ActTwoBadVersion => write!(f, "Act Two Bad Version"),
            Error::ActTwoBadKey => write!(f, "Act Two Bad Key"),
            Error::ActTwoBadTag => write!(f, "Act Two Bad Tag"),
            Error::ActThreeBadVersion => write!(f, "Act Three Bad Version"),
            Error::ActThreeBadKey => write!(f, "Act Three Bad Key"),
            Error::ActThreeBadTag => write!(f, "Act Three Bad Tag"),
            Error::PacketBadTag => write!(f, "Packet Bad Tag"),
            Error::HandshakeNotComplete => write!(f, "Brontide Handshake not complete"),
            Error::StreamClosed => write!(f, "TCP Stream was closed."),
            #[cfg(feature = "stream")]
            Error::Timeout => write!(f, "Timeout Error"),
        }
    }
}
