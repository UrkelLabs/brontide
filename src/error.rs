use hex::FromHexError;
use std;
use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Hex(FromHexError),
    //TODO naming on these. - technically all "bad-xyz"
    Version(String),
    BadKey(String),
    BadTag(String),
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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref e) => write!(f, "IO error: {}", e),
            Error::Hex(ref e) => write!(f, "Hex error: {}", e),
            Error::Version(ref e) => write!(f, "Version error: {}", e),
            Error::BadKey(ref e) => write!(f, "Bad Key error: {}", e),
            Error::BadTag(ref e) => write!(f, "Bad Tag error: {}", e),
        }
    }
}
