pub mod brontide;
pub mod brontide_stream;
pub mod cipher_state;
pub mod common;
pub mod error;
pub mod handshake;
pub mod symmetric_state;
pub mod util;

pub type Result<T> = std::result::Result<T, error::Error>;

//TODO benchmark Cipher
//TODO Move those benchmarks over to HSD
//TODO test changes to hsd where we remove the iv from memory, and only init when needed.
//TODO same goes for Symmetric

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
