pub mod cipher_state;
pub mod common;
pub mod error;
pub mod util;

pub type Result<T> = std::result::Result<T, error::Error>;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
