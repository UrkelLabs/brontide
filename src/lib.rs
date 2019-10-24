//TODO check which should be public
pub mod acts;
pub mod brontide;
pub mod builder;
pub mod cipher_state;
pub mod common;
pub mod error;
pub mod handshake;
#[cfg(feature = "stream")]
pub mod stream;
pub mod symmetric_state;
pub mod types;
pub mod util;

pub use crate::brontide::Brontide;
pub use crate::builder::BrontideBuilder;
pub use crate::error::Error;
pub use crate::types::PacketSize;
pub use crate::types::PublicKey;
pub use crate::types::SecretKey;

#[cfg(feature = "stream")]
pub use crate::stream::BrontideStream;

pub type Result<T> = std::result::Result<T, error::Error>;

//TODO benchmark Cipher
//TODO Move those benchmarks over to HSD
//TODO test changes to hsd where we remove the iv from memory, and only init when needed.
//TODO same goes for Symmetric
