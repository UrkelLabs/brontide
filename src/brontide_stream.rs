use crate::brontide::Brontide;
// use crate::Result;
use futures::io::Error;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::marker::Unpin;
// #![feature(async_await)]
// use futures::prelude::*;

//TODO not sure if we want this to be all caps syntax, or if we follow other enum syntax.
//Look into common practices here around "constant" enums
//TODO fix clippy issue of all prefixes being act
enum ActState {
    None,
    One,
    Two,
    Three,
}

//TODO this might actually have to be AsyncReadExt and AsyncWriteExt to have the functions I'm
//using.
pub struct BrontideStream<T>
where
    T: AsyncRead + AsyncWrite + AsyncReadExt + AsyncWriteExt + Unpin,
{
    socket: T,
    state: ActState,
    brontide: Brontide,
}

//TODO check on this.... Not sure if we are doing the impl correctly
impl<T> BrontideStream<T>
where
    T: AsyncRead + AsyncWrite + AsyncReadExt + AsyncReadExt + Unpin,
{
    //TODO just make this config
    // fn read_timeout() -> Duration {
    //     Duration::new(5, 0)
    // }

    //TODO more descriptive name for key here.
    // pub fn accept(&mut self, socket: T, key: [u8; 32]) {
    //     self.socket = socket;
    //     // self.init(false, key);
    // }

    //TODO check these names for local secret and remote public -> I think this hsould be local
    //public key NOT local secret
    //TODO returns a future, let's get the correct type.
    pub fn connect(&mut self, socket: T, local_secret: [u8; 32], remote_public: [u8; 32]) {
        //TODO check naming here
        self.brontide = Brontide::new(true, local_secret, Some(remote_public));

        //Probably want to await this here. TODO
        self.start(socket);
    }

    //TODO we probably want this returning a future.
    pub async fn start(&mut self, mut socket: T) -> Result<(), Error> {
        //TODO instead of doing this, I should expose this as a function
        if self.brontide.initiator() {
            self.state = ActState::Two;
            //TODO not sure if we need this I think we can infer size from the socket.
            // self.waiting = Act_two_size;
            let act_one = self.brontide.gen_act_one();
            //TODO await this.
            socket.write_all(&act_one).await?;
        //Catch the error either here, or above and destroy -> I"m thinking above.
        } else {
            self.state = ActState::One;
            //TODO as above check if this is needed, I think we can infer from reading the stream.
            // self.waiting = act_one_size
        }

        Ok(())
    }
}

impl<T> AsRef<T> for BrontideStream<T>
where
    T: AsyncReadExt + AsyncWriteExt + Unpin,
{
    fn as_ref(&self) -> &T {
        &self.socket
    }
}

impl<T> AsMut<T> for BrontideStream<T>
where
    T: AsyncReadExt + AsyncWriteExt + Unpin,
{
    fn as_mut(&mut self) -> &mut T {
        &mut self.socket
    }
}
