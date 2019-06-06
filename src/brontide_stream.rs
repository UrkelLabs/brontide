use crate::brontide::Brontide;
// use futures::io::{AsyncRead, AsyncWrite};
use futures::prelude::*;

//TODO not sure if we want this to be all caps syntax, or if we follow other enum syntax.
//Look into common practices here around "constant" enums
enum State {
    ACT_NONE,
    ACT_ONE,
    ACT_TWO,
    ACT_THREE,
}

//TODO this might actually have to be AsyncReadExt and AsyncWriteExt to have the functions I'm
//using.
pub struct BrontideStream<T>
where
    T: AsyncReadExt + AsyncWriteExt,
{
    socket: T,
    state: State,
    brontide: Brontide,
}

//TODO check on this.... Not sure if we are doing the impl correctly
impl BrontideStream<T>
where
    T: AsyncReadExt + AsyncReadExt,
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

        //Probably want to await this here.
        self.start();
    }

    //TODO we probably want this returning a future.
    pub fn start(&mut self, socket: T) {
        if self.initiator {
            self.state = State::ActTwo;
            //TODO not sure if we need this I think we can infer size from the socket.
            // self.waiting = Act_two_size;
            let act_one = self.brontide.gen_act_one();
            //TODO await this.
            socket.write_all(act_one); //.await?
                                       //Catch the error either here, or above and destroy -> I"m thinking above.
        } else {
            self.state = State::ACT_ONE;
            //TODO as above check if this is needed, I think we can infer from reading the stream.
            // self.waiting = act_one_size
        }
    }
}

impl<T> AsRef<T> for BrontideStream<T>
where
    T: AsyncReadExt + AsyncWriteExt,
{
    fn as_ref(&self) -> &T {
        &self.socket
    }
}

impl<T> AsMut<T> for BrontideStream<T>
where
    T: AsyncReadExt + AsyncWriteExt,
{
    fn as_mut(&mut self) -> &mut T {
        &mut self.socket
    }
}
