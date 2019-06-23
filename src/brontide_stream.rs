use crate::brontide::Brontide;
use crate::error::Error;
use crate::types::{PacketSize, PublicKey, SecretKey};
use crate::Result;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::marker::Unpin;

//TODO not sure if we want this to be all caps syntax, or if we follow other enum syntax.
//Look into common practices here around "constant" enums
//TODO fix clippy issue of all prefixes being act
#[derive(Eq, PartialEq)]
enum ActState {
    None,
    One,
    Two,
    Three,
    Done,
}

pub struct BrontideStreamBuilder<T>
where
    T: AsyncRead + AsyncWrite + AsyncReadExt + AsyncWriteExt + Unpin,
{
    socket: T,
    local_secret: SecretKey,
    remote_public: Option<PublicKey>,
    prologue: Option<String>,
    packet_size: PacketSize,
}

impl<T> BrontideStreamBuilder<T>
where
    T: AsyncRead + AsyncWrite + AsyncReadExt + AsyncWriteExt + Unpin,
{
    pub fn new<U: Into<SecretKey>>(socket: T, local_secret: U) -> Self {
        BrontideStreamBuilder {
            socket,
            local_secret: local_secret.into(),
            remote_public: None,
            prologue: None,
            packet_size: PacketSize::U32,
        }
    }

    pub fn with_packet_size(mut self, size: PacketSize) -> Self {
        self.packet_size = size;
        self
    }

    //TODO think about if we should have this be async and act how it already does,
    //OR if we just have it return a stream, and then have a function on that stream that
    //Starts the stream and returns if it works or not.
    pub async fn connect<U: Into<PublicKey>>(self, remote_public: U) -> Result<BrontideStream<T>> {
        let mut stream = BrontideStream {
            socket: self.socket,
            state: ActState::None,
            brontide: Brontide::new(
                true,
                self.local_secret,
                Some(remote_public.into()),
                None,
                self.packet_size,
            ),
        };

        stream.start().await?;
        //TODO check naming here
        // self.brontide = Brontide::new(true, local_secret, Some(remote_public));

        //Probably want to await this here. TODO
        // self.start(socket).await;

        //Either default, or act_one/two_size
        //TODO self.socket most likely.
        //TODO remove this unwrap, throw error.
        //Make this a custom type TODO
        let mut act_two = [0_u8; 50];
        //TODO ?
        stream.socket.read_exact(&mut act_two).await?;

        stream.brontide.recv_act_two(act_two)?;

        let act_three = stream.brontide.gen_act_three()?;

        stream.socket.write_all(&act_three).await?;

        Ok(stream)
    }
}

pub struct BrontideStream<T>
where
    T: AsyncRead + AsyncWrite + AsyncReadExt + AsyncWriteExt + Unpin,
{
    socket: T,
    state: ActState,
    brontide: Brontide,
}

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
    //pub async fn connect(
    //    socket: T,
    //    local_secret: [u8; 32],
    //    remote_public: [u8; 33],
    //) -> Result<Self> {
    //    let mut stream = BrontideStream {
    //        socket,
    //        state: ActState::None,
    //        brontide: Brontide::new(true, local_secret, Some(remote_public), None),
    //    };

    //    stream.start().await?;
    //    //TODO check naming here
    //    // self.brontide = Brontide::new(true, local_secret, Some(remote_public));

    //    //Probably want to await this here. TODO
    //    // self.start(socket).await;

    //    //Either default, or act_one/two_size
    //    //TODO self.socket most likely.
    //    //TODO remove this unwrap, throw error.
    //    //Make this a custom type TODO
    //    let mut act_two = [0_u8; 50];
    //    //TODO ?
    //    stream.socket.read_exact(&mut act_two).await?;

    //    stream.brontide.recv_act_two(act_two)?;

    //    let act_three = stream.brontide.gen_act_three()?;

    //    stream.socket.write_all(&act_three).await?;

    //    Ok(stream)
    //}

    //TODO this can just be wrapped into connect and accept -> no need for another function.
    //TODO don't think this is publica
    pub async fn start(&mut self) -> Result<()> {
        //TODO instead of doing this, I should expose this as a function
        if self.brontide.initiator() {
            self.state = ActState::Two;
            //TODO not sure if we need this I think we can infer size from the socket.
            // self.waiting = Act_two_size;
            let act_one = self.brontide.gen_act_one()?;
            //TODO await this.
            self.socket.write_all(&act_one).await?;
        //Catch the error either here, or above and destroy -> I"m thinking above.
        } else {
            self.state = ActState::One;
            //TODO as above check if this is needed, I think we can infer from reading the stream.
            // self.waiting = act_one_size
        }

        Ok(())
    }

    pub async fn write(&mut self, data: Vec<u8>) -> Result<()> {
        //TODO
        if self.state == ActState::None {
            return Err(Error::StreamNotReady);
        }

        if self.state != ActState::Done {
            //Push data to buffer for later. TODO
            //self.buffer.extend(data);
            //TODO custom error here. HandshakeNotComplete Could probably use for above as well.
            return Err(Error::StreamNotReady);
        }

        let length = data.len();

        //Need to do same as brontide
        // if length > std::u16::MAX as usize {
        //     return Err(Error::DataTooLarge("Data length too big".to_owned()));
        // }

        let len = [0_u8; 4];

        let encrypted_packet = self.brontide.write(data)?;

        self.socket.write_all(&encrypted_packet).await?;

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
