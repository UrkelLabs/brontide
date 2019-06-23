use crate::brontide::Brontide;
use crate::error::Error;
use crate::types::{ActState, PacketSize, PublicKey, SecretKey};
use crate::Result;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::marker::Unpin;

pub struct BrontideStreamBuilder<T>
where
    T: AsyncRead + AsyncWrite + AsyncReadExt + AsyncWriteExt + Unpin,
{
    socket: T,
    local_secret: SecretKey,
    remote_public: Option<PublicKey>,
    prologue: Option<String>,
    packet_size: PacketSize,
    initiator: bool,
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
            initiator: false,
        }
    }

    pub fn with_packet_size(mut self, size: PacketSize) -> Self {
        self.packet_size = size;
        self
    }

    pub fn with_prologue(mut self, prologue: &str) -> Self {
        self.prologue = Some(prologue.to_owned());
        self
    }

    pub fn connector<U: Into<PublicKey>>(mut self, remote_public: U) -> Self {
        self.remote_public = Some(remote_public.into());
        self.initiator = true;
        self
    }

    pub fn acceptor(mut self) -> Self {
        self.remote_public = None;
        self.initiator = false;
        self
    }

    pub fn build(self) -> BrontideStream<T> {
        BrontideStream {
            socket: self.socket,
            brontide: Brontide::new(
                self.initiator,
                self.local_secret,
                self.remote_public,
                self.prologue,
                self.packet_size,
            ),
        }
    }
}

pub struct BrontideStream<T>
where
    T: AsyncRead + AsyncWrite + AsyncReadExt + AsyncWriteExt + Unpin,
{
    socket: T,
    brontide: Brontide,
}

impl<T> BrontideStream<T>
where
    T: AsyncRead + AsyncWrite + AsyncReadExt + AsyncReadExt + Unpin,
{
    //TODO need to implement timeouts here. See: https://docs.rs/futures-timer/0.2.1/futures_timer/
    pub async fn start(&mut self) -> Result<()> {
        if self.brontide.initiator() {
            let act_one = self.brontide.gen_act_one()?;
            self.socket.write_all(&act_one).await?;

            let mut act_two = [0_u8; 50];
            self.socket.read_exact(&mut act_two).await?;
            self.brontide.recv_act_two(act_two)?;

            let act_three = self.brontide.gen_act_three()?;
            self.socket.write_all(&act_three).await?;
        } else {
            let mut act_one = [0_u8; 50];
            self.socket.read_exact(&mut act_one).await?;
            self.brontide.recv_act_one(act_one)?;

            let act_two = self.brontide.gen_act_two()?;
            self.socket.write_all(&act_two).await?;

            let mut act_three = [0_u8; 66];
            self.socket.read_exact(&mut act_three).await?;
            self.brontide.recv_act_three(act_three)?;
        }

        Ok(())
    }

    pub async fn write(&mut self, data: Vec<u8>) -> Result<()> {
        if self.brontide.act_state() == ActState::None {
            return Err(Error::HandshakeNotComplete);
        }

        //TODO not sure if we want to support this -> It's unlikely that someone will attempt to
        //write to a socket before the connection is finished.
        if self.brontide.act_state() != ActState::Done {
            //Push data to buffer for later. TODO
            //self.buffer.extend(data);
            return Err(Error::HandshakeNotComplete);
        }

        let length = data.len();

        //Need to do same as brontide
        // if length > std::u16::MAX as usize {
        // TODO make these errors verbose "Tried to write: , Ma writeable: xxx
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
