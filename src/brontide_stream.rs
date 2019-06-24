use crate::brontide::Brontide;
use crate::common::HEADER_SIZE;
use crate::error::Error;
use crate::types::{ActState, PacketSize, PublicKey, SecretKey, Tag};
use crate::Result;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures_timer::FutureExt;
use std::marker::Unpin;
use std::time::Duration;

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
    pub async fn start(&mut self) -> Result<()> {
        if self.brontide.initiator() {
            let act_one = self.brontide.gen_act_one()?;
            self.socket
                .write_all(&act_one)
                .timeout(Duration::from_secs(1))
                .await?;

            let mut act_two = [0_u8; 50];
            self.socket
                .read_exact(&mut act_two)
                .timeout(Duration::from_secs(1))
                .await?;
            self.brontide.recv_act_two(act_two)?;

            let act_three = self.brontide.gen_act_three()?;
            self.socket
                .write_all(&act_three)
                .timeout(Duration::from_secs(1))
                .await?;
        } else {
            let mut act_one = [0_u8; 50];
            self.socket
                .read_exact(&mut act_one)
                .timeout(Duration::from_secs(1))
                .await?;
            self.brontide.recv_act_one(act_one)?;

            let act_two = self.brontide.gen_act_two()?;
            self.socket
                .write_all(&act_two)
                .timeout(Duration::from_secs(1))
                .await?;

            let mut act_three = [0_u8; 66];
            self.socket
                .read_exact(&mut act_three)
                .timeout(Duration::from_secs(1))
                .await?;
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

        let encrypted_packet = self.brontide.write(data)?;

        self.socket.write_all(&encrypted_packet).await?;

        Ok(())
    }

    //TODO be able to include a timeout here -> If we do that, I think we then need to be able to
    //flush the connection.
    pub async fn next_message(&mut self) -> Result<Vec<u8>> {
        let mut header = [0; HEADER_SIZE];

        self.socket.read_exact(&mut header).await?;

        let size = self.brontide.packet_size().size();
        let len = &header[..size];
        //This should probably be a tryfrom, so that it throws an error if possible. TODO
        let tag = Tag::from(&header[size..]);

        let mut plain_text = Vec::with_capacity(size);
        let result = self
            .brontide
            .receive_cipher
            .as_mut()
            .ok_or_else(|| Error::NoCipher("receive cipher not initalized".to_owned()))?
            .decrypt(&len, tag, &[], &mut plain_text);

        let length: usize;

        if result {
            length = self.brontide.packet_size().length(&plain_text);
        } else {
            return Err(Error::BadTag("packet header: bad tag".to_owned()));
        };

        if length > self.brontide.packet_size().max() {
            return Err(Error::DataTooLarge(format!(
                "Tried to write: {}, Max: {}",
                length,
                self.brontide.packet_size().max()
            )));
        }

        // let mut body = [0; length + 16];
        let mut body = Vec::with_capacity(length + 16);

        self.socket.read_exact(&mut body).await?;

        Ok(body)
    }

    //pub async fn read(&mut self, data: Vec<u8>) -> Result<(Vec<u8>)> {
    //    if self.brontide.act_state() == ActState::None {
    //        return Err(Error::HandshakeNotComplete);
    //    }

    //    //TODO not sure if we want to support this -> It's unlikely that someone will attempt to
    //    //write to a socket before the connection is finished.
    //    if self.brontide.act_state() != ActState::Done {
    //        //Push data to buffer for later. TODO
    //        //self.buffer.extend(data);
    //        return Err(Error::HandshakeNotComplete);
    //    }

    //    let encrypted_packet = self.brontide.write(data)?;

    //    self.socket.write_all(&encrypted_packet).await?;

    //    Ok(())
    //}
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
