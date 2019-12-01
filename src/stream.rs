use crate::brontide::Brontide;
use crate::common::HEADER_SIZE;
use crate::error::Error;
use crate::types::{ActState, PacketSize, PublicKey, SecretKey, Tag};
use crate::Result;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures::task::AtomicWaker;
use futures::task::Context;
use futures::task::Poll;
use futures::FutureExt;
use futures::Stream;
use futures::{ready, Future};

use std::io;
use std::mem;
use std::pin::Pin;
use std::time::Duration;
//TODO clean up all these ^ remove unused, and organize.

use async_std::future::timeout;
use async_std::net::TcpStream;

//Making public until we can clean up tests @todo
pub struct BrontideStream {
    pub stream: TcpStream,
    pub brontide: Brontide,
}

// ===== impl BrontideStream =====

impl BrontideStream {
    pub fn new(stream: TcpStream, brontide: Brontide) -> BrontideStream {
        BrontideStream { stream, brontide }
    }

    pub async fn connect(stream: TcpStream, brontide: Brontide) -> Result<BrontideStream> {
        let mut bstream = BrontideStream::new(stream, brontide);
        let act_one = bstream.brontide.gen_act_one()?;
        timeout(Duration::from_secs(1), bstream.stream.write_all(&act_one)).await?;

        let mut act_two = [0_u8; 50];
        timeout(
            Duration::from_secs(1),
            bstream.stream.read_exact(&mut act_two),
        )
        .await?;
        bstream.brontide.recv_act_two(act_two)?;

        let act_three = bstream.brontide.gen_act_three()?;
        timeout(Duration::from_secs(1), bstream.stream.write_all(&act_three)).await?;

        Ok(bstream)
    }

    pub async fn accept(stream: TcpStream, brontide: Brontide) -> Result<BrontideStream> {
        let mut bstream = BrontideStream::new(stream, brontide);
        let mut act_one = [0_u8; 50];
        timeout(
            Duration::from_secs(1),
            bstream.stream.read_exact(&mut act_one),
        )
        .await?;
        bstream.brontide.recv_act_one(act_one)?;

        let act_two = bstream.brontide.gen_act_two()?;
        timeout(Duration::from_secs(1), bstream.stream.write_all(&act_two)).await?;

        let mut act_three = [0_u8; 66];
        timeout(
            Duration::from_secs(1),
            bstream.stream.read_exact(&mut act_three),
        )
        .await?;
        bstream.brontide.recv_act_three(act_three)?;

        Ok(bstream)
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        if self.brontide.act_state() == ActState::None {
            return Err(Error::HandshakeNotComplete);
        }

        let encrypted_packet = self.brontide.encode(data)?;

        self.stream.write_all(&encrypted_packet).await?;

        Ok(())
    }

    //TODO be able to include a timeout here -> If we do that, I think we then need to be able to
    //flush the connection.
    //TODO should handle EOF, and just continue to loop.
    pub async fn next_message(&mut self) -> Result<Vec<u8>> {
        //This has to be dynamic based on packet size.
        let mut header = [0; HEADER_SIZE];

        self.stream.read_exact(&mut header).await?;

        let size = self.brontide.packet_size().size();
        let len = &header[..size];

        //This should probably be a tryfrom, so that it throws an error if possible. TODO
        let tag1 = Tag::from(&header[size..]);

        let mut plain_text = Vec::with_capacity(size);
        let result = self
            .brontide
            .receive_cipher
            .as_mut()
            .ok_or_else(|| Error::NoCipher("receive cipher not initalized".to_owned()))?
            .decrypt(&len, tag1, &[], &mut plain_text);

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
        let mut body = vec![0; length + 16];

        //TODO explore using read_to_end here, then our vector will grow for us.
        self.stream.read_exact(&mut body).await?;

        let encrypted_message = &body[..length];
        //TODO make this a tryfrom, so it throw an error
        let tag2 = Tag::from(&body[length..]);

        let mut message = Vec::with_capacity(length);

        if !self
            .brontide
            .receive_cipher
            .as_mut()
            .ok_or_else(|| Error::NoCipher("receive cipher not initalized".to_owned()))?
            .decrypt(encrypted_message, tag2, &[], &mut message)
        {
            return Err(Error::BadTag("packet message: bad tag".to_owned()));
        };

        Ok(message)
    }
}

impl Stream for BrontideStream {
    type Item = Vec<u8>;
    // type Item = Result<UnencryptedPacket>

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.next_message().boxed().as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            //TODO I think if we receive an error from the value (Timeout error), then we close the
            //stream.
            Poll::Ready(Err(e)) => Poll::Ready(None),
            Poll::Ready(Ok(value)) => Poll::Ready(Some(value)),
        }
    }
}
