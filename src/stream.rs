use crate::brontide::Brontide;
use crate::common::HEADER_SIZE;
use crate::error::Error;
use crate::types::{ActState, PacketSize, PublicKey, SecretKey, Tag};
use crate::Result;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures::task::AtomicWaker;
use futures::task::Context;
use futures::task::Poll;
use futures::Stream;
use futures_timer::FutureExt;
use std::io;
use std::pin::Pin;
use std::time::Duration;
//TODO clean up all these ^ remove unused, and organize.

use runtime::net::TcpStream;

//Might need to be Atomic
pub struct Inner {
    waiting: usize,
    total: usize,
    //TODO should this be atomic bool?
    has_size: bool,
    pending: Vec<u8>,
    waker: AtomicWaker,
}

//Possibly make a new function, and then remove the pub crates here (TODO)
pub struct BrontideStream {
    stream: TcpStream,
    brontide: Brontide,
    inner: Inner,
}

// ===== impl BrontideStream =====

impl BrontideStream {
    pub fn new(stream: TcpStream, brontide: Brontide) -> BrontideStream {
        let inner = Inner {
            waiting: HEADER_SIZE,
            has_size: false,
            total: 0,
            pending: Vec::new(),
            waker: AtomicWaker::new(),
        };

        BrontideStream {
            stream,
            brontide,
            inner,
        }
    }
    pub async fn start(&mut self) -> Result<()> {
        if self.brontide.initiator() {
            let act_one = self.brontide.gen_act_one()?;
            self.stream
                .write_all(&act_one)
                .timeout(Duration::from_secs(1))
                .await?;

            let mut act_two = [0_u8; 50];
            self.stream
                .read_exact(&mut act_two)
                .timeout(Duration::from_secs(1))
                .await?;
            self.brontide.recv_act_two(act_two)?;

            let act_three = self.brontide.gen_act_three()?;
            self.stream
                .write_all(&act_three)
                .timeout(Duration::from_secs(1))
                .await?;
        } else {
            let mut act_one = [0_u8; 50];
            self.stream
                .read_exact(&mut act_one)
                .timeout(Duration::from_secs(1))
                .await?;
            self.brontide.recv_act_one(act_one)?;

            let act_two = self.brontide.gen_act_two()?;
            self.stream
                .write_all(&act_two)
                .timeout(Duration::from_secs(1))
                .await?;

            let mut act_three = [0_u8; 66];
            self.stream
                .read_exact(&mut act_three)
                .timeout(Duration::from_secs(1))
                .await?;
            self.brontide.recv_act_three(act_three)?;
        }

        //If any streams have been started, and are waiting for this to complete - then we wake
        //them.
        self.inner.waker.wake();

        Ok(())
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
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

        let encrypted_packet = self.brontide.encode(data)?;

        self.stream.write_all(&encrypted_packet).await?;

        Ok(())
    }

    //TODO be able to include a timeout here -> If we do that, I think we then need to be able to
    //flush the connection.
    //TODO should handle EOF, and just continue to loop.
    //pub async fn next_message(&mut self) -> Result<Vec<u8>> {
    //    //This has to be dynamic based on packet size.
    //    let mut header = [0; HEADER_SIZE];

    //    self.socket.read_exact(&mut header).await?;

    //    let size = self.brontide.packet_size().size();
    //    let len = &header[..size];

    //    //This should probably be a tryfrom, so that it throws an error if possible. TODO
    //    let tag1 = Tag::from(&header[size..]);

    //    let mut plain_text = Vec::with_capacity(size);
    //    let result = self
    //        .brontide
    //        .receive_cipher
    //        .as_mut()
    //        .ok_or_else(|| Error::NoCipher("receive cipher not initalized".to_owned()))?
    //        .decrypt(&len, tag1, &[], &mut plain_text);

    //    let length: usize;

    //    if result {
    //        length = self.brontide.packet_size().length(&plain_text);
    //    } else {
    //        return Err(Error::BadTag("packet header: bad tag".to_owned()));
    //    };

    //    if length > self.brontide.packet_size().max() {
    //        return Err(Error::DataTooLarge(format!(
    //            "Tried to write: {}, Max: {}",
    //            length,
    //            self.brontide.packet_size().max()
    //        )));
    //    }

    //    // let mut body = [0; length + 16];
    //    let mut body = vec![0; length + 16];

    //    //TODO explore using read_to_end here, then our vector will grow for us.
    //    self.socket.read_exact(&mut body).await?;

    //    let encrypted_message = &body[..length];
    //    //TODO make this a tryfrom, so it throw an error
    //    let tag2 = Tag::from(&body[length..]);

    //    let mut message = Vec::with_capacity(length);

    //    if !self
    //        .brontide
    //        .receive_cipher
    //        .as_mut()
    //        .ok_or_else(|| Error::NoCipher("receive cipher not initalized".to_owned()))?
    //        .decrypt(encrypted_message, tag2, &[], &mut message)
    //    {
    //        return Err(Error::BadTag("packet message: bad tag".to_owned()));
    //    };

    //    Ok(message)
    //}

    pub fn next_message(&mut self, cx: &mut Context<'_>) -> Poll<Result<Vec<u8>>> {
        dbg!("Are we getting here?");
        //TODO this probably should be actState != Done
        if self.brontide.act_state() == ActState::None {
            return Poll::Pending;

            //I think we need to save the cx here, and schedule to be rewoken when we have actstate
            //== Done
        }

        dbg!("Are we getting here?");

        loop {
            let mut buffer = vec![0; self.inner.waiting];
            match Pin::new(&mut self.stream).poll_read(cx, &mut buffer) {
                Poll::Ready(read) => {
                    let bytes_read = read?;

                    //Reading 0 bytes means the stream is shutdown.
                    if bytes_read == 0 {
                        //TODO implement something like Error stream shutdown.
                        // return Poll: Ready(Error::StreamClosed);
                    }

                    self.inner.total += bytes_read;
                    self.inner.pending.append(&mut buffer.to_vec());

                    if self.inner.total != self.inner.waiting {
                        return Poll::Pending;
                    }

                    //Iterate until entire header has been found.
                    if !self.inner.has_size {
                        //Break this into a different function. TODO
                        let size = self.brontide.packet_size().size();
                        let len = &self.inner.pending[..size];

                        //This should probably be a tryfrom, so that it throws an error if possible. TODO
                        let tag1 = Tag::from(&self.inner.pending[size..]);

                        let mut plain_text = Vec::with_capacity(size);
                        let result = self
                            .brontide
                            .receive_cipher
                            .as_mut()
                            .ok_or_else(|| {
                                Error::NoCipher("receive cipher not initalized".to_owned())
                            })?
                            .decrypt(&len, tag1, &[], &mut plain_text);

                        let length: usize;

                        if result {
                            length = self.brontide.packet_size().length(&plain_text);
                        } else {
                            return Poll::Ready(Err(Error::BadTag(
                                "packet header: bad tag".to_owned(),
                            )));
                        };

                        if length > self.brontide.packet_size().max() {
                            // return Err(Error::DataTooLarge(format!(
                            //     "Tried to write: {}, Max: {}",
                            //     length,
                            //     self.brontide.packet_size().max()
                            // )));
                        }

                        self.inner.total = 0;
                        self.inner.has_size = false;
                        self.inner.waiting = length;

                        //Try again if all data is queued up.
                    }
                }
                Poll::Pending => return Poll::Pending,
            };
        }

        // if !self.inner.has_size {
        //     assert_eq!(self.inner.waiting, HEADER_SIZE);
        //     assert_eq!(self.

        // }
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

impl Stream for BrontideStream {
    // type Item = io::Result<TcpStream>;
    type Item = Result<Vec<u8>>;
    // type Item = Result<UnencryptedPacket>

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.waker.register(cx.waker());
        match self.next_message(cx) {
            Poll::Pending => Poll::Pending,
            //TODO do we do something w/ the error here?
            //maybe log.
            // Poll::Ready(Err(e)) => Poll::Ready(None),
            Poll::Ready(value) => Poll::Ready(Some(value)),
        }

        // let (socket, _) = ready!(Pin::new(&mut *self.inner).poll_ready(cx)?);
        // Poll::Ready(Some(Ok(Vec::new())))
    }
}

//TODO do we need a timeout here? And if so, how long is our timeout between reads.
//Should it be configurable?
// impl Stream for BrontideStream {
//     type Item = Vec<u8>;
//     type Error = io::Error;

//     fn poll(&mut self) -> Result<Poll<Option<u8>>, io::Error> {
//         let mut buf = [0;1];
//         match self.0.poll_read(&mut buf) {
//             Ok(Async::Ready(n)) => {
//                 // By convention, if an AsyncRead says that it read 0 bytes,
//                 // we should assume that it has got to the end, so we signal that
//                 // the Stream is done in this case by returning None:
//                 if n == 0 {
//                     Ok(Async::Ready(None))
//                 } else {
//                     Ok(Async::Ready(Some(buf[0])))
//                 }
//             },
//             Ok(Async::NotReady) => Ok(Async::NotReady),
//             Err(e) => Err(e)
//         }
//     }
// }

// impl<T> AsRef<T> for BrontideStream<T>
// where
//     T: AsyncReadExt + AsyncWriteExt + Unpin,
// {
//     fn as_ref(&self) -> &T {
//         &self.socket
//     }
// }

// impl<T> AsMut<T> for BrontideStream<T>
// where
//     T: AsyncReadExt + AsyncWriteExt + Unpin,
// {
//     fn as_mut(&mut self) -> &mut T {
//         &mut self.socket
//     }
// }
//
// TODO BRONTIDEFUTURE
