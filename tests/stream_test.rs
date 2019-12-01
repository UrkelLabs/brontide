#[cfg(feature = "stream")]
use async_std;
#[cfg(feature = "stream")]
use async_std::net::TcpStream;
#[cfg(feature = "stream")]
use async_std::prelude::FutureExt;
#[cfg(feature = "stream")]
use async_std::task;
#[cfg(feature = "stream")]
use brontide::{BrontideBuilder, BrontideStream};
#[cfg(feature = "stream")]
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};

use std::time::Duration;

//@todo clean up the above.

mod common;
use common::stream_listener_oneshot_setup;

//TODO biggest thing to test with this is that streams can work out of order.
// Stream A connects
// Stream B connects
// Stream A sends act_one
// We return act_two
// Stream B sends act_one
// We return act_two
// Stream B sends act_three
// Stream B should be the first ready in the above scenario.

////TODO Tests we need
////1. Test sending in a message without doing a handshake. Ensure we fail on the stream side.
////2. Test timeouts.
////3. Test stream returns
////4. Test invalid keys.
////5. Test opening up a stream, and then not having the handshake done.
////If Handshake is complete is some time period, the stream should auto-rewake and read messages.

#[cfg(feature = "stream")]
#[async_std::test]
async fn test_brontide_stream() {
    async_std::task::spawn(async move {
        stream_listener_oneshot_setup("0.0.0.0:13038").await;
    });
    let mut pub_key = [0_u8; 33];
    pub_key.copy_from_slice(
        &hex::decode("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f").unwrap(),
    );

    let mut stream = BrontideBuilder::new([1; 32])
        .connect("0.0.0.0:13038", pub_key)
        .await
        .unwrap();

    while let Some(packet) = stream.next().await {
        assert_eq!(packet, b"hello");
    }
}

#[cfg(feature = "stream")]
#[async_std::test]
async fn test_brontide_out_of_order_streams() {
    async_std::task::spawn(async move {
        stream_listener_oneshot_setup("0.0.0.0:13039").await;
    });

    let mut pub_key = [0_u8; 33];
    pub_key.copy_from_slice(
        &hex::decode("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f").unwrap(),
    );

    //Stream A.
    let stream_a: async_std::task::JoinHandle<u32> = async_std::task::spawn(async move {
        //@todo maybe clone these to reduce time before starting.
        let brontide = BrontideBuilder::new([2; 32]).initiator(pub_key).build();
        let stream = TcpStream::connect("0.0.0.0:13039").await.unwrap();

        //Stream A connects immediately.
        let mut a_stream = BrontideStream::new(stream, brontide);

        //Stream A sends act_one first.
        let act_one = a_stream.brontide.gen_act_one().unwrap();

        a_stream.stream.write_all(&act_one).await.unwrap();

        //Read act two
        let mut act_two = [0_u8; 50];
        a_stream.stream.read_exact(&mut act_two).await.unwrap();

        //Process act two
        a_stream.brontide.recv_act_two(act_two).unwrap();

        //Stream A now waits. (timeout will occur at 1 second, so we sleep for less than that).
        //@todo sleeping longer than a second does not break the stream... That's a problem.
        //@fixme @bug
        task::sleep(Duration::from_millis(900_u64)).await;
        // task::sleep(Duration::from_millis(2000_u64)).await;

        //After sleeping, Stream A now processes act_three (which should be after Stream B)
        let act_three = a_stream.brontide.gen_act_three().unwrap();
        a_stream.stream.write_all(&act_three).await.unwrap();

        0
    });

    //Stream B.
    let stream_b: async_std::task::JoinHandle<u32> = async_std::task::spawn(async move {
        //@todo maybe clone these to reduce time before starting.
        let brontide = BrontideBuilder::new([3; 32]).initiator(pub_key).build();
        let stream = TcpStream::connect("0.0.0.0:13039").await.unwrap();

        let mut b_stream = BrontideStream::new(stream, brontide);

        //Stream B sleeps before sending act one.
        task::sleep(Duration::from_millis(500_u64)).await;

        //Stream B now generates act one and sends.
        let act_one = b_stream.brontide.gen_act_one().unwrap();

        b_stream.stream.write_all(&act_one).await.unwrap();

        //Read act two
        let mut act_two = [0_u8; 50];
        b_stream.stream.read_exact(&mut act_two).await.unwrap();

        //Process act two
        b_stream.brontide.recv_act_two(act_two).unwrap();

        //Stream B immediately sends act three
        let act_three = b_stream.brontide.gen_act_three().unwrap();
        b_stream.stream.write_all(&act_three).await.unwrap();

        1
    });

    let result = stream_a.race(stream_b);

    assert_eq!(result.await, 1);
}

//For setups, rip out the listener function and return a channel to it. Then we can write to the
//channel and it will pop up in the stream. TODO
