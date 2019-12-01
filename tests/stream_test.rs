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

////3. Test stream returns
////4. Test invalid keys.

#[cfg(feature = "stream")]
#[async_std::test]
#[should_panic(expected = "Timeout")]
async fn test_stream_timeout() {
    let handler =
        async_std::task::spawn(async move { stream_listener_oneshot_setup("0.0.0.0:13036").await });

    let mut pub_key = [0_u8; 33];
    pub_key.copy_from_slice(
        &hex::decode("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f").unwrap(),
    );

    let _stream = TcpStream::connect("0.0.0.0:13036").await.unwrap();

    //The current default timeout is 1 second, this should cause a panic.
    task::sleep(Duration::from_secs(2_u64)).await;

    handler.await.unwrap();
}

// This test should test that a brontide listener will fail if no handshake occurs.
#[cfg(feature = "stream")]
#[async_std::test]
#[should_panic]
async fn test_no_handshake_message() {
    let handler =
        async_std::task::spawn(async move { stream_listener_oneshot_setup("0.0.0.0:13037").await });

    let mut stream = TcpStream::connect("0.0.0.0:13037").await.unwrap();

    //Write 100 bytes
    stream.write_all(&[1; 100]).await.unwrap();

    handler.await.unwrap();
}

#[cfg(feature = "stream")]
#[async_std::test]
async fn test_brontide_stream() {
    async_std::task::spawn(async move {
        stream_listener_oneshot_setup("0.0.0.0:13038")
            .await
            .unwrap();
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

//Out of Order Stream Test
// Stream A connects
// Stream B connects
// Stream A sends act_one
// Listener return act_two
// Stream B sends act_one
// Listener return act_two
// Stream B sends act_three
// Stream B should be the ready first.
// This test runs the above process up to 5 times. If it works correctly at least once, we pass the
// tests. The test executor is shared amongst all the test cases, so sometimes it occurs that the
// streams were not processed in order. If they are not processed in order 5 times, then we fail
// the test and know that there are real errors occuring.
#[cfg(feature = "stream")]
#[async_std::test]
async fn test_brontide_out_of_order_streams() {
    async_std::task::spawn(async move {
        stream_listener_oneshot_setup("0.0.0.0:13039")
            .await
            .unwrap();
    });

    let mut correct_order_once = false;

    for _i in 0u32..4u32 {
        let mut pub_key = [0_u8; 33];
        pub_key.copy_from_slice(
            &hex::decode("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f")
                .unwrap(),
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

            task::sleep(Duration::from_millis(900_u64)).await;
            // task::sleep(Duration::from_millis(2000_u64)).await;

            //After sleeping, Stream A now processes act_three (which should be after Stream B)
            let act_three = a_stream.brontide.gen_act_three().unwrap();
            a_stream.stream.write_all(&act_three).await.unwrap();

            //Return 0 to distinguish from below.
            0
        });

        //Stream B.
        let stream_b: async_std::task::JoinHandle<u32> = async_std::task::spawn(async move {
            //@todo maybe clone these to reduce time before starting.
            let brontide = BrontideBuilder::new([3; 32]).initiator(pub_key).build();
            let stream = TcpStream::connect("0.0.0.0:13039").await.unwrap();

            let mut b_stream = BrontideStream::new(stream, brontide);

            //Stream B sleeps before sending act one.
            task::sleep(Duration::from_millis(100_u64)).await;

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

            //Return 1 to distinguish from above.
            1
        });

        let result = stream_a.race(stream_b);
        if result.await == 1 {
            correct_order_once = true;
            break;
        }
    }

    assert!(correct_order_once);
}
