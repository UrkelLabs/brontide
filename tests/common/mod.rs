#[cfg(feature = "stream")]
use async_std;
#[cfg(feature = "stream")]
use brontide::BrontideBuilder;
#[cfg(feature = "stream")]
use brontide::Result;
#[cfg(feature = "stream")]
use futures::StreamExt;

#[cfg(feature = "stream")]
pub async fn stream_listener_oneshot_setup(address: &str) -> Result<()> {
    let listener = async_std::net::TcpListener::bind(address).await?;

    let mut incoming = listener.incoming();
    while let Some(stream) = incoming.next().await {
        let stream = stream?;

        let result = async_std::task::spawn(async move {
            let mut accepted_stream = BrontideBuilder::new([1; 32]).accept(stream).await?;

            accepted_stream.write(b"hello").await.unwrap();

            Ok(())
        });

        let result = result.await;

        if result.is_err() {
            return result;
        }
    }

    Ok(())
}

// #[cfg(feature = "stream")]
// fn stream_listener_continous_setup() {
//     let (tx, rx) = unbounded();

//     let listener = async_std::net::TcpListener::bind("0.0.0.0:13038")
//         .await
//         .unwrap();

//     let mut incoming = listener.incoming();
//     while let Some(stream) = incoming.next().await {
//         // let stream = stream?;
//         let stream = stream.unwrap();

//         async_std::task::spawn(async move {
//             let mut accepted_stream = BrontideBuilder::new([1; 32]).accept(stream).await.unwrap();
//             accepted_stream.write(b"hello").await.unwrap();
//             // accepted_stream.write(b"olleh").await;
//             // accepted_stream.write(b"hello").await;
//             // loop {}
//         });
//     }
// }
