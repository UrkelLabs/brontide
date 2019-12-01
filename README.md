# Brontide
[![Build Status](https://travis-ci.org/HandshakeAlliance/rust-brontide.svg?branch=master)](https://travis-ci.org/HandshakeAlliance/rust-brontide)
[![Documentation][docs-badge]][docs-url]

[docs-badge]: https://docs.rs/brontide/badge.svg?version=0.0.0
[docs-url]: https://docs.rs/brontide

A rust implementation of the Handshake and Lightning Network secure messaging protocol.
This implementation is based on Brontide from HSD as well as Noise from LND.

# Usage

A majority of Rust-Brontide is available on stable Rust. When compiling on stable, we export the main Brontide struct.
In order for ease of use, we have also included a Brontide Stream structure that handles incoming and outgoing sockets.

Brontide exposes two main structs to interact with the library. Brontide and BrontideStream. BrontideStream is only available if compiling with the stream feature.
Both of theses structs are built using the builder pattern. 

### Brontide 

```
    // Get the remove static public key.
    let mut rs_pub = PublicKey.from_str("028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7")?;

    // Build the local static private key.
    let ls_priv = PrivateKey.from_str("1111111111111111111111111111111111111111111111111111111111111111")?

    // Contruct an initiator from BrontideBuilder.
    let mut initiator = brontide::BrontideBuilder::new(ls_priv)
        .initiator(rs_pub)
        .build();

    let act_one = initiator.gen_act_one()?;

    initiator.recv_act_two(act_two)?;

    ...
```

### BrontideStream 

```
// Listener Setup
async_std::task::spawn(async move {
    let listener = async_std::net::TcpListener::bind("0.0.0.0:13038")
        .await
        .unwrap();

    let mut incoming = listener.incoming();
    while let Some(stream) = incoming.next().await {
        let stream = stream?;

        async_std::task::spawn(async move {
            let mut accepted_stream =
                BrontideBuilder::new(ls_priv).accept(stream).await?;
            accepted_stream.write(b"hello").await?;
        });
    }
});

// Connector Setup
let mut stream = BrontideBuilder::new(ls_priv)
    .connect("0.0.0.0:13038", pub_key)
    .await?;

while let Some(packet) = stream.next().await {
    assert_eq!(packet, b"hello");
}
```
