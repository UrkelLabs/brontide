# Rust-Brontide
[![Build Status](https://travis-ci.org/HandshakeAlliance/rust-brontide.svg?branch=master)](https://travis-ci.org/HandshakeAlliance/rust-brontide)
[![codecov](https://codecov.io/gh/HandshakeAlliance/rust-brontide/branch/master/graph/badge.svg)](https://codecov.io/gh/HandshakeAlliance/rust-brontide)
[![Documentation][docs-badge]][docs-url]

[docs-badge]: https://docs.rs/brontide/badge.svg?version=0.0.0
[docs-url]: https://docs.rs/brontide

A rust implementation of the Handshake and Lightning Network secure messaging protocol.
This implementation is based on Brontide from HSD as well as Noise from LND.

# Usage

A majority of Rust-Brontide is available on stable Rust. When compiling on stable, we export the main Brontide struct.
In order for ease of use, we have also included a Brontide Stream structure that handles incoming and outgoing sockets. This 
feature requires nightly as it makes heavy use of async/await and futures. These will be stable in 1.37 which should be released early August,
at which point we will remove the nightly requirement.
