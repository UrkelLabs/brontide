# Rust-Brontide
[![Build Status](https://travis-ci.org/HandshakeAlliance/rust-brontide.svg?branch=master)](https://travis-ci.org/HandshakeAlliance/rust-brontide)
[![codecov](https://codecov.io/gh/HandshakeAlliance/rust-brontide/branch/master/graph/badge.svg)](https://codecov.io/gh/HandshakeAlliance/rust-brontide)
[![Documentation][docs-badge]][docs-url]

[docs-badge]: https://docs.rs/brontide/badge.svg?version=0.0.0
[docs-url]: https://docs.rs/brontide

A rust implementation of the Handshake and Lightning Network secure messaging protocol.
This implementation is based on Brontide from HSD as well as Noise from LND.

# Usage

Currently Rust-Brontide requires the nightly version of rust to compile. This crate makes heavy usage
of futures 0.3 as well as the new async/await syntax. These will be stable in 1.37 which should be released early August,
at which point we will remove the nightly requirement.
