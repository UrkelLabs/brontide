#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate brontide;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
});
