#![no_main]

use crypto_core_rs::parse_header_blob_rs;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_header_blob_rs(data);
});
