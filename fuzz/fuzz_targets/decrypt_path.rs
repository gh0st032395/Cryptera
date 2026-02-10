#![no_main]

use crypto_core_rs::{decrypt_file_ex_rs, verify_file_integrity_rs};
use libfuzzer_sys::fuzz_target;
use std::fs;
use tempfile::tempdir;

fuzz_target!(|data: &[u8]| {
    let Ok(dir) = tempdir() else { return };
    let input = dir.path().join("sample.ecf");
    let output = dir.path().join("sample.out");
    if fs::write(&input, data).is_err() {
        return;
    }
    let in_path = input.to_string_lossy();
    let out_path = output.to_string_lossy();
    let _ = verify_file_integrity_rs(&in_path, "fuzz-pass", None);
    let _ = decrypt_file_ex_rs(&in_path, &out_path, "fuzz-pass", None);
});
