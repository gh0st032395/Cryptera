use std::fs;

use crypto_core_rs::{
    decrypt_file_ex_rs, encrypt_file_rs, read_metadata_rs, verify_file_integrity_rs,
};
use tempfile::tempdir;

fn encrypt_fast(input_file: &str, output_file: &str, password: &str) {
    encrypt_file_rs(
        input_file,
        output_file,
        password,
        None,
        None,
        true,
        Some(4),
        Some(2),
        Some(1024),
        Some(1),
        Some(8 * 1024),
        Some(1),
        None,
        false,
    )
    .expect("encryption should succeed");
}

#[test]
fn roundtrip_encrypt_decrypt_verify_metadata() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("input.txt");
    let enc = dir.path().join("input.ecf");
    let output = dir.path().join("output.txt");
    let password = "test-password";
    let content = b"crypto-v2 regression test payload";

    fs::write(&input, content).expect("write input");
    encrypt_fast(
        input.to_str().expect("utf8 path"),
        enc.to_str().expect("utf8 path"),
        password,
    );

    let meta = read_metadata_rs(enc.to_str().expect("utf8 path")).expect("metadata");
    assert_eq!(meta.version, 5);
    assert_eq!(meta.k, 4);
    assert_eq!(meta.r, 2);

    verify_file_integrity_rs(enc.to_str().expect("utf8 path"), password, None).expect("verify");
    decrypt_file_ex_rs(
        enc.to_str().expect("utf8 path"),
        output.to_str().expect("utf8 path"),
        password,
        None,
    )
    .expect("decrypt");

    let restored = fs::read(&output).expect("read output");
    assert_eq!(restored, content);
}

#[test]
fn verify_fails_when_header_auth_tag_is_tampered() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("input.bin");
    let enc = dir.path().join("input.ecf");
    let tampered = dir.path().join("input-tampered.ecf");
    let password = "header-auth-password";

    fs::write(&input, b"header auth tamper test").expect("write input");
    encrypt_fast(
        input.to_str().expect("utf8 path"),
        enc.to_str().expect("utf8 path"),
        password,
    );

    let mut blob = fs::read(&enc).expect("read encrypted");
    let hdr_len = u16::from_be_bytes([blob[4], blob[5]]) as usize;
    let auth_start = 4 + 2 + hdr_len + 4;
    blob[auth_start] ^= 0xAA;
    fs::write(&tampered, blob).expect("write tampered");

    let err = verify_file_integrity_rs(tampered.to_str().expect("utf8 path"), password, None)
        .expect_err("verify should fail");
    assert_eq!(err.code, "HEADER_AUTH_FAILED");
}

#[test]
fn decrypt_with_wrong_password_fails_cleanly() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("input.bin");
    let enc = dir.path().join("input.ecf");
    let output = dir.path().join("output.bin");

    fs::write(&input, b"wrong password test").expect("write input");
    encrypt_fast(
        input.to_str().expect("utf8 path"),
        enc.to_str().expect("utf8 path"),
        "correct-password",
    );

    let err = decrypt_file_ex_rs(
        enc.to_str().expect("utf8 path"),
        output.to_str().expect("utf8 path"),
        "wrong-password",
        None,
    )
    .expect_err("decrypt should fail");
    assert!(
        ["PASSWORD_INVALID", "HEADER_AUTH_FAILED"].contains(&err.code),
        "unexpected error code: {}",
        err.code
    );
}

#[test]
fn verify_truncated_file_fails() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("input.dat");
    let enc = dir.path().join("input.ecf");
    let truncated = dir.path().join("input-truncated.ecf");

    fs::write(&input, vec![0xAB; 8192]).expect("write input");
    encrypt_fast(
        input.to_str().expect("utf8 path"),
        enc.to_str().expect("utf8 path"),
        "truncate-password",
    );

    let original = fs::read(&enc).expect("read encrypted");
    let shortened_len = (original.len() / 2).max(1);
    fs::write(&truncated, &original[..shortened_len]).expect("write truncated");

    let err = verify_file_integrity_rs(
        truncated.to_str().expect("utf8 path"),
        "truncate-password",
        None,
    )
    .expect_err("verify should fail");
    assert!(
        ["TRUNCATED", "HEADER_INVALID", "CORRUPT_BEYOND_FEC"].contains(&err.code),
        "unexpected error code: {}",
        err.code
    );
}
