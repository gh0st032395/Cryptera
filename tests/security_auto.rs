use byteorder::{BigEndian, ByteOrder};
use crc32fast::Hasher;
use crypto_core_rs::{decrypt_file_ex_rs, parse_header_blob_rs, verify_file_integrity_rs};
use std::fs;
use tempfile::tempdir;

fn crc32(data: &[u8]) -> u32 {
    let mut h = Hasher::new();
    h.update(data);
    h.finalize()
}

#[test]
fn tampered_header_with_recomputed_crc_fails_auth() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("input.bin");
    let enc = dir.path().join("input.ecf");
    let tampered = dir.path().join("tampered.ecf");
    let output = dir.path().join("out.bin");

    fs::write(&input, b"security-header-auth-test").expect("write input");

    crypto_core_rs::encrypt_file_rs(
        input.to_str().expect("utf8 path"),
        enc.to_str().expect("utf8 path"),
        "secure-password",
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
    .expect("encrypt");

    let mut blob = fs::read(&enc).expect("read encrypted");
    let hdr_len = u16::from_be_bytes([blob[4], blob[5]]) as usize;
    let hdr_start = 6usize;
    let hdr_end = hdr_start + hdr_len;

    // Mutate header content.
    blob[hdr_start + 1] ^= 0x11;

    // Recompute CRC so CRC checks pass; authentication tag must still fail.
    let mut prefix = Vec::with_capacity(6 + hdr_len);
    prefix.extend_from_slice(&blob[..6]);
    prefix.extend_from_slice(&blob[hdr_start..hdr_end]);
    let new_crc = crc32(&prefix);

    // Patch start CRC.
    let start_crc_off = hdr_end;
    BigEndian::write_u32(&mut blob[start_crc_off..start_crc_off + 4], new_crc);

    // Patch trailer CRC.
    let total_len = blob.len();
    let trailer_start = total_len - (hdr_len + 26);
    let trailer_crc_off = trailer_start + hdr_len;
    BigEndian::write_u32(&mut blob[trailer_crc_off..trailer_crc_off + 4], new_crc);

    fs::write(&tampered, &blob).expect("write tampered");

    let verify_err = verify_file_integrity_rs(
        tampered.to_str().expect("utf8 path"),
        "secure-password",
        None,
    )
    .expect_err("verify should fail");
    assert_eq!(verify_err.code, "HEADER_AUTH_FAILED");

    let dec_err = decrypt_file_ex_rs(
        tampered.to_str().expect("utf8 path"),
        output.to_str().expect("utf8 path"),
        "secure-password",
        None,
    )
    .expect_err("decrypt should fail");
    assert_eq!(dec_err.code, "HEADER_AUTH_FAILED");
}

#[test]
fn parse_header_blob_rejects_untrusted_random_input() {
    let bad = vec![0x41u8; 64];
    let err = parse_header_blob_rs(&bad).expect_err("random blob must be rejected");
    assert_eq!(err.code, "HEADER_INVALID");
}
