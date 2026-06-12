// Backward-compatibility tests against committed v4 fixtures.
// The fixtures in tests/fixtures/ were generated with the v4 writer and
// must remain decryptable by every future format version.

use crypto_core_rs::{
    decrypt_file_ex_rs, encrypt_file_rs, read_metadata_rs, verify_file_integrity_rs,
};

const PASSWORD: &str = "FixtureP@ssw0rd42";
const HDR_FLAG_ENC_FILENAME: u8 = 0x40;

fn expected_plaintext() -> Vec<u8> {
    (0..3000usize).map(|i| ((i * 7 + 13) % 251) as u8).collect()
}

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn v4_basic_fixture_still_decrypts_and_verifies() {
    let path = fixture("v4-basic.ecf");

    let meta = read_metadata_rs(&path).expect("metadata");
    assert_eq!(meta.version, 4);
    assert_eq!(
        meta.filename, "secret-note.txt",
        "v4 stores the filename in plaintext"
    );
    assert_eq!((meta.k, meta.r), (4, 2));

    verify_file_integrity_rs(&path, PASSWORD, None).expect("verify");

    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("restored.bin");
    let meta = decrypt_file_ex_rs(&path, out.to_str().unwrap(), PASSWORD, None).expect("decrypt");
    assert_eq!(meta.filename, "secret-note.txt");
    assert_eq!(std::fs::read(&out).unwrap(), expected_plaintext());
}

#[test]
fn v4_zlib_hidden_fixture_still_decrypts_and_verifies() {
    let path = fixture("v4-zlib-hidden.ecf");

    let meta = read_metadata_rs(&path).expect("metadata");
    assert_eq!(meta.version, 4);
    assert_eq!(meta.filename, "", "hidden filename stays empty");

    verify_file_integrity_rs(&path, PASSWORD, None).expect("verify");

    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("restored.bin");
    decrypt_file_ex_rs(&path, out.to_str().unwrap(), PASSWORD, None).expect("decrypt");
    assert_eq!(std::fs::read(&out).unwrap(), expected_plaintext());
}

#[test]
fn v5_filename_is_encrypted_in_header_and_recovered_with_password() {
    let dir = tempfile::tempdir().expect("tempdir");
    let input = dir.path().join("very-secret-name.txt");
    std::fs::write(&input, expected_plaintext()).unwrap();
    let encrypted = dir.path().join("out.ecf");

    encrypt_file_rs(
        input.to_str().unwrap(),
        encrypted.to_str().unwrap(),
        PASSWORD,
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

    // The plaintext filename must not appear anywhere in the file bytes.
    let raw = std::fs::read(&encrypted).unwrap();
    let needle = b"very-secret-name";
    assert!(
        !raw.windows(needle.len()).any(|w| w == needle),
        "plaintext filename leaked into the .ecf file"
    );

    // Without the password the metadata exposes the flag but not the name.
    let meta = read_metadata_rs(encrypted.to_str().unwrap()).expect("metadata");
    assert_eq!(meta.version, 5);
    assert_ne!(meta.flags & HDR_FLAG_ENC_FILENAME, 0);
    assert_eq!(meta.filename, "", "filename must be opaque without the key");

    // With the password verify and decrypt recover the original name.
    let meta =
        verify_file_integrity_rs(encrypted.to_str().unwrap(), PASSWORD, None).expect("verify");
    assert_eq!(meta.filename, "very-secret-name.txt");

    let out = dir.path().join("restored.bin");
    let meta = decrypt_file_ex_rs(
        encrypted.to_str().unwrap(),
        out.to_str().unwrap(),
        PASSWORD,
        None,
    )
    .expect("decrypt");
    assert_eq!(meta.filename, "very-secret-name.txt");
    assert_eq!(std::fs::read(&out).unwrap(), expected_plaintext());
}

#[test]
fn v5_hidden_filename_stores_no_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let input = dir.path().join("input.bin");
    std::fs::write(&input, expected_plaintext()).unwrap();
    let encrypted = dir.path().join("out.ecf");

    encrypt_file_rs(
        input.to_str().unwrap(),
        encrypted.to_str().unwrap(),
        PASSWORD,
        None,
        None,
        false,
        Some(4),
        Some(2),
        Some(1024),
        Some(1),
        Some(8 * 1024),
        Some(1),
        Some(""), // hide filename
        false,
    )
    .expect("encrypt");

    let meta = read_metadata_rs(encrypted.to_str().unwrap()).expect("metadata");
    assert_eq!(meta.version, 5);
    assert_eq!(meta.flags & HDR_FLAG_ENC_FILENAME, 0);

    let meta =
        verify_file_integrity_rs(encrypted.to_str().unwrap(), PASSWORD, None).expect("verify");
    assert_eq!(
        meta.filename, "",
        "hidden filename stays empty even with the key"
    );
}

#[test]
fn v4_fixture_rejects_wrong_password() {
    let path = fixture("v4-basic.ecf");
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("restored.bin");
    let err = decrypt_file_ex_rs(&path, out.to_str().unwrap(), "WrongPassword1!", None)
        .expect_err("wrong password must fail");
    // v4 header auth is checked before the pwchk record.
    assert!(
        err.code == "PASSWORD_INVALID" || err.code == "HEADER_AUTH_FAILED",
        "unexpected code {}",
        err.code
    );
    assert!(!out.exists());
}
