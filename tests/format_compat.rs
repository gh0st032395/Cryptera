// Backward-compatibility tests against committed v4 fixtures.
// The fixtures in tests/fixtures/ were generated with the v4 writer and
// must remain decryptable by every future format version.

use crypto_core_rs::{decrypt_file_ex_rs, read_metadata_rs, verify_file_integrity_rs};

const PASSWORD: &str = "FixtureP@ssw0rd42";

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
    assert_eq!(meta.filename, "secret-note.txt", "v4 stores the filename in plaintext");
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
