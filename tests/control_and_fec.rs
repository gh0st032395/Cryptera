// Regression tests for cooperative pause/cancel and FEC recovery limits.

use crypto_core_rs::{
    decrypt_file_ex_rs, encrypt_file_rs, encrypt_file_rs_controlled, ControlFlags,
};
use std::io::Read;
use std::time::Duration;

const PASSWORD: &str = "CorrectHorse9!Battery";

fn write_input(dir: &std::path::Path, size: usize) -> std::path::PathBuf {
    let path = dir.join("input.bin");
    let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    std::fs::write(&path, data).expect("write input");
    path
}

fn fast_encrypt_args() -> (Option<u32>, Option<u32>, Option<u16>) {
    // Minimal Argon2 cost: tests exercise control flow, not KDF strength.
    (Some(1), Some(8 * 1024), Some(1))
}

#[test]
fn cancel_aborts_encryption_without_creating_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let input = write_input(dir.path(), 256 * 1024);
    let output = dir.path().join("out.ecf");

    let ctrl = ControlFlags::new();
    ctrl.request_cancel();

    let (t, m, p) = fast_encrypt_args();
    let err = encrypt_file_rs_controlled(
        input.to_str().unwrap(),
        output.to_str().unwrap(),
        PASSWORD,
        None,
        None,
        false,
        Some(4),
        Some(2),
        Some(1024),
        t,
        m,
        p,
        None,
        false,
        Some(&ctrl),
        None,
    )
    .expect_err("pre-cancelled operation must fail");
    assert_eq!(err.code, "CANCELLED");
    assert!(!output.exists(), "no output may be left behind on cancel");
}

#[test]
fn paused_encryption_blocks_until_cancelled() {
    let dir = tempfile::tempdir().expect("tempdir");
    let input = write_input(dir.path(), 256 * 1024);
    let output = dir.path().join("out.ecf");

    let ctrl = ControlFlags::new();
    ctrl.set_pause(true);

    let ctrl_worker = ctrl.clone();
    let input_s = input.to_str().unwrap().to_string();
    let output_s = output.to_str().unwrap().to_string();
    let handle = std::thread::spawn(move || {
        let (t, m, p) = fast_encrypt_args();
        encrypt_file_rs_controlled(
            &input_s,
            &output_s,
            PASSWORD,
            None,
            None,
            false,
            Some(4),
            Some(2),
            Some(1024),
            t,
            m,
            p,
            None,
            false,
            Some(&ctrl_worker),
            None,
        )
    });

    // While paused the worker must not complete.
    std::thread::sleep(Duration::from_millis(400));
    assert!(
        !handle.is_finished(),
        "encryption must stay blocked while paused"
    );

    // Cancelling during the pause must wake and abort the worker.
    ctrl.request_cancel();
    let res = handle.join().expect("worker thread join");
    let err = res.expect_err("cancelled operation must fail");
    assert_eq!(err.code, "CANCELLED");
    assert!(!output.exists());
}

/// Locate the start of the shard data in a v4 .ecf file without a
/// password-check record: magic(4) + len(2) + header + crc(4) + auth(16).
fn data_offset_v4(path: &std::path::Path) -> u64 {
    let mut f = std::fs::File::open(path).expect("open ecf");
    let mut head = [0u8; 6];
    f.read_exact(&mut head).expect("read magic+len");
    assert_eq!(&head[..4], b"ECF1");
    let hdr_len = u16::from_be_bytes([head[4], head[5]]) as u64;
    4 + 2 + hdr_len + 4 + 16
}

#[test]
fn fec_recovers_up_to_r_corrupted_shards_and_fails_beyond() {
    const K: u16 = 4;
    const R: u16 = 2;
    const SHARD_SIZE: u64 = 1024;
    const SHARD_STRIDE: u64 = 8 + SHARD_SIZE + 16; // CRC copies + ct + tag

    let dir = tempfile::tempdir().expect("tempdir");
    let input = write_input(dir.path(), 3 * 1024); // single block
    let encrypted = dir.path().join("out.ecf");

    let (t, m, p) = fast_encrypt_args();
    encrypt_file_rs(
        input.to_str().unwrap(),
        encrypted.to_str().unwrap(),
        PASSWORD,
        None,
        None,
        false, // no pwchk record: shard data starts right after the header
        Some(K),
        Some(R),
        Some(SHARD_SIZE as u32),
        t,
        m,
        p,
        None,
        false,
    )
    .expect("encrypt");

    let pristine = std::fs::read(&encrypted).expect("read encrypted");
    let offset = data_offset_v4(&encrypted);

    let corrupt_shards = |count: u64| -> Vec<u8> {
        let mut bytes = pristine.clone();
        for shard in 0..count {
            let pos = (offset + shard * SHARD_STRIDE + 8 + 100) as usize;
            for b in &mut bytes[pos..pos + 32] {
                *b ^= 0xFF;
            }
        }
        bytes
    };

    // R corrupted shards: still recoverable.
    let recoverable = dir.path().join("recoverable.ecf");
    std::fs::write(&recoverable, corrupt_shards(R as u64)).unwrap();
    let restored = dir.path().join("restored.bin");
    decrypt_file_ex_rs(
        recoverable.to_str().unwrap(),
        restored.to_str().unwrap(),
        PASSWORD,
        None,
    )
    .expect("decrypt must recover from R corrupted shards");
    assert_eq!(
        std::fs::read(&restored).unwrap(),
        std::fs::read(&input).unwrap()
    );

    // R+1 corrupted shards: beyond the FEC budget.
    let beyond = dir.path().join("beyond.ecf");
    std::fs::write(&beyond, corrupt_shards(R as u64 + 1)).unwrap();
    let failed_out = dir.path().join("failed.bin");
    let err = decrypt_file_ex_rs(
        beyond.to_str().unwrap(),
        failed_out.to_str().unwrap(),
        PASSWORD,
        None,
    )
    .expect_err("R+1 corrupted shards must not be recoverable");
    assert_eq!(err.code, "CORRUPT_BEYOND_FEC");
    assert!(!failed_out.exists());
}
