//! End-to-end tests driving the real binary, i.e. the contract scripts depend
//! on: stdout, exit codes and the files left on disk.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_cryptera");
const PW: &str = "correct horse battery staple";

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .current_dir(dir)
        .env("CRYPTERA_PASSWORD", PW)
        .output()
        .expect("run cryptera")
}

fn run_ok(dir: &Path, args: &[&str]) -> String {
    let out = run(dir, args);
    assert!(
        out.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn code(out: &Output) -> i32 {
    out.status.code().expect("process exited with a code")
}

fn json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).expect("stdout is one JSON object")
}

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

#[test]
fn file_roundtrip_restores_content_and_original_name() {
    let dir = tmp();
    let src = dir.path().join("report.txt");
    std::fs::write(&src, b"hello cryptera").unwrap();

    let printed = run_ok(dir.path(), &["encrypt", "report.txt", "--quiet"]);
    assert_eq!(PathBuf::from(&printed).file_name().unwrap(), "report.ecf");
    assert!(dir.path().join("report.ecf").exists());

    std::fs::remove_file(&src).unwrap();
    let printed = run_ok(dir.path(), &["decrypt", "report.ecf", "--quiet"]);
    assert!(printed.ends_with("report.txt"), "got {printed}");
    assert_eq!(std::fs::read(&src).unwrap(), b"hello cryptera");
}

#[test]
fn folder_roundtrip_extracts_and_skips_symlinks() {
    let dir = tmp();
    let src = dir.path().join("photos");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("a.txt"), b"one").unwrap();
    std::fs::write(src.join("sub/b.txt"), b"two").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("a.txt", src.join("link")).unwrap();

    let out = run(
        dir.path(),
        &[
            "encrypt",
            "photos",
            "--folder-comp",
            "gz",
            "--json",
            "--quiet",
        ],
    );
    assert_eq!(code(&out), 0);
    let v = json(&out);
    assert_eq!(v["ok"], true);
    assert_eq!(v["container"], true);
    assert_eq!(v["archive_name"], ".tar.gz");

    let out = run(
        dir.path(),
        &[
            "decrypt",
            "photos.ecf",
            "-o",
            "restored",
            "--json",
            "--quiet",
        ],
    );
    assert_eq!(code(&out), 0);
    let v = json(&out);
    assert_eq!(v["extracted"], true);
    assert_eq!(v["meta"]["container"], true);

    let restored = dir.path().join("restored/photos");
    assert_eq!(std::fs::read(restored.join("a.txt")).unwrap(), b"one");
    assert_eq!(std::fs::read(restored.join("sub/b.txt")).unwrap(), b"two");
    assert!(!restored.join("link").exists(), "symlinks must be skipped");
}

// Regression: a compressed folder container with a hidden filename has no
// suffix to sniff, so extraction must recover the codec from the archive bytes.
// Every codec, with --keep-tar to check the kept archive is named for its
// actual compression.
#[test]
fn compressed_hidden_filename_folder_still_extracts() {
    for comp in ["gz", "bz2", "xz"] {
        let dir = tmp();
        let src = dir.path().join("data");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("a.txt"), b"one").unwrap();
        std::fs::write(src.join("sub/b.txt"), b"two").unwrap();

        run_ok(
            dir.path(),
            &[
                "encrypt",
                "data",
                "--folder-comp",
                comp,
                "--hide-filename",
                "-o",
                "c.ecf",
                "--quiet",
            ],
        );
        // Name is hidden: meta (no password) shows nothing to sniff from.
        let out = run(dir.path(), &["meta", "c.ecf", "--json", "--quiet"]);
        assert_eq!(json(&out)["meta"]["filename"], "", "comp={comp}");

        let out = run(
            dir.path(),
            &[
                "decrypt",
                "c.ecf",
                "-o",
                "r",
                "--keep-tar",
                "--json",
                "--quiet",
            ],
        );
        assert_eq!(
            code(&out),
            0,
            "comp={comp}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(json(&out)["extracted"], true, "comp={comp}");

        let r = dir.path().join("r/data");
        assert_eq!(
            std::fs::read(r.join("a.txt")).unwrap(),
            b"one",
            "comp={comp}"
        );
        assert_eq!(
            std::fs::read(r.join("sub/b.txt")).unwrap(),
            b"two",
            "comp={comp}"
        );
        // The kept tar is named for its real compression, not always ".tar".
        let kept = dir.path().join(format!(
            "r/decrypted.tar.{}",
            if comp == "gz" { "gz" } else { comp }
        ));
        assert!(kept.exists(), "comp={comp}: expected {}", kept.display());
    }
}

#[test]
fn wrong_password_exits_3_with_a_machine_readable_code() {
    let dir = tmp();
    std::fs::write(dir.path().join("a.txt"), b"secret").unwrap();
    run_ok(dir.path(), &["encrypt", "a.txt", "--quiet"]);

    let out = Command::new(BIN)
        .args(["verify", "a.ecf", "--json", "--quiet"])
        .current_dir(dir.path())
        .env("CRYPTERA_PASSWORD", "not the password")
        .output()
        .unwrap();

    assert_eq!(code(&out), 3);
    let v = json(&out);
    assert_eq!(v["ok"], false);
    assert_eq!(v["code"], "HEADER_AUTH_FAILED");
}

#[test]
fn existing_output_is_refused_until_forced() {
    let dir = tmp();
    std::fs::write(dir.path().join("a.txt"), b"secret").unwrap();
    run_ok(dir.path(), &["encrypt", "a.txt", "--quiet"]);

    let out = run(dir.path(), &["encrypt", "a.txt", "--json", "--quiet"]);
    assert_eq!(code(&out), 5);
    assert_eq!(json(&out)["code"], "OUTPUT_EXISTS");

    let out = run(dir.path(), &["encrypt", "a.txt", "--force", "--quiet"]);
    assert_eq!(code(&out), 0);
}

#[test]
fn password_can_come_from_stdin() {
    let dir = tmp();
    std::fs::write(dir.path().join("a.txt"), b"secret").unwrap();

    let mut child = Command::new(BIN)
        .args(["encrypt", "a.txt", "--password-stdin", "--quiet"])
        .current_dir(dir.path())
        .env_remove("CRYPTERA_PASSWORD")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(format!("{PW}\n").as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stderr));

    // The same password read from a file must open it.
    let pw_file = dir.path().join("pw.txt");
    std::fs::write(&pw_file, format!("{PW}\n")).unwrap();
    let out = Command::new(BIN)
        .args([
            "verify",
            "a.ecf",
            "--password-file",
            pw_file.to_str().unwrap(),
            "--json",
            "--quiet",
        ])
        .current_dir(dir.path())
        .env_remove("CRYPTERA_PASSWORD")
        .output()
        .unwrap();
    assert_eq!(code(&out), 0);
    assert_eq!(json(&out)["ok"], true);
}

#[test]
fn missing_password_source_is_reported_not_prompted() {
    let dir = tmp();
    std::fs::write(dir.path().join("a.txt"), b"secret").unwrap();

    // No TTY in tests, so the prompt must not be attempted.
    let out = Command::new(BIN)
        .args(["encrypt", "a.txt", "--json", "--quiet"])
        .current_dir(dir.path())
        .env_remove("CRYPTERA_PASSWORD")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(code(&out), 1);
    assert_eq!(json(&out)["code"], "PASSWORD_REQUIRED");
}

#[test]
fn meta_needs_no_password_and_flags_a_container() {
    let dir = tmp();
    std::fs::create_dir(dir.path().join("stuff")).unwrap();
    std::fs::write(dir.path().join("stuff/x.txt"), b"x").unwrap();
    run_ok(dir.path(), &["encrypt", "stuff", "--quiet"]);

    let out = Command::new(BIN)
        .args(["meta", "stuff.ecf", "--json"])
        .current_dir(dir.path())
        .env_remove("CRYPTERA_PASSWORD")
        .output()
        .unwrap();
    assert_eq!(code(&out), 0);
    let v = json(&out);
    assert_eq!(v["ok"], true);
    assert_eq!(v["meta"]["container"], true);
    assert_eq!(v["meta"]["version"], 5);
}

#[test]
fn garbage_input_is_reported_as_corrupt() {
    let dir = tmp();
    std::fs::write(dir.path().join("junk.ecf"), b"not a container").unwrap();
    let out = run(dir.path(), &["meta", "junk.ecf", "--json"]);
    assert_eq!(code(&out), 4);
    assert_eq!(json(&out)["code"], "HEADER_INVALID");
}
