use std::collections::BTreeMap;
use std::path::Path;

/// FNV-1a 64-bit — a tiny, dependency-free hash for build-time fingerprinting.
fn fnv1a(seed: u64, bytes: &[u8]) -> u64 {
    let mut hash = seed;
    for b in bytes {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Register every file under `dir` as a Cargo build input and record a hash of
/// its contents (keyed by path so the result is order-independent).
fn collect(dir: &Path, files: &mut BTreeMap<String, u64>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, files);
        } else {
            println!("cargo:rerun-if-changed={}", path.display());
            let content = std::fs::read(&path).unwrap_or_default();
            files.insert(
                path.to_string_lossy().into_owned(),
                fnv1a(0xcbf2_9ce4_8422_2325, &content),
            );
        }
    }
}

fn main() {
    // The frontend (../ui) is embedded into the binary at compile time by
    // `tauri::generate_context!`. Tauri does NOT register those files as build
    // inputs, so editing only frontend files would not force a rebuild — a
    // release bundle could then ship stale embedded HTML/JS. That is exactly
    // what caused an old "update available" dialog to reappear at launch only
    // in installed/bundled builds (debug `tauri dev` reads ../ui from disk and
    // was unaffected).
    //
    // We hash the whole frontend tree and expose the digest as a rustc env.
    // `main.rs` references it, so the crate — and therefore the asset-embedding
    // macro — is recompiled whenever any frontend file changes, guaranteeing
    // the bundle always embeds the current UI.
    println!("cargo:rerun-if-changed=../ui");
    let mut files = BTreeMap::new();
    collect(Path::new("../ui"), &mut files);

    let mut digest = 0xcbf2_9ce4_8422_2325u64;
    for (path, hash) in &files {
        digest = fnv1a(digest, path.as_bytes());
        digest = fnv1a(digest, &hash.to_le_bytes());
    }
    println!("cargo:rustc-env=CRYPTERA_FRONTEND_HASH={digest:016x}");

    tauri_build::build();
}
