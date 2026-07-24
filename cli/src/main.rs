//! `cryptera` — scriptable front-end over the same core the GUI uses.
//!
//! Design rules, because this binary exists to be driven by scripts:
//!   * one JSON object on stdout with `--json`, human text otherwise;
//!   * progress and diagnostics only ever on stderr;
//!   * stable exit codes (see `error.rs`) so callers can branch without
//!     parsing messages;
//!   * passwords never come from argv.

mod error;
mod password;
mod paths;
mod report;

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};
use cryptera_ops::{create_tar, is_tar_container, safe_extract_tar, tar_suffix};
use crypto_core_rs::{
    decrypt_file_ex_rs_controlled, encrypt_file_rs_controlled, get_keyfile_hash_rs,
    read_metadata_rs, verify_file_integrity_rs_controlled, ControlFlags, MetaInfo,
};
use secrecy::ExposeSecret;

use error::{CliError, ERR_INPUT_REQUIRED, ERR_IO, ERR_OUTPUT_EXISTS};
use password::PasswordSource;
use report::{MetaReport, Reporter};

const ABOUT: &str =
    "Cryptera — offline encryption with authenticated headers and Reed-Solomon recovery.";

const AFTER_HELP: &str = "\
Passwords are never taken from the command line. In order of precedence:
  --password-stdin        first line of stdin
  --password-file <PATH>  first line of the file
  --password-env <VAR>    the named environment variable
  $CRYPTERA_PASSWORD      used when no flag is given
  interactive prompt      only when stdin is a terminal

Exit codes: 0 ok, 1 error, 2 usage, 3 wrong password, 4 corrupt/not an ECF
container, 5 output exists, 6 cancelled.

Examples:
  cryptera encrypt report.pdf --password-env PW
  cryptera encrypt ./photos --folder-comp gz -o photos.ecf --password-file pw.txt
  printf '%s' \"$PW\" | cryptera decrypt photos.ecf -o ./restored --password-stdin
  cryptera verify backup.ecf --json --password-env PW";

#[derive(Parser)]
#[command(name = "cryptera", version, about = ABOUT, after_help = AFTER_HELP)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt a file or a folder into an .ecf container
    Encrypt(EncryptArgs),
    /// Decrypt an .ecf container
    Decrypt(DecryptArgs),
    /// Check password and integrity without writing any output
    Verify(VerifyArgs),
    /// Print container header metadata (no password needed)
    Meta(MetaArgs),
}

#[derive(Args)]
struct OutputOpts {
    /// Emit a single JSON object on stdout instead of human-readable text
    #[arg(long, global = true)]
    json: bool,
    /// Do not write progress to stderr
    #[arg(short, long, global = true)]
    quiet: bool,
}

#[derive(Args)]
struct PasswordOpts {
    /// Read the password from this environment variable
    #[arg(long, value_name = "VAR", conflicts_with_all = ["password_file", "password_stdin"])]
    password_env: Option<String>,
    /// Read the password from the first line of this file
    #[arg(long, value_name = "PATH", conflicts_with_all = ["password_env", "password_stdin"])]
    password_file: Option<PathBuf>,
    /// Read the password from the first line of stdin
    #[arg(long, conflicts_with_all = ["password_env", "password_file"])]
    password_stdin: bool,
    /// Keyfile mixed into key derivation (must match the one used to encrypt)
    #[arg(long, value_name = "PATH")]
    keyfile: Option<PathBuf>,
}

impl PasswordOpts {
    fn source(&self) -> PasswordSource<'_> {
        PasswordSource {
            env: self.password_env.as_deref(),
            file: self.password_file.as_deref(),
            stdin: self.password_stdin,
        }
    }

    fn keyfile_hash(&self) -> Result<Option<Vec<u8>>, CliError> {
        match self.keyfile.as_deref() {
            Some(p) => Ok(Some(get_keyfile_hash_rs(&p.to_string_lossy())?)),
            None => Ok(None),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum SecProfile {
    /// Argon2id 3 passes / 64 MiB
    Standard,
    /// Argon2id 6 passes / 256 MiB
    Strong,
    /// Argon2id 10 passes / 512 MiB
    Paranoid,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum IntProfile {
    /// 28 data / 4 parity shards
    Low,
    /// 24 data / 8 parity shards
    Medium,
    /// 12 data / 12 parity shards
    High,
    /// 8 data / 24 parity shards
    Max,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum FileComp {
    None,
    Zlib,
    Lzma,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum FolderComp {
    None,
    Gz,
    Bz2,
    Xz,
}

impl SecProfile {
    fn as_core(self) -> &'static str {
        match self {
            Self::Standard => "Standard",
            Self::Strong => "Strong",
            Self::Paranoid => "Paranoid",
        }
    }
}

impl IntProfile {
    fn as_core(self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Max => "Max",
        }
    }
}

impl FileComp {
    fn as_core(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Zlib => Some("zlib"),
            Self::Lzma => Some("lzma"),
        }
    }
}

impl FolderComp {
    fn as_core(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Gz => "gz",
            Self::Bz2 => "bz2",
            Self::Xz => "xz",
        }
    }
}

#[derive(Args)]
struct EncryptArgs {
    /// File or folder to encrypt (folders are archived to TAR first)
    input: PathBuf,
    /// Output container. Default: <input>.ecf
    #[arg(short, long, value_name = "PATH")]
    output: Option<PathBuf>,
    /// Argon2id cost
    #[arg(long, value_enum, default_value_t = SecProfile::Standard)]
    sec_profile: SecProfile,
    /// Reed-Solomon shard split
    #[arg(long, value_enum, default_value_t = IntProfile::Medium)]
    int_profile: IntProfile,
    /// Compression applied to a single file before encryption
    #[arg(long, value_enum, default_value_t = FileComp::None)]
    file_comp: FileComp,
    /// Compression applied to the TAR archive of a folder
    #[arg(long, value_enum, default_value_t = FolderComp::None)]
    folder_comp: FolderComp,
    /// Archive symlinks and special entries instead of skipping them (folders)
    #[arg(long)]
    keep_symlinks: bool,
    /// Do not store the password-check record
    #[arg(long)]
    no_pwchk: bool,
    /// Do not store the original name in the header
    #[arg(long)]
    hide_filename: bool,
    /// Overwrite the output if it already exists
    #[arg(short, long)]
    force: bool,
    #[command(flatten)]
    pw: PasswordOpts,
    #[command(flatten)]
    out: OutputOpts,
}

#[derive(Args)]
struct DecryptArgs {
    /// Container to decrypt
    input: PathBuf,
    /// Output file, or output directory when extracting. Default: derived from
    /// the header, else the input name without .ecf
    #[arg(short, long, value_name = "PATH")]
    output: Option<PathBuf>,
    /// Unpack the TAR container into the output directory (default for
    /// containers)
    #[arg(long, conflicts_with = "no_extract")]
    extract: bool,
    /// Write the raw TAR instead of unpacking it
    #[arg(long)]
    no_extract: bool,
    /// Also keep decrypted.tar next to the extracted files
    #[arg(long)]
    keep_tar: bool,
    /// Overwrite an existing output file, or extract into a non-empty directory
    #[arg(short, long)]
    force: bool,
    #[command(flatten)]
    pw: PasswordOpts,
    #[command(flatten)]
    out: OutputOpts,
}

#[derive(Args)]
struct VerifyArgs {
    /// Container to verify
    input: PathBuf,
    #[command(flatten)]
    pw: PasswordOpts,
    #[command(flatten)]
    out: OutputOpts,
}

#[derive(Args)]
struct MetaArgs {
    /// Container to inspect
    input: PathBuf,
    #[command(flatten)]
    out: OutputOpts,
}

fn main() {
    let cli = Cli::parse();
    let (json, quiet) = match &cli.command {
        Command::Encrypt(a) => (a.out.json, a.out.quiet),
        Command::Decrypt(a) => (a.out.json, a.out.quiet),
        Command::Verify(a) => (a.out.json, a.out.quiet),
        Command::Meta(a) => (a.out.json, a.out.quiet),
    };
    let reporter = Reporter::new(json, quiet);

    let result = match cli.command {
        Command::Encrypt(args) => run_encrypt(args, &reporter),
        Command::Decrypt(args) => run_decrypt(args, &reporter),
        Command::Verify(args) => run_verify(args, &reporter),
        Command::Meta(args) => run_meta(args, &reporter),
    };

    if let Err(err) = result {
        reporter.failure(&err);
        std::process::exit(err.exit_code());
    }
    std::process::exit(error::EXIT_OK);
}

fn path_str(p: &Path) -> String {
    p.to_string_lossy().to_string()
}

/// Refuse to clobber an existing path unless `--force` was passed.
fn guard_output(path: &Path, force: bool) -> Result<(), CliError> {
    if path.exists() && !force {
        return Err(CliError::new(
            ERR_OUTPUT_EXISTS,
            format!("{} already exists (use --force)", path.display()),
        ));
    }
    Ok(())
}

fn ensure_parent_dir(path: &Path) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| CliError::new(ERR_IO, e.to_string()))?;
        }
    }
    Ok(())
}

fn run_encrypt(args: EncryptArgs, out: &Reporter) -> Result<(), CliError> {
    if !args.input.exists() {
        return Err(CliError::new(
            ERR_INPUT_REQUIRED,
            format!("{} does not exist", args.input.display()),
        ));
    }
    let is_dir = args.input.is_dir();
    let output = args
        .output
        .clone()
        .unwrap_or_else(|| paths::default_encrypt_output(&args.input, is_dir));
    guard_output(&output, args.force)?;
    ensure_parent_dir(&output)?;

    let pw = password::resolve(&args.pw.source(), true)?;
    let kf_hash = args.pw.keyfile_hash()?;
    let ctrl = ControlFlags::new();

    let (sec_t, sec_m, sec_p) = cryptera_ops::sec_profile_params(args.sec_profile.as_core());
    let (k, r) = cryptera_ops::int_profile_params(args.int_profile.as_core());

    // A folder is archived to a temporary TAR first; the tempfile is deleted
    // when it drops, so it must outlive the encryption call.
    let (input_path, original_name, _tmp_guard) = if is_dir {
        out.stage("archiving");
        // Pre-counting the walk turns the archiving phase into a real
        // percentage, as the GUI does.
        let total_entries = cryptera_ops::count_entries(&args.input);
        let mut entries = |count: u64| out.progress("archiving", count, total_entries);
        let (tmp, name) = create_tar(
            &args.input,
            args.folder_comp.as_core(),
            !args.keep_symlinks,
            &ctrl,
            Some(&mut entries),
        )?;
        let tar_path = path_str(tmp.path());
        (tar_path, Some(name), Some(tmp))
    } else {
        (path_str(&args.input), None, None)
    };

    let stored_name: Option<&str> = if args.hide_filename {
        Some("")
    } else {
        original_name.as_deref()
    };

    out.stage("encrypting");
    let mut progress = |stage: &str, done: u64, total: u64| out.progress(stage, done, total);
    encrypt_file_rs_controlled(
        &input_path,
        &path_str(&output),
        pw.expose_secret(),
        kf_hash.as_deref(),
        if is_dir {
            None
        } else {
            args.file_comp.as_core()
        },
        !args.no_pwchk,
        Some(k),
        Some(r),
        None,
        Some(sec_t),
        Some(sec_m),
        Some(sec_p),
        stored_name,
        is_dir,
        Some(&ctrl),
        Some(&mut progress),
    )?;

    let stored_size = std::fs::metadata(&output).map(|m| m.len()).unwrap_or(0);
    out.encrypt_done(
        &args.input,
        &output,
        is_dir,
        if is_dir {
            Some(tar_suffix(args.folder_comp.as_core()))
        } else {
            None
        },
        stored_size,
    );
    Ok(())
}

fn run_decrypt(args: DecryptArgs, out: &Reporter) -> Result<(), CliError> {
    if !args.input.is_file() {
        return Err(CliError::new(
            ERR_INPUT_REQUIRED,
            format!("{} is not a file", args.input.display()),
        ));
    }

    // The header is readable without the password: it tells us whether the
    // payload is a container and, when not hidden, the original name — both
    // needed to pick a default output before doing any work.
    let header = read_metadata_rs(&path_str(&args.input))?;
    let container = is_tar_container(header.flags);
    let extract = if args.extract {
        true
    } else if args.no_extract {
        false
    } else {
        container
    };
    if extract && !container {
        return Err(CliError::new(
            "NOT_A_CONTAINER",
            "--extract was requested but this container holds a single file",
        ));
    }

    let output = args.output.clone().unwrap_or_else(|| {
        if extract {
            paths::strip_ecf(&args.input)
        } else {
            paths::default_decrypt_output(&args.input, &header.filename)
        }
    });

    let pw = password::resolve(&args.pw.source(), false)?;
    let kf_hash = args.pw.keyfile_hash()?;
    let ctrl = ControlFlags::new();
    let mut progress = |stage: &str, done: u64, total: u64| out.progress(stage, done, total);

    if !extract {
        // From v5 on, the original name is encrypted: it only becomes readable
        // once the payload has been decrypted. When the caller did not pick an
        // output we therefore decrypt to a scratch sibling first and rename to
        // the recovered name, so `cryptera decrypt report.ecf` restores
        // report.txt rather than an extension-less "report".
        let name_known_upfront =
            args.output.is_some() || paths::sanitize_stored_filename(&header.filename).is_some();
        if name_known_upfront {
            guard_output(&output, args.force)?;
            ensure_parent_dir(&output)?;
            out.stage("decrypting");
            let meta = decrypt_file_ex_rs_controlled(
                &path_str(&args.input),
                &path_str(&output),
                pw.expose_secret(),
                kf_hash.as_deref(),
                Some(&ctrl),
                Some(&mut progress),
            )?;
            out.decrypt_done(&args.input, &output, false, &meta);
            return Ok(());
        }

        let dir = match args.input.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let scratch = scratch_sibling(&dir);
        out.stage("decrypting");
        let meta = decrypt_file_ex_rs_controlled(
            &path_str(&args.input),
            &path_str(&scratch),
            pw.expose_secret(),
            kf_hash.as_deref(),
            Some(&ctrl),
            Some(&mut progress),
        )
        .inspect_err(|_| {
            let _ = std::fs::remove_file(&scratch);
        })?;

        let final_path = paths::default_decrypt_output(&args.input, &meta.filename);
        if let Err(e) = guard_output(&final_path, args.force) {
            let _ = std::fs::remove_file(&scratch);
            return Err(e);
        }
        std::fs::rename(&scratch, &final_path).map_err(|e| {
            let _ = std::fs::remove_file(&scratch);
            CliError::new(ERR_IO, e.to_string())
        })?;
        out.decrypt_done(&args.input, &final_path, false, &meta);
        return Ok(());
    }

    if output.exists() && !output.is_dir() {
        return Err(CliError::new(
            ERR_OUTPUT_EXISTS,
            format!("{} exists and is not a directory", output.display()),
        ));
    }
    if paths::dir_is_non_empty(&output) && !args.force {
        return Err(CliError::new(
            ERR_OUTPUT_EXISTS,
            format!("{} is not empty (use --force)", output.display()),
        ));
    }
    std::fs::create_dir_all(&output).map_err(|e| CliError::new(ERR_IO, e.to_string()))?;

    // safe_extract_tar sniffs the compression from the extension, so the
    // temporary TAR has to carry the suffix recorded in the header.
    let suffix = tar_extension(&header.filename);
    let tmp_dir = tempfile::tempdir().map_err(|e| CliError::new(ERR_IO, e.to_string()))?;
    let tar_path = tmp_dir.path().join(format!("payload{suffix}"));

    out.stage("decrypting");
    let meta = decrypt_file_ex_rs_controlled(
        &path_str(&args.input),
        &path_str(&tar_path),
        pw.expose_secret(),
        kf_hash.as_deref(),
        Some(&ctrl),
        Some(&mut progress),
    )?;

    // The name may only become readable after decryption (v5 encrypts it), in
    // which case the temp file needs renaming before the extension sniffing.
    let real_suffix = tar_extension(&meta.filename);
    let tar_path = if real_suffix != suffix {
        let renamed = tmp_dir.path().join(format!("payload{real_suffix}"));
        std::fs::rename(&tar_path, &renamed).map_err(|e| CliError::new(ERR_IO, e.to_string()))?;
        renamed
    } else {
        tar_path
    };

    out.stage("extracting");
    safe_extract_tar(&path_str(&tar_path), &path_str(&output))?;

    if args.keep_tar {
        let target = output.join("decrypted.tar");
        std::fs::copy(&tar_path, &target).map_err(|e| CliError::new(ERR_IO, e.to_string()))?;
    }

    out.decrypt_done(&args.input, &output, true, &meta);
    Ok(())
}

/// An unused path next to the container, used to stage a decrypt whose final
/// name is only known afterwards. Same directory as the destination so the
/// final step is a rename, not a copy across filesystems.
fn scratch_sibling(dir: &Path) -> PathBuf {
    let pid = std::process::id();
    for n in 0u32.. {
        let candidate = dir.join(format!(".cryptera-{pid}-{n}.part"));
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!("u32 candidates exhausted")
}

/// TAR extension recorded in the stored archive name, defaulting to `.tar`.
fn tar_extension(stored_name: &str) -> &'static str {
    let lower = stored_name.to_lowercase();
    if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        ".tar.gz"
    } else if lower.ends_with(".tar.bz2") || lower.ends_with(".tbz2") {
        ".tar.bz2"
    } else if lower.ends_with(".tar.xz") || lower.ends_with(".txz") {
        ".tar.xz"
    } else {
        ".tar"
    }
}

fn run_verify(args: VerifyArgs, out: &Reporter) -> Result<(), CliError> {
    if !args.input.is_file() {
        return Err(CliError::new(
            ERR_INPUT_REQUIRED,
            format!("{} is not a file", args.input.display()),
        ));
    }
    let pw = password::resolve(&args.pw.source(), false)?;
    let kf_hash = args.pw.keyfile_hash()?;
    let ctrl = ControlFlags::new();
    let mut progress = |stage: &str, done: u64, total: u64| out.progress(stage, done, total);

    out.stage("verifying");
    let meta = verify_file_integrity_rs_controlled(
        &path_str(&args.input),
        pw.expose_secret(),
        kf_hash.as_deref(),
        Some(&ctrl),
        Some(&mut progress),
    )?;
    out.verify_done(&args.input, &meta);
    Ok(())
}

fn run_meta(args: MetaArgs, out: &Reporter) -> Result<(), CliError> {
    if !args.input.is_file() {
        return Err(CliError::new(
            ERR_INPUT_REQUIRED,
            format!("{} is not a file", args.input.display()),
        ));
    }
    let meta = read_metadata_rs(&path_str(&args.input))?;
    out.meta_done(&args.input, &meta);
    Ok(())
}

/// Shared by the reporter: metadata as it is presented to the user.
fn meta_report(meta: &MetaInfo) -> MetaReport {
    MetaReport::from(meta)
}

/// stderr is only decorated when it is a terminal; redirected output stays
/// line-oriented and greppable.
fn stderr_is_tty() -> bool {
    std::io::stderr().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn tar_extension_follows_the_stored_name() {
        assert_eq!(tar_extension("photos.tar.gz"), ".tar.gz");
        assert_eq!(tar_extension("photos.TGZ"), ".tar.gz");
        assert_eq!(tar_extension("photos.tar.bz2"), ".tar.bz2");
        assert_eq!(tar_extension("photos.tar.xz"), ".tar.xz");
        assert_eq!(tar_extension("photos.tar"), ".tar");
        assert_eq!(tar_extension(""), ".tar");
    }

    #[test]
    fn profile_names_match_the_core_strings() {
        assert_eq!(
            cryptera_ops::sec_profile_params(SecProfile::Paranoid.as_core()),
            (10, 512 * 1024, 8)
        );
        assert_eq!(
            cryptera_ops::int_profile_params(IntProfile::Max.as_core()),
            (8, 24)
        );
        assert_eq!(FileComp::Lzma.as_core(), Some("lzma"));
        assert_eq!(FileComp::None.as_core(), None);
        assert_eq!(FolderComp::Bz2.as_core(), "bz2");
    }
}
