use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

use crypto_core_rs::{
    decrypt_file_ex_rs, encrypt_file_rs, get_keyfile_hash_rs, read_metadata_rs,
    verify_file_integrity_rs, CoreError, MetaInfo,
};
use rpassword::prompt_password;
use tar::Builder;
use tempfile::NamedTempFile;
use walkdir::WalkDir;

const HDR_FLAG_COMPRESS_ZLIB: u8 = 0x02;
const HDR_FLAG_COMPRESS_LZMA: u8 = 0x08;
const HDR_FLAG_TAR_CONTAINER: u8 = 0x20;

#[derive(Parser)]
#[command(name = "crypto", about = "CryptoV2 CLI - Secure File Encryptor/Decryptor")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt {
        input: String,
        output: String,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(short, long)]
        keyfile: Option<String>,
        #[arg(short, long, value_parser = ["zlib", "lzma"])]
        compress: Option<String>,
        #[arg(long)]
        hide_filename: bool,
        #[arg(long, default_value = "Standard")]
        security: String,
        #[arg(long, default_value = "Medium")]
        integrity: String,
    },
    EncryptFolder {
        input: String,
        output: String,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(short, long)]
        keyfile: Option<String>,
        #[arg(long, default_value = "none", value_parser = ["none", "gz", "bz2", "xz"])]
        tar_compress: String,
        #[arg(long)]
        skip_special: bool,
        #[arg(long)]
        hide_filename: bool,
        #[arg(long, default_value = "Standard")]
        security: String,
        #[arg(long, default_value = "Medium")]
        integrity: String,
    },
    Decrypt {
        input: String,
        output: String,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(short, long)]
        keyfile: Option<String>,
    },
    Info {
        input: String,
    },
    Verify {
        input: String,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(short, long)]
        keyfile: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Encrypt {
            input,
            output,
            password,
            keyfile,
            compress,
            hide_filename,
            security,
            integrity,
        } => cmd_encrypt(
            &input,
            &output,
            password,
            keyfile,
            compress,
            hide_filename,
            &security,
            &integrity,
        ),
        Commands::EncryptFolder {
            input,
            output,
            password,
            keyfile,
            tar_compress,
            skip_special,
            hide_filename,
            security,
            integrity,
        } => cmd_encrypt_folder(
            &input,
            &output,
            password,
            keyfile,
            &tar_compress,
            skip_special,
            hide_filename,
            &security,
            &integrity,
        ),
        Commands::Decrypt {
            input,
            output,
            password,
            keyfile,
        } => cmd_decrypt(&input, &output, password, keyfile),
        Commands::Info { input } => cmd_info(&input),
        Commands::Verify {
            input,
            password,
            keyfile,
        } => cmd_verify(&input, password, keyfile),
    };

    if let Err(err) = result {
        eprintln!("ERROR [{}]: {}", err.code, err.message);
        std::process::exit(1);
    }
}

fn prompt_or_err(label: &str, provided: Option<String>) -> Result<String, CoreError> {
    if let Some(p) = provided {
        if p.is_empty() {
            return Err(CoreError::new("PASSWORD_INVALID", "Password cannot be empty."));
        }
        return Ok(p);
    }
    let pw = prompt_password(label).map_err(|e| CoreError::new("IO_ERROR", e.to_string()))?;
    if pw.is_empty() {
        return Err(CoreError::new("PASSWORD_INVALID", "Password cannot be empty."));
    }
    Ok(pw)
}

fn security_profile(name: &str) -> Result<(u32, u32, u16), CoreError> {
    match name {
        "Standard" => Ok((3, 64 * 1024, 2)),
        "Strong" => Ok((6, 256 * 1024, 4)),
        "Paranoid" => Ok((10, 512 * 1024, 8)),
        _ => Err(CoreError::new("PARAMS_OUT_OF_LIMITS", "Unknown security profile")),
    }
}

fn integrity_profile(name: &str) -> Result<(u16, u16), CoreError> {
    match name {
        "Low" => Ok((28, 4)),
        "Medium" => Ok((24, 8)),
        "High" => Ok((12, 12)),
        "Max" => Ok((8, 24)),
        _ => Err(CoreError::new("PARAMS_OUT_OF_LIMITS", "Unknown integrity profile")),
    }
}

fn load_keyfile_hash(path: Option<String>) -> Result<Option<Vec<u8>>, CoreError> {
    if let Some(p) = path {
        let hash = get_keyfile_hash_rs(&p)?;
        Ok(Some(hash))
    } else {
        Ok(None)
    }
}

fn cmd_encrypt(
    input: &str,
    output: &str,
    password: Option<String>,
    keyfile: Option<String>,
    compress: Option<String>,
    hide_filename: bool,
    security: &str,
    integrity: &str,
) -> Result<(), CoreError> {
    let password = prompt_or_err("Encryption Password: ", password)?;
    let (t, m, p) = security_profile(security)?;
    let (k, r) = integrity_profile(integrity)?;
    let kf_hash = load_keyfile_hash(keyfile)?;

    let original_filename = if hide_filename { Some("") } else { None };
    println!("Encrypting {input} -> {output}...");
    encrypt_file_rs(
        input,
        output,
        &password,
        kf_hash.as_deref(),
        compress.as_deref(),
        true,
        Some(k),
        Some(r),
        None,
        Some(t),
        Some(m),
        Some(p),
        original_filename,
        false,
    )?;
    println!("Encryption complete.");
    Ok(())
}

fn cmd_encrypt_folder(
    input: &str,
    output: &str,
    password: Option<String>,
    keyfile: Option<String>,
    tar_compress: &str,
    skip_special: bool,
    hide_filename: bool,
    security: &str,
    integrity: &str,
) -> Result<(), CoreError> {
    let password = prompt_or_err("Encryption Password: ", password)?;
    let (t, m, p) = security_profile(security)?;
    let (k, r) = integrity_profile(integrity)?;
    let kf_hash = load_keyfile_hash(keyfile)?;

    let (tmp_tar, base_name) = create_tar(Path::new(input), tar_compress, skip_special)?;
    let tar_path = tmp_tar.path().to_string_lossy().to_string();
    let original_name = if hide_filename { Some("") } else { Some(base_name.as_str()) };

    println!("Encrypting {input} -> {output} (TAR)...");
    encrypt_file_rs(
        &tar_path,
        output,
        &password,
        kf_hash.as_deref(),
        None,
        true,
        Some(k),
        Some(r),
        None,
        Some(t),
        Some(m),
        Some(p),
        original_name,
        true,
    )?;
    println!("Encryption complete.");
    Ok(())
}

fn cmd_decrypt(
    input: &str,
    output: &str,
    password: Option<String>,
    keyfile: Option<String>,
) -> Result<(), CoreError> {
    let password = prompt_or_err("Decryption Password: ", password)?;
    let kf_hash = load_keyfile_hash(keyfile)?;

    println!("Decrypting {input} -> {output}...");
    let meta = decrypt_file_ex_rs(input, output, &password, kf_hash.as_deref())?;
    println!("Decryption complete. Original filename: {}", display_filename(&meta));
    Ok(())
}

fn cmd_info(input: &str) -> Result<(), CoreError> {
    let meta = read_metadata_rs(input)?;
    let comp = if meta.flags & HDR_FLAG_COMPRESS_ZLIB != 0 {
        "zlib"
    } else if meta.flags & HDR_FLAG_COMPRESS_LZMA != 0 {
        "lzma"
    } else {
        "none"
    };
    let container = if meta.flags & HDR_FLAG_TAR_CONTAINER != 0 {
        "tar"
    } else {
        "none"
    };

    println!("Format Version: {}", meta.version);
    println!("Plain Size:     {} bytes", meta.plain_size);
    println!("Stored Size:    {} bytes", meta.stored_size);
    println!(
        "Integrity:      k={}, r={}, shard={} bytes",
        meta.k, meta.r, meta.shard_size
    );
    println!(
        "Security:       Argon2id (t={}, m={} KiB, p={})",
        meta.argon2_time, meta.argon2_mem_kib, meta.argon2_par
    );
    println!("Compression:    {}", comp);
    println!("Container:      {}", container);
    println!("Filename:       {}", display_filename(&meta));
    Ok(())
}

fn cmd_verify(
    input: &str,
    password: Option<String>,
    keyfile: Option<String>,
) -> Result<(), CoreError> {
    let password = prompt_or_err("Decryption Password: ", password)?;
    let kf_hash = load_keyfile_hash(keyfile)?;

    println!("Verifying {input}...");
    verify_file_integrity_rs(input, &password, kf_hash.as_deref())?;
    println!("Verification OK.");
    Ok(())
}

fn display_filename(meta: &MetaInfo) -> String {
    if meta.filename.is_empty() {
        "(Hidden)".to_string()
    } else {
        meta.filename.clone()
    }
}

fn tar_suffix(comp: &str) -> &'static str {
    match comp {
        "gz" => ".tar.gz",
        "bz2" => ".tar.bz2",
        "xz" => ".tar.xz",
        _ => ".tar",
    }
}

fn create_tar(folder: &Path, comp: &str, skip_special: bool) -> Result<(NamedTempFile, String), CoreError> {
    let base_name = folder
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let tmp = NamedTempFile::new()
        .map_err(|e| CoreError::new("IO_ERROR", e.to_string()))?;

    let file = tmp
        .reopen()
        .map_err(|e| CoreError::new("IO_ERROR", e.to_string()))?;

    let writer: Box<dyn std::io::Write> = match comp {
        "gz" => Box::new(flate2::write::GzEncoder::new(file, flate2::Compression::default())),
        "bz2" => Box::new(bzip2::write::BzEncoder::new(file, bzip2::Compression::default())),
        "xz" => Box::new(xz2::write::XzEncoder::new(file, 6)),
        _ => Box::new(file),
    };

    let mut builder = Builder::new(writer);
    let base_prefix = PathBuf::from(&base_name);

    for entry in WalkDir::new(folder).follow_links(false) {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => {
                if skip_special {
                    continue;
                } else {
                    return Err(CoreError::new("IO_ERROR", "Failed to read directory entry"));
                }
            }
        };

        if skip_special && entry.file_type().is_symlink() {
            continue;
        }

        let path = entry.path();
        let rel = match path.strip_prefix(folder) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let tar_path = if rel.as_os_str().is_empty() {
            base_prefix.clone()
        } else {
            base_prefix.join(rel)
        };

        if entry.file_type().is_dir() {
            builder
                .append_dir(&tar_path, path)
                .map_err(|e| CoreError::new("IO_ERROR", e.to_string()))?;
        } else if entry.file_type().is_file() {
            builder
                .append_path_with_name(path, &tar_path)
                .map_err(|e| CoreError::new("IO_ERROR", e.to_string()))?;
        }
    }

    builder
        .finish()
        .map_err(|e| CoreError::new("IO_ERROR", e.to_string()))?;

    Ok((tmp, format!("{base_name}{}", tar_suffix(comp))))
}
