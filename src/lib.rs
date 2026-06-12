#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![allow(clippy::needless_range_loop)]

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crc32fast::Hasher as Crc32;
use flate2::write::{ZlibDecoder, ZlibEncoder};
use flate2::Compression;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use tempfile::NamedTempFile;
use xz2::write::XzDecoder;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"ECF1";
const TRAILER: &[u8; 4] = b"ECCT";
const VERSION_U8: u8 = 4;

const ALG_AES_GCM: u8 = 1;
const KDF_ARGON2ID: u8 = 1;
const CRC_CRC32: u8 = 1;

const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;

const K_DATA: u16 = 24;
const R_PARITY: u16 = 8;
const SHARD_SIZE: u32 = 16 * 1024;

const ARGON2_TIME: u32 = 3;
const ARGON2_MEM_KIB: u32 = 65536;
const ARGON2_PAR: u16 = 2;

const CRC_COPIES: usize = 2;
const CRC_BLOCK_SIZE: usize = 4 * CRC_COPIES;
const MAX_HEADER_LEN: usize = 8192;

const ARGON2_TIME_MIN: u32 = 1;
const ARGON2_TIME_MAX: u32 = 10;
const ARGON2_MEM_KIB_MIN: u32 = 8 * 1024;
const ARGON2_MEM_KIB_MAX: u32 = 512 * 1024;
const ARGON2_PAR_MIN: u16 = 1;
const ARGON2_PAR_MAX: u16 = 8;

const K_MIN: u16 = 1;
const K_MAX: u16 = 64;
const R_MIN: u16 = 1;
const R_MAX: u16 = 64;
const SHARD_SIZE_MIN: u32 = 1024;
const SHARD_SIZE_MAX: u32 = 1024 * 1024;
const MAX_BLOCKS_U32: u64 = 1u64 << 32;

const HDR_FLAG_PWCHK: u8 = 0x01;
const HDR_FLAG_COMPRESS_ZLIB: u8 = 0x02;
const HDR_FLAG_COMPRESS_LZMA: u8 = 0x08;
const HDR_FLAG_HAS_FILENAME: u8 = 0x10;
const HDR_FLAG_TAR_CONTAINER: u8 = 0x20;

const PWCHK_MAGIC: &[u8; 4] = b"PWCK";
const PWCHK_PLAINTEXT_LEN: usize = 32;
const PWCHK_PLAINTEXT: [u8; PWCHK_PLAINTEXT_LEN] = *b"ECF1-PASSWORD-CHECK-RECORD-000\0\0";
const PWCHK_RECORD_SIZE: usize = 4 + (4 * CRC_COPIES) + PWCHK_PLAINTEXT_LEN + TAG_LEN;
const HEADER_AUTH_TAG_LEN: usize = 16;
const HEADER_AUTH_CONTEXT: &[u8] = b"ECF1-HEADER-AUTH-V1";

const DECRYPT_PASSWORD_INVALID: &str = "PASSWORD_INVALID";
const DECRYPT_CORRUPT_BEYOND_FEC: &str = "CORRUPT_BEYOND_FEC";
const DECRYPT_HEADER_INVALID: &str = "HEADER_INVALID";
const DECRYPT_HEADER_AUTH_FAILED: &str = "HEADER_AUTH_FAILED";
const DECRYPT_PARAMS_OUT_OF_LIMITS: &str = "PARAMS_OUT_OF_LIMITS";
const DECRYPT_TRUNCATED: &str = "TRUNCATED";
const DECRYPT_IO_ERROR: &str = "IO_ERROR";
const DECRYPT_CANCELLED: &str = "CANCELLED";
const DECRYPT_UNKNOWN_ERROR: &str = "UNKNOWN_ERROR";

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
pub struct CoreError {
    pub code: &'static str,
    pub message: String,
}

impl CoreError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

fn crc32_bytes(data: &[u8]) -> u32 {
    let mut hasher = Crc32::new();
    hasher.update(data);
    hasher.finalize()
}

fn nonce12(nonce_base: u32, block_index: u32, shard_index: u32) -> [u8; 12] {
    let mut out = [0u8; 12];
    (&mut out[0..4]).write_u32::<BigEndian>(nonce_base).unwrap();
    (&mut out[4..8])
        .write_u32::<BigEndian>(block_index)
        .unwrap();
    (&mut out[8..12])
        .write_u32::<BigEndian>(shard_index)
        .unwrap();
    out
}

fn validate_limits(
    k: u16,
    r: u16,
    shard_size: u32,
    argon2_time: u32,
    argon2_mem_kib: u32,
    argon2_par: u16,
    num_blocks: Option<u64>,
) -> Result<(), CoreError> {
    if !(ARGON2_TIME_MIN..=ARGON2_TIME_MAX).contains(&argon2_time) {
        return Err(CoreError::new(
            DECRYPT_PARAMS_OUT_OF_LIMITS,
            format!("argon2_time out of limits: {argon2_time}"),
        ));
    }
    if !(ARGON2_MEM_KIB_MIN..=ARGON2_MEM_KIB_MAX).contains(&argon2_mem_kib) {
        return Err(CoreError::new(
            DECRYPT_PARAMS_OUT_OF_LIMITS,
            format!("argon2_mem_kib out of limits: {argon2_mem_kib}"),
        ));
    }
    if !(ARGON2_PAR_MIN..=ARGON2_PAR_MAX).contains(&argon2_par) {
        return Err(CoreError::new(
            DECRYPT_PARAMS_OUT_OF_LIMITS,
            format!("argon2_par out of limits: {argon2_par}"),
        ));
    }
    if !(K_MIN..=K_MAX).contains(&k) {
        return Err(CoreError::new(
            DECRYPT_PARAMS_OUT_OF_LIMITS,
            format!("k out of limits: {k}"),
        ));
    }
    if !(R_MIN..=R_MAX).contains(&r) {
        return Err(CoreError::new(
            DECRYPT_PARAMS_OUT_OF_LIMITS,
            format!("r out of limits: {r}"),
        ));
    }
    if (k as u32 + r as u32) > 255 {
        return Err(CoreError::new(
            DECRYPT_PARAMS_OUT_OF_LIMITS,
            format!("k+r must be <= 255, got {}", k as u32 + r as u32),
        ));
    }
    if !(SHARD_SIZE_MIN..=SHARD_SIZE_MAX).contains(&shard_size) {
        return Err(CoreError::new(
            DECRYPT_PARAMS_OUT_OF_LIMITS,
            format!("shard_size out of limits: {shard_size}"),
        ));
    }
    if let Some(nb) = num_blocks {
        if !(0 < nb && nb < MAX_BLOCKS_U32) {
            return Err(CoreError::new(
                DECRYPT_PARAMS_OUT_OF_LIMITS,
                format!("num_blocks out of limits: {nb}"),
            ));
        }
    }
    Ok(())
}

fn keyfile_hash(path: &Path) -> io::Result<Vec<u8>> {
    let mut sha = Sha256::new();
    let mut f = File::open(path)?;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        sha.update(&buf[..n]);
    }
    Ok(sha.finalize().to_vec())
}

fn derive_key(
    password: &str,
    salt: &[u8],
    t: u32,
    mem_kib: u32,
    par: u16,
    keyfile_hash: Option<&[u8]>,
) -> Result<[u8; KEY_LEN], CoreError> {
    if password.is_empty() {
        return Err(CoreError::new(
            DECRYPT_PASSWORD_INVALID,
            "Password invalid (empty).",
        ));
    }
    let mut secret = Zeroizing::new(password.as_bytes().to_vec());
    if let Some(kf) = keyfile_hash {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(kf)
            .map_err(|_| CoreError::new(DECRYPT_UNKNOWN_ERROR, "HMAC init failed"))?;
        mac.update(secret.as_slice());
        *secret = mac.finalize().into_bytes().to_vec();
    }

    let params = Params::new(mem_kib, t, par.into(), Some(KEY_LEN))
        .map_err(|e| CoreError::new(DECRYPT_UNKNOWN_ERROR, format!("Argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; KEY_LEN];
    argon2
        .hash_password_into(secret.as_slice(), salt, &mut out)
        .map_err(|e| CoreError::new(DECRYPT_UNKNOWN_ERROR, format!("Argon2 error: {e}")))?;
    Ok(out)
}

fn derive_header_auth_key(master_key: &[u8]) -> Result<[u8; KEY_LEN], CoreError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(master_key)
        .map_err(|_| CoreError::new(DECRYPT_UNKNOWN_ERROR, "HMAC init failed"))?;
    mac.update(HEADER_AUTH_CONTEXT);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&digest[..KEY_LEN]);
    Ok(out)
}

fn header_auth_tag(
    master_key: &[u8],
    prefix: &[u8],
    hdr_crc: u32,
) -> Result<[u8; HEADER_AUTH_TAG_LEN], CoreError> {
    let auth_key = Zeroizing::new(derive_header_auth_key(master_key)?);
    let mut mac = <HmacSha256 as Mac>::new_from_slice(auth_key.as_ref())
        .map_err(|_| CoreError::new(DECRYPT_UNKNOWN_ERROR, "HMAC init failed"))?;
    mac.update(prefix);
    mac.update(&hdr_crc.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; HEADER_AUTH_TAG_LEN];
    out.copy_from_slice(&digest[..HEADER_AUTH_TAG_LEN]);
    Ok(out)
}

fn write_header(
    plain_size: u64,
    stored_size: u64,
    k: u16,
    r: u16,
    shard_size: u32,
    flags: u8,
    t: u32,
    m: u32,
    p: u16,
    filename: Option<&str>,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, u16, u32, [u8; 16], u32, u8), CoreError> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let nonce_base = OsRng.next_u32();

    let mut hdr = Vec::with_capacity(128);
    hdr.write_u8(VERSION_U8).unwrap();
    hdr.write_u8(ALG_AES_GCM).unwrap();
    hdr.write_u8(KDF_ARGON2ID).unwrap();
    hdr.write_u8(CRC_CRC32).unwrap();
    hdr.write_u8(salt.len() as u8).unwrap();
    hdr.extend_from_slice(&salt);
    hdr.write_u32::<BigEndian>(nonce_base).unwrap();
    hdr.write_u64::<BigEndian>(plain_size).unwrap();
    hdr.write_u64::<BigEndian>(stored_size).unwrap();
    hdr.write_u32::<BigEndian>(shard_size).unwrap();
    hdr.write_u16::<BigEndian>(k).unwrap();
    hdr.write_u16::<BigEndian>(r).unwrap();
    hdr.write_u32::<BigEndian>(t).unwrap();
    hdr.write_u32::<BigEndian>(m).unwrap();
    hdr.write_u16::<BigEndian>(p).unwrap();
    hdr.write_u8(TAG_LEN as u8).unwrap();
    hdr.write_u8(flags).unwrap();

    if flags & HDR_FLAG_HAS_FILENAME != 0 {
        let fname_bytes = filename.unwrap_or("").as_bytes();
        hdr.write_u16::<BigEndian>(fname_bytes.len() as u16)
            .unwrap();
        hdr.extend_from_slice(fname_bytes);
    }

    if hdr.is_empty() || hdr.len() > MAX_HEADER_LEN {
        return Err(CoreError::new(
            DECRYPT_HEADER_INVALID,
            "Header length out of bounds",
        ));
    }

    let hdr_len = hdr.len() as u16;
    let mut prefix = Vec::with_capacity(6 + hdr.len());
    prefix.extend_from_slice(MAGIC);
    prefix.write_u16::<BigEndian>(hdr_len).unwrap();
    prefix.extend_from_slice(&hdr);
    let hdr_crc = crc32_bytes(&prefix);

    let mut start_header = prefix.clone();
    start_header.write_u32::<BigEndian>(hdr_crc).unwrap();

    let mut trailer = Vec::with_capacity(hdr.len() + 10);
    trailer.extend_from_slice(&hdr);
    trailer.write_u32::<BigEndian>(hdr_crc).unwrap();
    trailer.write_u16::<BigEndian>(hdr_len).unwrap();
    trailer.extend_from_slice(TRAILER);

    Ok((
        start_header,
        trailer,
        prefix,
        hdr_len,
        hdr_crc,
        salt,
        nonce_base,
        flags,
    ))
}
#[derive(Debug, Clone)]
struct HeaderParams {
    version: u8,
    salt: Vec<u8>,
    nonce_base: u32,
    plain_size: u64,
    stored_size: u64,
    shard_size: u32,
    k: u16,
    r: u16,
    argon2_time: u32,
    argon2_mem_kib: u32,
    argon2_par: u16,
    tag_len: u8,
    flags: u8,
    filename: String,
}

#[derive(Debug, Clone)]
struct HeaderBlob {
    hdr: Vec<u8>,
    hdr_len: u16,
    hdr_crc: u32,
    hdr_auth: Option<[u8; HEADER_AUTH_TAG_LEN]>,
}

#[derive(Debug, Clone)]
pub struct MetaInfo {
    pub filename: String,
    pub version: u8,
    pub k: u16,
    pub r: u16,
    pub shard_size: u32,
    pub plain_size: u64,
    pub stored_size: u64,
    pub flags: u8,
    pub argon2_time: u32,
    pub argon2_mem_kib: u32,
    pub argon2_par: u16,
}

fn meta_from_params(params: &HeaderParams) -> MetaInfo {
    MetaInfo {
        filename: params.filename.clone(),
        version: params.version,
        k: params.k,
        r: params.r,
        shard_size: params.shard_size,
        plain_size: params.plain_size,
        stored_size: params.stored_size,
        flags: params.flags,
        argon2_time: params.argon2_time,
        argon2_mem_kib: params.argon2_mem_kib,
        argon2_par: params.argon2_par,
    }
}

pub struct ControlFlags {
    pub cancel: Arc<AtomicBool>,
    pub pause: Arc<AtomicBool>,
}

fn control_wait(control: Option<&ControlFlags>) -> Result<(), CoreError> {
    if let Some(ctrl) = control {
        if ctrl.cancel.load(Ordering::SeqCst) {
            return Err(CoreError::new(DECRYPT_CANCELLED, "Operation cancelled."));
        }
        while ctrl.pause.load(Ordering::SeqCst) {
            if ctrl.cancel.load(Ordering::SeqCst) {
                return Err(CoreError::new(DECRYPT_CANCELLED, "Operation cancelled."));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    Ok(())
}

fn progress_report(
    progress: &mut Option<&mut dyn FnMut(&str, u64, u64)>,
    stage: &str,
    done: u64,
    total: u64,
) {
    if let Some(cb) = progress.as_mut() {
        cb(stage, done, total);
    }
}

fn parse_header(hdr: &[u8]) -> Result<HeaderParams, CoreError> {
    let mut rdr = io::Cursor::new(hdr);
    let version = rdr
        .read_u8()
        .map_err(|_| CoreError::new(DECRYPT_HEADER_INVALID, "Invalid header (version)"))?;
    let _alg = rdr
        .read_u8()
        .map_err(|_| CoreError::new(DECRYPT_HEADER_INVALID, "Invalid header (alg)"))?;
    let _kdf = rdr
        .read_u8()
        .map_err(|_| CoreError::new(DECRYPT_HEADER_INVALID, "Invalid header (kdf)"))?;
    let _crc = rdr
        .read_u8()
        .map_err(|_| CoreError::new(DECRYPT_HEADER_INVALID, "Invalid header (crc)"))?;
    let salt_len = rdr
        .read_u8()
        .map_err(|_| CoreError::new(DECRYPT_HEADER_INVALID, "Invalid header (salt_len)"))?;
    let mut salt = vec![0u8; salt_len as usize];
    rdr.read_exact(&mut salt)
        .map_err(|_| CoreError::new(DECRYPT_HEADER_INVALID, "Invalid header (salt)"))?;
    let nonce_base = rdr
        .read_u32::<BigEndian>()
        .map_err(|_| CoreError::new(DECRYPT_HEADER_INVALID, "Invalid header (nonce)"))?;
    let plain_size = rdr
        .read_u64::<BigEndian>()
        .map_err(|_| CoreError::new(DECRYPT_HEADER_INVALID, "Invalid header (plain_size)"))?;
    let stored_size = if version >= 3 {
        rdr.read_u64::<BigEndian>()
            .map_err(|_| CoreError::new(DECRYPT_HEADER_INVALID, "Invalid header (stored_size)"))?
    } else {
        plain_size
    };
    let shard_size = rdr
        .read_u32::<BigEndian>()
        .map_err(|_| CoreError::new(DECRYPT_HEADER_INVALID, "Invalid header (shard_size)"))?;
    let k = rdr
        .read_u16::<BigEndian>()
        .map_err(|_| CoreError::new(DECRYPT_HEADER_INVALID, "Invalid header (k)"))?;
    let r = rdr
        .read_u16::<BigEndian>()
        .map_err(|_| CoreError::new(DECRYPT_HEADER_INVALID, "Invalid header (r)"))?;
    let argon2_time = rdr
        .read_u32::<BigEndian>()
        .map_err(|_| CoreError::new(DECRYPT_HEADER_INVALID, "Invalid header (argon2_time)"))?;
    let argon2_mem_kib = rdr
        .read_u32::<BigEndian>()
        .map_err(|_| CoreError::new(DECRYPT_HEADER_INVALID, "Invalid header (argon2_mem)"))?;
    let argon2_par = rdr
        .read_u16::<BigEndian>()
        .map_err(|_| CoreError::new(DECRYPT_HEADER_INVALID, "Invalid header (argon2_par)"))?;
    let tag_len = rdr
        .read_u8()
        .map_err(|_| CoreError::new(DECRYPT_HEADER_INVALID, "Invalid header (tag_len)"))?;
    let flags = rdr
        .read_u8()
        .map_err(|_| CoreError::new(DECRYPT_HEADER_INVALID, "Invalid header (flags)"))?;

    let mut filename = String::new();
    let mut had_filename = false;
    if version >= 3 {
        if flags & HDR_FLAG_HAS_FILENAME != 0 {
            had_filename = true;
        }
    } else if version == 2 {
        had_filename = true;
    }

    if had_filename && (rdr.position() as usize + 2) <= hdr.len() {
        {
            let fname_len = rdr.read_u16::<BigEndian>().map_err(|_| {
                CoreError::new(DECRYPT_HEADER_INVALID, "Invalid header (fname_len)")
            })?;
            let pos = rdr.position() as usize;
            if pos + fname_len as usize <= hdr.len() {
                let mut fname = vec![0u8; fname_len as usize];
                rdr.read_exact(&mut fname).ok();
                if let Ok(s) = String::from_utf8(fname) {
                    filename = s;
                }
            }
        }
    }

    Ok(HeaderParams {
        version,
        salt,
        nonce_base,
        plain_size,
        stored_size,
        shard_size,
        k,
        r,
        argon2_time,
        argon2_mem_kib,
        argon2_par,
        tag_len,
        flags,
        filename,
    })
}

fn read_header_from_start(mut f: &File) -> io::Result<Option<HeaderBlob>> {
    let mut magic = [0u8; 4];
    if f.read_exact(&mut magic).is_err() || &magic != MAGIC {
        return Ok(None);
    }
    let hdr_len = f.read_u16::<BigEndian>().ok();
    let hdr_len = match hdr_len {
        Some(v) => v,
        None => return Ok(None),
    };
    if hdr_len == 0 || hdr_len as usize > MAX_HEADER_LEN {
        return Ok(None);
    }
    let mut hdr = vec![0u8; hdr_len as usize];
    if f.read_exact(&mut hdr).is_err() {
        return Ok(None);
    }
    let hdr_crc = f.read_u32::<BigEndian>().ok();
    let hdr_crc = match hdr_crc {
        Some(v) => v,
        None => return Ok(None),
    };
    let mut prefix = Vec::with_capacity(6 + hdr.len());
    prefix.extend_from_slice(MAGIC);
    prefix.write_u16::<BigEndian>(hdr_len).unwrap();
    prefix.extend_from_slice(&hdr);
    if crc32_bytes(&prefix) != hdr_crc {
        return Ok(None);
    }
    let version = hdr.first().copied().unwrap_or(0);
    let hdr_auth = if version >= 4 {
        let mut tag = [0u8; HEADER_AUTH_TAG_LEN];
        if f.read_exact(&mut tag).is_err() {
            return Ok(None);
        }
        Some(tag)
    } else {
        None
    };
    Ok(Some(HeaderBlob {
        hdr,
        hdr_len,
        hdr_crc,
        hdr_auth,
    }))
}

fn read_header_from_end(mut f: &File) -> io::Result<Option<HeaderBlob>> {
    let size = f.metadata()?.len();
    if size < 10 {
        return Ok(None);
    }
    let mut trailer = [0u8; 4];
    f.seek(io::SeekFrom::End(-4))?;
    f.read_exact(&mut trailer)?;
    if &trailer != TRAILER {
        return Ok(None);
    }
    f.seek(io::SeekFrom::End(-6))?;
    let hdr_len = f.read_u16::<BigEndian>()?;
    if hdr_len == 0 || hdr_len as usize > MAX_HEADER_LEN {
        return Ok(None);
    }

    let mut try_layout = |with_auth: bool| -> io::Result<Option<HeaderBlob>> {
        let trailer_overhead: i64 = if with_auth { 26 } else { 10 };
        let total_needed = trailer_overhead as u64 + hdr_len as u64;
        if size < total_needed {
            return Ok(None);
        }
        let base_from_end = trailer_overhead + hdr_len as i64;
        f.seek(io::SeekFrom::End(-base_from_end))?;
        let mut hdr = vec![0u8; hdr_len as usize];
        f.read_exact(&mut hdr)?;
        let hdr_crc = f.read_u32::<BigEndian>()?;
        let hdr_auth = if with_auth {
            let mut tag = [0u8; HEADER_AUTH_TAG_LEN];
            f.read_exact(&mut tag)?;
            Some(tag)
        } else {
            None
        };

        let mut prefix = Vec::with_capacity(6 + hdr.len());
        prefix.extend_from_slice(MAGIC);
        prefix.write_u16::<BigEndian>(hdr_len).unwrap();
        prefix.extend_from_slice(&hdr);
        if crc32_bytes(&prefix) != hdr_crc {
            return Ok(None);
        }
        let version = hdr.first().copied().unwrap_or(0);
        if version >= 4 && !with_auth {
            return Ok(None);
        }
        if version < 4 && with_auth {
            return Ok(None);
        }
        Ok(Some(HeaderBlob {
            hdr,
            hdr_len,
            hdr_crc,
            hdr_auth,
        }))
    };

    if let Some(h) = try_layout(true)? {
        return Ok(Some(h));
    }
    try_layout(false)
}
struct GfTables {
    inv: [u8; 256],
    mul: [[u8; 256]; 256],
}

fn gf_tables() -> &'static GfTables {
    use std::sync::OnceLock;
    static TABLES: OnceLock<GfTables> = OnceLock::new();
    TABLES.get_or_init(|| {
        const PRIMITIVE_POLY: u16 = 0x11D;
        let mut exp = [0u8; 512];
        let mut log = [0i16; 256];
        let mut x: u16 = 1;
        for i in 0..255 {
            exp[i] = x as u8;
            log[x as usize] = i as i16;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= PRIMITIVE_POLY;
            }
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        let mut inv = [0u8; 256];
        inv[0] = 0;
        for a in 1..256 {
            let idx = (255 - log[a] as i32) as usize;
            inv[a] = exp[idx];
        }
        let mut mul = [[0u8; 256]; 256];
        for a in 1..256 {
            let la = log[a] as i32;
            for b in 1..256 {
                let idx = (la + log[b] as i32) % 255;
                mul[a][b] = exp[idx as usize];
            }
        }
        GfTables { inv, mul }
    })
}

fn gf_mat_inv(a: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, CoreError> {
    let tbl = gf_tables();
    let k = a.len();
    let mut aug = vec![vec![0u8; k * 2]; k];
    for i in 0..k {
        for j in 0..k {
            aug[i][j] = a[i][j];
        }
        aug[i][k + i] = 1;
    }
    for col in 0..k {
        let mut pivot = None;
        for row in col..k {
            if aug[row][col] != 0 {
                pivot = Some(row);
                break;
            }
        }
        let pivot = pivot
            .ok_or_else(|| CoreError::new(DECRYPT_CORRUPT_BEYOND_FEC, "Matrix not invertible"))?;
        if pivot != col {
            aug.swap(pivot, col);
        }
        let pv = aug[col][col];
        let inv_pv = tbl.inv[pv as usize];
        if inv_pv != 1 {
            for j in 0..(k * 2) {
                let val = aug[col][j];
                aug[col][j] = tbl.mul[inv_pv as usize][val as usize];
            }
        }
        for row in 0..k {
            if row == col {
                continue;
            }
            let factor = aug[row][col];
            if factor != 0 {
                for j in 0..(k * 2) {
                    let val = aug[col][j];
                    aug[row][j] ^= tbl.mul[factor as usize][val as usize];
                }
            }
        }
    }
    let mut inv = vec![vec![0u8; k]; k];
    for i in 0..k {
        inv[i].copy_from_slice(&aug[i][k..]);
    }
    Ok(inv)
}

fn gf_mat_mul(a: &[Vec<u8>], b: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, CoreError> {
    let tbl = gf_tables();
    let r = a.len();
    let n = a[0].len();
    let n2 = b.len();
    let c = b[0].len();
    if n != n2 {
        return Err(CoreError::new(
            DECRYPT_CORRUPT_BEYOND_FEC,
            "Dimension mismatch",
        ));
    }
    let mut out = vec![vec![0u8; c]; r];
    for i in 0..r {
        for k in 0..n {
            let val_a = a[i][k];
            if val_a == 0 {
                continue;
            }
            for j in 0..c {
                out[i][j] ^= tbl.mul[val_a as usize][b[k][j] as usize];
            }
        }
    }
    Ok(out)
}

fn build_generator_matrix(k: u16, r: u16) -> Result<Vec<Vec<u8>>, CoreError> {
    let m = (k + r) as usize;
    if m > 255 {
        return Err(CoreError::new(
            DECRYPT_PARAMS_OUT_OF_LIMITS,
            "k+r must be <= 255",
        ));
    }
    let tbl = gf_tables();
    let k = k as usize;
    let mut v = vec![vec![0u8; k]; m];
    for i in 0..m {
        v[i][0] = 1;
    }
    for j in 1..k {
        for i in 0..m {
            let xs = (i + 1) as u8;
            let prev = v[i][j - 1];
            v[i][j] = tbl.mul[xs as usize][prev as usize];
        }
    }
    let t = gf_mat_inv(&v[..k])?;
    let g = gf_mat_mul(&v, &t)?;
    for i in 0..k {
        for j in 0..k {
            if (i == j && g[i][j] != 1) || (i != j && g[i][j] != 0) {
                return Err(CoreError::new(
                    DECRYPT_CORRUPT_BEYOND_FEC,
                    "Failed to build systematic generator matrix",
                ));
            }
        }
    }
    Ok(g)
}

fn fec_encode(
    data: &[Vec<u8>],
    g: &[Vec<u8>],
    k: usize,
    r: usize,
) -> Result<Vec<Vec<u8>>, CoreError> {
    let m = k + r;
    let mut out = vec![vec![0u8; data[0].len()]; m];
    for i in 0..k {
        out[i].copy_from_slice(&data[i]);
    }
    let g_parity = &g[k..];
    let parity = gf_mat_mul(g_parity, data)?;
    for i in 0..r {
        out[k + i].copy_from_slice(&parity[i]);
    }
    Ok(out)
}

fn fec_decode(
    shards: &[Option<Vec<u8>>],
    present: &[bool],
    g: &[Vec<u8>],
    k: usize,
    r: usize,
) -> Result<Vec<Vec<u8>>, CoreError> {
    let m = k + r;
    let mut avail_idx = Vec::new();
    for i in 0..m {
        if present[i] {
            avail_idx.push(i);
        }
    }
    if avail_idx.len() < k {
        return Err(CoreError::new(
            DECRYPT_CORRUPT_BEYOND_FEC,
            "Not enough shards to recover the block",
        ));
    }
    let use_idx = &avail_idx[..k];
    let mut a = Vec::with_capacity(k);
    for &idx in use_idx {
        a.push(g[idx].clone());
    }
    let a_inv = gf_mat_inv(&a)?;
    let mut avail_data = Vec::with_capacity(k);
    for &idx in use_idx {
        avail_data.push(shards[idx].as_ref().unwrap().clone());
    }
    gf_mat_mul(&a_inv, &avail_data)
}

fn write_crc_copies(w: &mut dyn Write, data: &[u8]) -> io::Result<()> {
    let crc = crc32_bytes(data);
    for _ in 0..CRC_COPIES {
        w.write_u32::<BigEndian>(crc)?;
    }
    Ok(())
}

fn atomic_replace(tmp: &Path, target: &Path) -> io::Result<()> {
    if !target.exists() {
        return fs::rename(tmp, target);
    }

    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let backup_marker = NamedTempFile::new_in(parent)?;
    let backup_path = backup_marker.path().to_path_buf();
    drop(backup_marker);
    let _ = fs::remove_file(&backup_path);

    fs::rename(target, &backup_path)?;
    match fs::rename(tmp, target) {
        Ok(()) => {
            let _ = fs::remove_file(&backup_path);
            Ok(())
        }
        Err(e) => {
            let _ = fs::rename(&backup_path, target);
            Err(e)
        }
    }
}

fn header_data_offset(hdr_len: u16, version: u8) -> u64 {
    let mut size = 4u64 + 2 + hdr_len as u64 + 4;
    if version >= 4 {
        size += HEADER_AUTH_TAG_LEN as u64;
    }
    size
}

fn verify_header_auth(
    version: u8,
    key: &[u8],
    prefix: &[u8],
    hdr_crc: u32,
    hdr_auth: Option<[u8; HEADER_AUTH_TAG_LEN]>,
) -> Result<(), CoreError> {
    if version < 4 {
        return Ok(());
    }
    let stored = hdr_auth.ok_or_else(|| {
        CoreError::new(
            DECRYPT_HEADER_INVALID,
            "Missing header authentication tag for v4 file.",
        )
    })?;
    let expected = header_auth_tag(key, prefix, hdr_crc)?;
    if stored != expected {
        return Err(CoreError::new(
            DECRYPT_HEADER_AUTH_FAILED,
            "Header authentication failed.",
        ));
    }
    Ok(())
}

pub fn get_keyfile_hash_rs(path: &str) -> Result<Vec<u8>, CoreError> {
    keyfile_hash(Path::new(path)).map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))
}

pub fn read_metadata_rs(path: &str) -> Result<MetaInfo, CoreError> {
    let (params, _hdr, _hdr_len, _hdr_crc, _hdr_auth) = open_header(path)?;
    Ok(meta_from_params(&params))
}

pub fn parse_header_blob_rs(blob: &[u8]) -> Result<MetaInfo, CoreError> {
    if blob.len() < 10 {
        return Err(CoreError::new(
            DECRYPT_HEADER_INVALID,
            "Blob too short for header.",
        ));
    }
    if &blob[..4] != MAGIC {
        return Err(CoreError::new(DECRYPT_HEADER_INVALID, "Invalid magic."));
    }
    let mut rdr = io::Cursor::new(&blob[4..]);
    let hdr_len = rdr
        .read_u16::<BigEndian>()
        .map_err(|_| CoreError::new(DECRYPT_HEADER_INVALID, "Invalid header length."))?;
    if hdr_len == 0 || hdr_len as usize > MAX_HEADER_LEN {
        return Err(CoreError::new(
            DECRYPT_HEADER_INVALID,
            "Header length out of bounds.",
        ));
    }
    let min = 4 + 2 + hdr_len as usize + 4;
    if blob.len() < min {
        return Err(CoreError::new(
            DECRYPT_HEADER_INVALID,
            "Truncated header blob.",
        ));
    }
    let hdr_start = 6;
    let hdr_end = hdr_start + hdr_len as usize;
    let hdr = &blob[hdr_start..hdr_end];
    let mut crc_rdr = io::Cursor::new(&blob[hdr_end..hdr_end + 4]);
    let hdr_crc = crc_rdr
        .read_u32::<BigEndian>()
        .map_err(|_| CoreError::new(DECRYPT_HEADER_INVALID, "Invalid header CRC field."))?;
    let mut prefix = Vec::with_capacity(6 + hdr.len());
    prefix.extend_from_slice(MAGIC);
    prefix.write_u16::<BigEndian>(hdr_len).unwrap();
    prefix.extend_from_slice(hdr);
    if crc32_bytes(&prefix) != hdr_crc {
        return Err(CoreError::new(
            DECRYPT_HEADER_INVALID,
            "Header CRC mismatch.",
        ));
    }
    let params = parse_header(hdr)?;
    Ok(meta_from_params(&params))
}

pub fn encrypt_file_rs_controlled(
    input_file: &str,
    output_file: &str,
    password: &str,
    keyfile_hash: Option<&[u8]>,
    compress_alg: Option<&str>,
    enable_pwchk: bool,
    k: Option<u16>,
    r: Option<u16>,
    shard_size: Option<u32>,
    argon2_t: Option<u32>,
    argon2_m: Option<u32>,
    argon2_p: Option<u16>,
    original_filename: Option<&str>,
    is_tar_container: bool,
    control: Option<&ControlFlags>,
    mut progress: Option<&mut dyn FnMut(&str, u64, u64)>,
) -> Result<(), CoreError> {
    let k = k.unwrap_or(K_DATA);
    let r = r.unwrap_or(R_PARITY);
    let shard_size = shard_size.unwrap_or(SHARD_SIZE);
    let argon2_t = argon2_t.unwrap_or(ARGON2_TIME);
    let argon2_m = argon2_m.unwrap_or(ARGON2_MEM_KIB);
    let argon2_p = argon2_p.unwrap_or(ARGON2_PAR);

    let mut flags = 0u8;
    if enable_pwchk {
        flags |= HDR_FLAG_PWCHK;
    }
    let mut comp_flag = 0u8;
    if let Some(alg) = compress_alg {
        if alg == "zlib" {
            comp_flag = HDR_FLAG_COMPRESS_ZLIB;
        } else if alg == "lzma" {
            comp_flag = HDR_FLAG_COMPRESS_LZMA;
        } else {
            return Err(CoreError::new(
                DECRYPT_UNKNOWN_ERROR,
                "Unsupported compression",
            ));
        }
    }
    flags |= comp_flag;
    if is_tar_container {
        flags |= HDR_FLAG_TAR_CONTAINER;
    }

    let filename_meta: Option<String> = match original_filename {
        None => {
            flags |= HDR_FLAG_HAS_FILENAME;
            Some(
                Path::new(input_file)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
            )
        }
        Some("") => None,
        Some(name) => {
            flags |= HDR_FLAG_HAS_FILENAME;
            Some(name.to_string())
        }
    };

    let plain_size = fs::metadata(input_file)
        .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?
        .len();

    let mut temp_compressed: Option<NamedTempFile> = None;
    let mut processing_path = PathBuf::from(input_file);

    if let Some(alg) = compress_alg {
        let out_dir = Path::new(output_file)
            .parent()
            .unwrap_or_else(|| Path::new("."));
        let tmp = NamedTempFile::new_in(out_dir)
            .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?;
        let mut f_in = BufReader::new(
            File::open(input_file).map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?,
        );
        let f_out = BufWriter::new(
            tmp.reopen()
                .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?,
        );

        if alg == "zlib" {
            let mut enc = ZlibEncoder::new(f_out, Compression::new(6));
            let mut buf = [0u8; 64 * 1024];
            loop {
                control_wait(control)?;
                let n = f_in
                    .read(&mut buf)
                    .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?;
                if n == 0 {
                    break;
                }
                enc.write_all(&buf[..n])
                    .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?;
            }
            enc.finish()
                .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?;
        } else if alg == "lzma" {
            let mut enc = xz2::write::XzEncoder::new(f_out, 6);
            let mut buf = [0u8; 64 * 1024];
            loop {
                control_wait(control)?;
                let n = f_in
                    .read(&mut buf)
                    .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?;
                if n == 0 {
                    break;
                }
                enc.write_all(&buf[..n])
                    .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?;
            }
            enc.finish()
                .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?;
        }
        processing_path = tmp.path().to_path_buf();
        temp_compressed = Some(tmp);
    }

    let stored_size = fs::metadata(&processing_path)
        .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?
        .len();

    let block_size = k as u64 * shard_size as u64;
    let num_blocks = if stored_size == 0 {
        1
    } else {
        stored_size.div_ceil(block_size)
    };

    validate_limits(
        k,
        r,
        shard_size,
        argon2_t,
        argon2_m,
        argon2_p,
        Some(num_blocks),
    )?;

    let (start_header, base_trailer, prefix, _hdr_len, hdr_crc, salt, nonce_base, flags) =
        write_header(
            plain_size,
            stored_size,
            k,
            r,
            shard_size,
            flags,
            argon2_t,
            argon2_m,
            argon2_p,
            filename_meta.as_deref(),
        )?;

    let key = Zeroizing::new(derive_key(
        password,
        &salt,
        argon2_t,
        argon2_m,
        argon2_p,
        keyfile_hash,
    )?);
    let hdr_auth = header_auth_tag(key.as_ref(), &prefix, hdr_crc)?;
    let mut start_header = start_header;
    start_header.extend_from_slice(&hdr_auth);
    let mut trailer = Vec::with_capacity(base_trailer.len() + HEADER_AUTH_TAG_LEN);
    let trailer_split = base_trailer.len() - 6;
    trailer.extend_from_slice(&base_trailer[..trailer_split]);
    trailer.extend_from_slice(&hdr_auth);
    trailer.extend_from_slice(&base_trailer[trailer_split..]);

    let out_dir = Path::new(output_file)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let tmp_out = NamedTempFile::new_in(out_dir)
        .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?;
    let tmp_path = tmp_out.path().to_path_buf();

    let mut f_in = BufReader::new(
        File::open(&processing_path)
            .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?,
    );
    let mut f_out = BufWriter::new(
        tmp_out
            .reopen()
            .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?,
    );

    f_out
        .write_all(&start_header)
        .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?;

    if flags & HDR_FLAG_PWCHK != 0 {
        let nonce = nonce12(nonce_base, 0xFFFFFFFF, 0xFFFFFFFF);
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|e| CoreError::new(DECRYPT_UNKNOWN_ERROR, e.to_string()))?;
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &PWCHK_PLAINTEXT,
                    aad: [prefix.as_slice(), PWCHK_MAGIC].concat().as_slice(),
                },
            )
            .map_err(|_| CoreError::new(DECRYPT_UNKNOWN_ERROR, "Password check encrypt failed"))?;
        let (ct_body, tag) = ct.split_at(PWCHK_PLAINTEXT_LEN);
        f_out
            .write_all(PWCHK_MAGIC)
            .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?;
        write_crc_copies(&mut f_out, &[ct_body, tag].concat())
            .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?;
        f_out
            .write_all(ct_body)
            .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?;
        f_out
            .write_all(tag)
            .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?;
    }

    let g = build_generator_matrix(k, r)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|e| CoreError::new(DECRYPT_UNKNOWN_ERROR, e.to_string()))?;

    let block_size_usize = block_size as usize;
    let shard_size_usize = shard_size as usize;
    let m = (k + r) as usize;
    let mut block_buf = vec![0u8; block_size_usize];

    for block_index in 0..num_blocks {
        control_wait(control)?;
        progress_report(&mut progress, "encrypt", block_index, num_blocks);
        let mut read_total = 0usize;
        while read_total < block_size_usize {
            let n = f_in
                .read(&mut block_buf[read_total..])
                .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?;
            if n == 0 {
                break;
            }
            read_total += n;
        }
        if read_total < block_size_usize {
            for b in &mut block_buf[read_total..] {
                *b = 0;
            }
        }

        let mut data_shards = Vec::with_capacity(k as usize);
        for i in 0..k as usize {
            let start = i * shard_size_usize;
            let end = start + shard_size_usize;
            data_shards.push(block_buf[start..end].to_vec());
        }
        let coded = fec_encode(&data_shards, &g, k as usize, r as usize)?;

        for shard_index in 0..m {
            let shard_plain = &coded[shard_index];
            let nonce = nonce12(nonce_base, block_index as u32, shard_index as u32);
            let aad = [
                prefix.as_slice(),
                &(block_index as u32).to_be_bytes(),
                &(shard_index as u32).to_be_bytes(),
            ]
            .concat();
            let ct = cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: shard_plain,
                        aad: &aad,
                    },
                )
                .map_err(|_| CoreError::new(DECRYPT_UNKNOWN_ERROR, "Encrypt failed"))?;
            let (ct_body, tag) = ct.split_at(shard_size_usize);
            write_crc_copies(&mut f_out, &[ct_body, tag].concat())
                .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?;
            f_out
                .write_all(ct_body)
                .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?;
            f_out
                .write_all(tag)
                .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?;
        }
    }

    progress_report(&mut progress, "encrypt", num_blocks, num_blocks);

    f_out
        .write_all(&trailer)
        .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?;
    f_out
        .flush()
        .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?;

    atomic_replace(&tmp_path, Path::new(output_file))
        .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?;
    drop(temp_compressed);
    Ok(())
}

pub fn encrypt_file_rs(
    input_file: &str,
    output_file: &str,
    password: &str,
    keyfile_hash: Option<&[u8]>,
    compress_alg: Option<&str>,
    enable_pwchk: bool,
    k: Option<u16>,
    r: Option<u16>,
    shard_size: Option<u32>,
    argon2_t: Option<u32>,
    argon2_m: Option<u32>,
    argon2_p: Option<u16>,
    original_filename: Option<&str>,
    is_tar_container: bool,
) -> Result<(), CoreError> {
    encrypt_file_rs_controlled(
        input_file,
        output_file,
        password,
        keyfile_hash,
        compress_alg,
        enable_pwchk,
        k,
        r,
        shard_size,
        argon2_t,
        argon2_m,
        argon2_p,
        original_filename,
        is_tar_container,
        None,
        None,
    )
}

pub fn decrypt_file_ex_rs_controlled(
    input_file: &str,
    output_file: &str,
    password: &str,
    keyfile_hash: Option<&[u8]>,
    control: Option<&ControlFlags>,
    progress: Option<&mut dyn FnMut(&str, u64, u64)>,
) -> Result<MetaInfo, CoreError> {
    let params = decrypt_internal_rs_controlled(
        input_file,
        output_file,
        password,
        keyfile_hash,
        control,
        progress,
    )?;
    Ok(meta_from_params(&params))
}

pub fn decrypt_file_ex_rs(
    input_file: &str,
    output_file: &str,
    password: &str,
    keyfile_hash: Option<&[u8]>,
) -> Result<MetaInfo, CoreError> {
    decrypt_file_ex_rs_controlled(input_file, output_file, password, keyfile_hash, None, None)
}

pub fn verify_file_integrity_rs(
    input_file: &str,
    password: &str,
    keyfile_hash: Option<&[u8]>,
) -> Result<MetaInfo, CoreError> {
    let params = verify_internal_rs_controlled(input_file, password, keyfile_hash, None, None)?;
    Ok(meta_from_params(&params))
}

pub fn verify_file_integrity_rs_controlled(
    input_file: &str,
    password: &str,
    keyfile_hash: Option<&[u8]>,
    control: Option<&ControlFlags>,
    progress: Option<&mut dyn FnMut(&str, u64, u64)>,
) -> Result<MetaInfo, CoreError> {
    let params =
        verify_internal_rs_controlled(input_file, password, keyfile_hash, control, progress)?;
    Ok(meta_from_params(&params))
}

fn open_header(
    path: &str,
) -> Result<
    (
        HeaderParams,
        Vec<u8>,
        u16,
        u32,
        Option<[u8; HEADER_AUTH_TAG_LEN]>,
    ),
    CoreError,
> {
    let f = File::open(path).map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?;
    let mut header = read_header_from_start(&f)
        .map_err(|e| CoreError::new(DECRYPT_HEADER_INVALID, e.to_string()))?;
    if header.is_none() {
        header = read_header_from_end(&f)
            .map_err(|e| CoreError::new(DECRYPT_HEADER_INVALID, e.to_string()))?;
    }
    let header =
        header.ok_or_else(|| CoreError::new(DECRYPT_HEADER_INVALID, "Header not found."))?;
    let hdr = header.hdr;
    let hdr_len = header.hdr_len;
    let hdr_crc = header.hdr_crc;
    let hdr_auth = header.hdr_auth;
    let params = parse_header(&hdr)?;
    Ok((params, hdr, hdr_len, hdr_crc, hdr_auth))
}
/// Result of header parsing, limit validation, key derivation, header
/// authentication and (optional) password-check verification — everything
/// decrypt and verify share before touching the data blocks.
struct PreparedInput {
    params: HeaderParams,
    prefix: Vec<u8>,
    cipher: Aes256Gcm,
    num_blocks: u64,
    data_offset: u64,
}

fn open_and_authenticate(
    input_file: &str,
    password: &str,
    keyfile_hash: Option<&[u8]>,
    control: Option<&ControlFlags>,
) -> Result<PreparedInput, CoreError> {
    let (params, hdr, hdr_len, hdr_crc, hdr_auth) = open_header(input_file)?;
    if params.version > VERSION_U8 {
        return Err(CoreError::new(
            DECRYPT_HEADER_INVALID,
            format!(
                "Unsupported version {} (max {})",
                params.version, VERSION_U8
            ),
        ));
    }
    if params.version < 1 {
        return Err(CoreError::new(
            DECRYPT_HEADER_INVALID,
            format!("Invalid version {}", params.version),
        ));
    }
    let block_size = params.k as u64 * params.shard_size as u64;
    let num_blocks = if params.stored_size == 0 {
        1
    } else {
        params.stored_size.div_ceil(block_size)
    };
    // Limits must be validated BEFORE the Argon2 derivation so a malicious
    // header cannot request unbounded KDF cost.
    validate_limits(
        params.k,
        params.r,
        params.shard_size,
        params.argon2_time,
        params.argon2_mem_kib,
        params.argon2_par,
        Some(num_blocks),
    )?;

    let mut prefix = Vec::with_capacity(6 + hdr.len());
    prefix.extend_from_slice(MAGIC);
    prefix.write_u16::<BigEndian>(hdr_len).unwrap();
    prefix.extend_from_slice(&hdr);

    let pwchk_present = params.flags & HDR_FLAG_PWCHK != 0;
    let mut data_offset = header_data_offset(hdr_len, params.version);

    let key = Zeroizing::new(derive_key(
        password,
        &params.salt,
        params.argon2_time,
        params.argon2_mem_kib,
        params.argon2_par,
        keyfile_hash,
    )?);
    verify_header_auth(params.version, key.as_ref(), &prefix, hdr_crc, hdr_auth)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|e| CoreError::new(DECRYPT_UNKNOWN_ERROR, e.to_string()))?;

    if pwchk_present {
        control_wait(control)?;
        let mut f_in = BufReader::new(
            File::open(input_file).map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?,
        );
        f_in.seek(io::SeekFrom::Start(data_offset))
            .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?;
        let mut blob = vec![0u8; PWCHK_RECORD_SIZE];
        f_in.read_exact(&mut blob).map_err(|_| {
            CoreError::new(DECRYPT_TRUNCATED, "File truncated at password check record")
        })?;
        let off = 4 + (4 * CRC_COPIES);
        let ct = &blob[off..off + PWCHK_PLAINTEXT_LEN];
        let tag = &blob[off + PWCHK_PLAINTEXT_LEN..off + PWCHK_PLAINTEXT_LEN + TAG_LEN];
        let nonce = nonce12(params.nonce_base, 0xFFFFFFFF, 0xFFFFFFFF);
        let aad = [prefix.as_slice(), PWCHK_MAGIC].concat();
        let mut data = Vec::with_capacity(PWCHK_PLAINTEXT_LEN + TAG_LEN);
        data.extend_from_slice(ct);
        data.extend_from_slice(tag);
        if cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &data,
                    aad: &aad,
                },
            )
            .is_err()
        {
            return Err(CoreError::new(
                DECRYPT_PASSWORD_INVALID,
                "Wrong password or corrupted keyfile.",
            ));
        }
        data_offset += PWCHK_RECORD_SIZE as u64;
    }

    Ok(PreparedInput {
        params,
        prefix,
        cipher,
        num_blocks,
        data_offset,
    })
}

/// Read, authenticate and (if needed) FEC-recover every block.
/// With `sink = Some(writer)` the recovered plaintext is written out
/// (decrypt); with `sink = None` blocks are only validated (verify).
fn process_blocks(
    input_file: &str,
    prepared: &PreparedInput,
    mut sink: Option<&mut dyn Write>,
    control: Option<&ControlFlags>,
    mut progress: Option<&mut dyn FnMut(&str, u64, u64)>,
    stage: &str,
) -> Result<(), CoreError> {
    let params = &prepared.params;
    let num_blocks = prepared.num_blocks;
    let block_size = params.k as u64 * params.shard_size as u64;
    let g = build_generator_matrix(params.k, params.r)?;

    let mut f_in = BufReader::new(
        File::open(input_file).map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?,
    );
    f_in.seek(io::SeekFrom::Start(prepared.data_offset))
        .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?;

    let k = params.k as usize;
    let r = params.r as usize;
    let m = k + r;
    let shard_size = params.shard_size as usize;

    for block_index in 0..num_blocks {
        control_wait(control)?;
        progress_report(&mut progress, stage, block_index, num_blocks);
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; m];
        let mut present = vec![false; m];

        for shard_index in 0..m {
            let mut crc_fields = [0u8; CRC_BLOCK_SIZE];
            f_in.read_exact(&mut crc_fields).map_err(|_| {
                CoreError::new(
                    DECRYPT_TRUNCATED,
                    format!(
                        "Unexpected EOF reading shard {shard_index} CRC in block {block_index}"
                    ),
                )
            })?;
            let mut crcs = Vec::new();
            let mut cur = io::Cursor::new(&crc_fields);
            for _ in 0..CRC_COPIES {
                crcs.push(cur.read_u32::<BigEndian>().unwrap());
            }
            let mut ct = vec![0u8; shard_size];
            f_in.read_exact(&mut ct).map_err(|_| {
                CoreError::new(
                    DECRYPT_TRUNCATED,
                    format!(
                        "File truncated at shard data (block {block_index}, shard {shard_index})"
                    ),
                )
            })?;
            let mut tag = vec![0u8; params.tag_len as usize];
            f_in.read_exact(&mut tag)
                .map_err(|_| CoreError::new(DECRYPT_TRUNCATED, format!("File truncated at authentication tag (block {block_index}, shard {shard_index})")))?;
            let crc_calc = crc32_bytes(&[ct.as_slice(), tag.as_slice()].concat());
            if !crcs.contains(&crc_calc) {
                continue;
            }
            let nonce = nonce12(params.nonce_base, block_index as u32, shard_index as u32);
            let aad = [
                prepared.prefix.as_slice(),
                &(block_index as u32).to_be_bytes(),
                &(shard_index as u32).to_be_bytes(),
            ]
            .concat();
            let mut data = Vec::with_capacity(shard_size + tag.len());
            data.extend_from_slice(&ct);
            data.extend_from_slice(&tag);
            if let Ok(pt) = prepared.cipher.decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &data,
                    aad: &aad,
                },
            ) {
                shards[shard_index] = Some(pt);
                present[shard_index] = true;
            }
        }

        let have_all_data = present.iter().take(k).all(|&v| v);
        if !have_all_data && present.iter().filter(|v| **v).count() < k {
            return Err(CoreError::new(
                DECRYPT_CORRUPT_BEYOND_FEC,
                format!("Block {block_index} failed recovery (too many corrupted shards)."),
            ));
        }

        if let Some(w) = sink.as_mut() {
            let data_block = if have_all_data {
                let mut out = Vec::with_capacity(k);
                for shard in shards.iter_mut().take(k) {
                    out.push(shard.take().unwrap());
                }
                out
            } else {
                fec_decode(&shards, &present, &g, k, r)?
            };

            let mut byte_data = Vec::with_capacity(k * shard_size);
            for shard in data_block {
                byte_data.extend_from_slice(&shard);
            }

            let valid_bytes = if block_index == num_blocks - 1 {
                (params.stored_size - (block_index * block_size)) as usize
            } else {
                byte_data.len()
            };
            w.write_all(&byte_data[..valid_bytes])
                .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?;
        } else if !have_all_data {
            let _ = fec_decode(&shards, &present, &g, k, r)?;
        }
    }

    progress_report(&mut progress, stage, num_blocks, num_blocks);
    Ok(())
}

fn decrypt_internal_rs_controlled(
    input_file: &str,
    output_file: &str,
    password: &str,
    keyfile_hash: Option<&[u8]>,
    control: Option<&ControlFlags>,
    progress: Option<&mut dyn FnMut(&str, u64, u64)>,
) -> Result<HeaderParams, CoreError> {
    let prepared = open_and_authenticate(input_file, password, keyfile_hash, control)?;
    let params = &prepared.params;

    let out_dir = Path::new(output_file)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let tmp_out = NamedTempFile::new_in(out_dir)
        .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?;
    let tmp_path = tmp_out.path().to_path_buf();
    let f_out = BufWriter::new(
        tmp_out
            .reopen()
            .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?,
    );

    let mut writer: Box<dyn Write> = if params.flags & HDR_FLAG_COMPRESS_ZLIB != 0 {
        Box::new(ZlibDecoder::new(LimitedWriter::new(
            f_out,
            Some(params.plain_size),
        )))
    } else if params.flags & HDR_FLAG_COMPRESS_LZMA != 0 {
        Box::new(XzDecoder::new(LimitedWriter::new(
            f_out,
            Some(params.plain_size),
        )))
    } else {
        Box::new(LimitedWriter::new(f_out, Some(params.plain_size)))
    };

    process_blocks(
        input_file,
        &prepared,
        Some(writer.as_mut()),
        control,
        progress,
        "decrypt",
    )?;

    writer
        .flush()
        .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?;

    atomic_replace(&tmp_path, Path::new(output_file))
        .map_err(|e| CoreError::new(DECRYPT_IO_ERROR, e.to_string()))?;
    Ok(prepared.params)
}

fn verify_internal_rs_controlled(
    input_file: &str,
    password: &str,
    keyfile_hash: Option<&[u8]>,
    control: Option<&ControlFlags>,
    progress: Option<&mut dyn FnMut(&str, u64, u64)>,
) -> Result<HeaderParams, CoreError> {
    let prepared = open_and_authenticate(input_file, password, keyfile_hash, control)?;
    process_blocks(input_file, &prepared, None, control, progress, "verify")?;
    Ok(prepared.params)
}

struct LimitedWriter<W: Write> {
    inner: W,
    limit: Option<u64>,
    written: u64,
}

impl<W: Write> LimitedWriter<W> {
    fn new(inner: W, limit: Option<u64>) -> Self {
        Self {
            inner,
            limit,
            written: 0,
        }
    }
}

impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(limit) = self.limit {
            if self.written + buf.len() as u64 > limit {
                return Err(io::Error::other("Output size limit exceeded"));
            }
        }
        let n = self.inner.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
