use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use cipher::StreamCipherCoreWrapper;
use rand::RngCore;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::result;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

type StreamCipherWrapper = StreamCipherCoreWrapper<
    chacha20::ChaChaCore<
        cipher::typenum::UInt<
            cipher::typenum::UInt<
                cipher::typenum::UInt<
                    cipher::typenum::UInt<cipher::typenum::UTerm, cipher::consts::B1>,
                    cipher::consts::B0,
                >,
                cipher::consts::B1,
            >,
            cipher::consts::B0,
        >,
    >,
>;

/// A specialized [`Result`] type for crypto operations.
///
/// This type is broadly used across [`crate::crypto`] for any operation which may
/// produce an error.
///
/// This type alias is generally used to avoid writing out [`crypto::Error`] directly and
/// is otherwise a direct mapping to [`Result`].
pub type Result<T> = result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO Error")]
    Io(#[from] std::io::Error),
    #[error("System Time Error")]
    Time(#[from] std::time::SystemTimeError),
    #[error("{0}")]
    Crypto(String),
}

// -------- File format (header is plaintext, payload is encrypted) --------
// [ MAGIC(4) = b"C20F" ]
// [ VER(1) = 1 ]
// [ SALT_LEN(1) = 16 ]
// [ SALT(16) ]
// [ NONCE(12) ]
// [ ENCRYPTED( NAME_LEN(4 LE) || NAME_UTF8 || FILE_DATA... ) ]
const MAGIC: &[u8; 4] = b"C20F";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const BUFFER_SIZE: usize = 4096;

// ---- Key derivation (Argon2id) ----
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    use argon2::{Algorithm, Argon2, Params, Version};
    // ~19 MiB memory, 2 iterations, 1 lane; output 32 bytes
    let params = Params::new(19 * 1024, 2, 1, Some(32)).expect("argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    match argon2.hash_password_into(passphrase.as_bytes(), salt, &mut key) {
        Ok(_) => Ok(key),
        Err(_) => Err(Error::Crypto(String::from("Unable to generate key"))),
    }
}

fn write_header<W: Write>(
    mut writer: W,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<()> {
    writer.write_all(MAGIC)?;
    writer.write_all(&[VERSION])?;
    writer.write_all(&[SALT_LEN as u8])?;
    writer.write_all(salt)?;
    writer.write_all(nonce)?;
    Ok(())
}

fn read_header<R: Read>(mut reader: R) -> Result<(Vec<u8>, [u8; NONCE_LEN])> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(Error::Crypto(String::from("Not an encrypted file.")));
    }
    let mut ver = [0u8; 1];
    reader.read_exact(&mut ver)?;
    if ver[0] != VERSION {
        return Err(Error::Crypto(String::from("Invalid version.")));
    }
    let mut salt_len_b = [0u8; 1];
    reader.read_exact(&mut salt_len_b)?;
    let salt_len = salt_len_b[0] as usize;
    let mut salt = vec![0u8; salt_len];
    reader.read_exact(&mut salt)?;
    if salt.len() != SALT_LEN {
        return Err(Error::Crypto(String::from("Invalid salt.")));
    }
    let mut nonce = [0u8; NONCE_LEN];
    reader.read_exact(&mut nonce)?;
    Ok((salt, nonce))
}

fn apply_cipher<R: Read, W: Write>(
    reader: &mut BufReader<R>,
    writer: &mut BufWriter<W>,
    cipher: &mut StreamCipherWrapper,
    offset: u64,
) -> Result<u64> {
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut offset = offset;
    cipher.seek(offset);
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        let mut chunk = buffer[..n].to_vec();
        cipher.seek(offset);
        cipher.apply_keystream(&mut chunk);
        writer.write_all(&chunk)?;
        offset += n as u64;
    }

    Ok(offset)
}

fn split_file_path(file_path: &PathBuf) -> Result<(PathBuf, &OsStr)> {
    let Some(path) = file_path.parent() else {
        return Err(Error::Crypto(String::from("Cannot parse input path")));
    };
    let Some(file_name) = file_path.file_name() else {
        return Err(Error::Crypto(String::from(
            "Cannot parse input path file name",
        )));
    };
    let path = PathBuf::from(path);
    Ok((path, file_name))
}

fn get_unique_file_name(path: &PathBuf) -> Result<String> {
    // TODO: ensure path is a path (or empty?)
    loop {
        let mut file_path = path.clone();
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
        let random: u32 = rand::random();
        let file_name = format!("{}-{}.enc", ts, random);
        file_path.push(&file_name);

        if !file_path.exists() {
            return Ok(file_name);
        }
    }
}

// ---- Core: Encrypt (streaming) ----
pub fn encrypt_file(passphrase: &str, file_path: &PathBuf, delete: bool) -> Result<PathBuf> {
    // make sure it's a file, and it exists
    ensure_file(file_path)?;

    // create the salf for generating the key (passphrase + salt)
    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);
    let key: [u8; 32] = derive_key(passphrase, &salt)?;

    // create nonce for encryption
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);

    let (path, file_name) = split_file_path(&file_path)?;
    let unique_file_name = get_unique_file_name(&path)?;
    let mut unique_file_path = path.clone();
    unique_file_path.push(&unique_file_name);
    let mut reader = BufReader::new(File::open(&file_path)?);
    let mut writer = BufWriter::new(File::create(&unique_file_path)?);

    // write the head - not encrypted
    write_header(&mut writer, &salt, &nonce)?;

    let mut cipher = ChaCha20::new((&key).into(), (&nonce).into());

    // original file name + size - used to restore original file
    let file_name_bytes = file_name.as_encoded_bytes();
    let file_name_len = file_name_bytes.len() as u32;

    let mut prefix = Vec::with_capacity(4 + file_name_bytes.len());
    prefix.extend_from_slice(&file_name_len.to_le_bytes());
    prefix.extend_from_slice(file_name_bytes);

    // write prefix - encrypted
    let mut offset: u64 = 0;
    cipher.seek(offset);
    cipher.apply_keystream(&mut prefix);
    writer.write_all(&prefix)?;
    offset += prefix.len() as u64;

    // write file contents - encrypted
    apply_cipher(&mut reader, &mut writer, &mut cipher, offset)?;

    writer.flush()?;
    if delete {
        drop(reader);
        fs::remove_file(file_path)?;
    }

    Ok(unique_file_path)
}

// ---- Core: Decrypt (streaming) ----
pub fn decrypt_file(
    passphrase: &str,
    file_path: &PathBuf,
    delete: bool,
    overwrite: bool,
) -> Result<PathBuf> {
    let mut reader = BufReader::new(File::open(file_path)?);
    let (salt, nonce) = read_header(&mut reader)?;

    let key: [u8; 32] = derive_key(passphrase, &salt)?;
    let mut cipher = ChaCha20::new((&key).into(), (&nonce).into());
    let mut offset: u64 = 0;

    let mut buffer = [0u8; 4];
    reader.read_exact(&mut buffer)?;
    cipher.seek(offset);
    cipher.apply_keystream(&mut buffer);
    offset += 4;
    let original_filename_length = u32::from_le_bytes(buffer) as usize;

    let mut buffer = vec![0u8; original_filename_length];
    reader.read_exact(&mut buffer)?;
    cipher.seek(offset);
    cipher.apply_keystream(&mut buffer);
    offset += original_filename_length as u64;
    let original_file_name = String::from_utf8_lossy(&buffer).to_string();

    let (mut path, _) = split_file_path(&file_path)?;

    let mut writer = get_writer(&path, &original_file_name, overwrite)?;

    apply_cipher(&mut reader, &mut writer, &mut cipher, offset)?;

    writer.flush()?;
    if delete {
        drop(reader);
        fs::remove_file(file_path)?;
    }

    path.push(original_file_name);
    Ok(path)
}

fn get_writer(path: &PathBuf, file_name: &str, overwrite: bool) -> Result<BufWriter<File>> {
    let mut out_file_path = path.clone();
    out_file_path.push(file_name);
    let file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create_new(!overwrite)
        .open(out_file_path)?;
    Ok(BufWriter::new(file))
}

fn ensure_file(path: &PathBuf) -> Result<()> {
    match path.is_file() {
        true => Ok(()),
        false => Err(Error::Crypto(String::from("Not a file"))),
    }
}
