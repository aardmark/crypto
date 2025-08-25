use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use cipher::StreamCipherCoreWrapper;
use rand::Rng;
use rand::RngCore;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::result;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

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
    #[error("data store disconnected")]
    Io(#[from] std::io::Error),
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
    cipher: &mut StreamCipherCoreWrapper<
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
    >,
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

// ---- Core: Encrypt (streaming) ----
pub fn encrypt(passphrase: &str, input: &str) -> Result<String> {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let key: [u8; 32] = derive_key(passphrase, &salt)?;
    let output = unique_filename();
    let mut reader = BufReader::new(File::open(&input)?);
    let mut writer = BufWriter::new(File::create(&output)?);

    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);

    write_header(&mut writer, &salt, &nonce)?;

    let mut cipher = ChaCha20::new((&key).into(), (&nonce).into());

    let stored_name = input;
    let name_bytes = stored_name.as_bytes();
    let name_len = name_bytes.len() as u32;

    let mut prefix = Vec::with_capacity(4 + name_bytes.len());
    prefix.extend_from_slice(&name_len.to_le_bytes());
    prefix.extend_from_slice(name_bytes);

    let mut offset: u64 = 0;
    cipher.seek(offset);
    cipher.apply_keystream(&mut prefix);
    writer.write_all(&prefix)?;
    offset += prefix.len() as u64;

    apply_cipher(&mut reader, &mut writer, &mut cipher, offset)?;

    writer.flush()?;
    Ok(output)
}

// ---- Core: Decrypt (streaming) ----
pub fn decrypt(passphrase: &str, input: &str) -> Result<String> {
    let mut reader = BufReader::new(File::open(input)?);
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

    let mut writer = BufWriter::new(File::create(&original_file_name)?);

    apply_cipher(&mut reader, &mut writer, &mut cipher, offset)?;

    writer.flush()?;
    Ok(original_file_name)
}

fn unique_filename() -> String {
    loop {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let random: u32 = rand::thread_rng().r#gen();
        let candidate = format!("{}-{}", ts, random);

        let path = PathBuf::from(".").join(&candidate);

        if !path.exists() {
            return candidate;
        }
    }
}
