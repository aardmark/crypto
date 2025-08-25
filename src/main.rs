use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use clap::{Parser, Subcommand};
use rand::RngCore;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};

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

#[derive(Parser)]
#[command(author, version, about = "ChaCha20 file encrypt/decrypt with Argon2id KDF, with encrypted filename support", long_about = None)]
struct Cli {
    /// Subcommand: encrypt or decrypt
    #[command(subcommand)]
    command: Commands,

    /// Provide a passphrase (Argon2id derives a 32-byte key; salt stored in header)
    #[arg(short, long)]
    passphrase: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt input -> output file contains header + encrypted(filename + data)
    Encrypt {
        /// Input file path to encrypt
        input: String,
        /// Output file to write
        output: String,
    },

    /// Decrypt input -> output file or directory
    Decrypt {
        /// Input file (must be produced by this tool)
        input: String,
    },
}

// ---- Key derivation (Argon2id) ----
fn derive_key_argon2id(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    use argon2::{Algorithm, Argon2, Params, Version};
    // ~19 MiB memory, 2 iterations, 1 lane; output 32 bytes
    let params = Params::new(19 * 1024, 2, 1, Some(32)).expect("argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .expect("argon2 hashing failed");
    key
}

// ---- Utilities ----
// fn file_name_for_storage(input_path: &Path, strip_path: bool) -> String {
//     let name = if strip_path {
//         input_path.file_name().unwrap_or_default()
//     } else {
//         input_path.as_os_str()
//     };
//     // NOTE: This uses lossy UTF-8 for cross-platform simplicity.
//     // If you need perfect round-tripping of non-UTF-8 names, use a raw-bytes scheme (extra tooling).
//     name.to_string_lossy().to_string()
// }

fn write_header<W: Write>(
    mut out: W,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> std::io::Result<()> {
    out.write_all(MAGIC)?;
    out.write_all(&[VERSION])?;
    out.write_all(&[SALT_LEN as u8])?;
    out.write_all(salt)?;
    out.write_all(nonce)?;
    Ok(())
}

fn read_header<R: Read>(mut inp: R) -> std::io::Result<(Vec<u8>, [u8; NONCE_LEN])> {
    let mut magic = [0u8; 4];
    inp.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad magic",
        ));
    }
    let mut ver = [0u8; 1];
    inp.read_exact(&mut ver)?;
    if ver[0] != VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported version",
        ));
    }
    let mut salt_len_b = [0u8; 1];
    inp.read_exact(&mut salt_len_b)?;
    let salt_len = salt_len_b[0] as usize;
    let mut salt = vec![0u8; salt_len];
    inp.read_exact(&mut salt)?;
    let mut nonce = [0u8; NONCE_LEN];
    inp.read_exact(&mut nonce)?;
    Ok((salt, nonce))
}

// ---- Core: Encrypt (streaming) ----
fn process_encrypt(
    key: &[u8; 32],
    input: &str,
    output: &str,
    salt: [u8; SALT_LEN],
) -> std::io::Result<()> {
    let mut in_file = BufReader::new(File::open(&input)?);
    let mut out_file = BufWriter::new(File::create(&output)?);

    // Nonce
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);

    // Header (plaintext)
    write_header(&mut out_file, &salt, &nonce)?;

    // Init cipher
    let mut cipher = ChaCha20::new(key.into(), (&nonce).into());

    // Encrypt the prefixed filename metadata first
    let stored_name = input;
    let name_bytes = stored_name.as_bytes();
    let name_len = name_bytes.len() as u32;

    // Build small prefix buffer: [len (u32 LE)] [name bytes]
    let mut prefix = Vec::with_capacity(4 + name_bytes.len());
    prefix.extend_from_slice(&name_len.to_le_bytes());
    prefix.extend_from_slice(name_bytes);

    // Apply keystream to prefix at offset 0 and write
    let mut offset: u64 = 0;
    cipher.seek(offset);
    cipher.apply_keystream(&mut prefix);
    out_file.write_all(&prefix)?;
    offset += prefix.len() as u64;

    // Now stream the rest of the file
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = in_file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        let mut chunk = buffer[..n].to_vec();
        cipher.seek(offset);
        cipher.apply_keystream(&mut chunk);
        out_file.write_all(&chunk)?;
        offset += n as u64;
    }

    out_file.flush()?;
    Ok(())
}

// ---- Core: Decrypt (streaming) ----
fn process_decrypt(passphrase: &str, input: &str) -> std::io::Result<()> {
    // Open and read header to get salt + nonce
    let mut in_file = BufReader::new(File::open(input)?);
    let (salt, nonce) = read_header(&mut in_file)?;

    if salt.len() != SALT_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected salt length",
        ));
    }
    let key: [u8; 32] = derive_key_argon2id(passphrase, &salt);

    // Init cipher
    let mut cipher = ChaCha20::new((&key).into(), (&nonce).into());

    // Decrypt the name length (4 bytes) and filename bytes
    let mut offset: u64 = 0;

    let mut len_enc = [0u8; 4];
    in_file.read_exact(&mut len_enc)?;
    cipher.seek(offset);
    cipher.apply_keystream(&mut len_enc);
    offset += 4;
    let name_len = u32::from_le_bytes(len_enc) as usize;

    let mut name_enc = vec![0u8; name_len];
    in_file.read_exact(&mut name_enc)?;
    cipher.seek(offset);
    cipher.apply_keystream(&mut name_enc);
    offset += name_len as u64;
    let stored_name = String::from_utf8_lossy(&name_enc).to_string();

    let mut out_file = BufWriter::new(File::create(&stored_name)?);

    // Stream-decrypt the remainder (file data)
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = in_file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        let mut chunk = buffer[..n].to_vec();
        cipher.seek(offset);
        cipher.apply_keystream(&mut chunk);
        out_file.write_all(&chunk)?;
        offset += n as u64;
    }

    out_file.flush()?;
    println!("Decrypted -> {})", stored_name);
    Ok(())
}

// Very basic filename sanitizer to avoid writing traversal paths
// fn sanitize_filename(name: &str) -> String {
//     let candidate = Path::new(name);
//     let base = candidate.file_name().unwrap_or_default().to_string_lossy();
//     let mut s = base.to_string();
//     // Strip a few problematic characters
//     for ch in ['\0', '/', '\\', ':', '*', '?', '"', '<', '>', '|'] {
//         s = s.replace(ch, "_");
//     }
//     if s.is_empty() {
//         "output.bin".to_string()
//     } else {
//         s
//     }
// }

// ---- Entrypoint ----
fn main() -> std::io::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { input, output } => {
            // Key source for encryption
            let mut salt = [0u8; SALT_LEN];
            rand::thread_rng().fill_bytes(&mut salt);
            let key: [u8; 32] = derive_key_argon2id(&cli.passphrase, &salt);

            // let input_path = Path::new(&input);
            process_encrypt(&key, &input, &output, salt)?;
            println!("Encrypted -> {}", output);
        }

        Commands::Decrypt { input } => {
            process_decrypt(&cli.passphrase, &input)?;
        }
    }

    Ok(())
}
