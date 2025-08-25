use clap::{Parser, Subcommand};
use crypto;
use crypto::Result;

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
    },

    /// Decrypt input -> output file or directory
    Decrypt {
        /// Input file (must be produced by this tool)
        input: String,
    },
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
fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { input } => {
            let encrypted_file = crypto::encrypt(&cli.passphrase, &input)?;
            println!("Encrypted {} -> {}", input, encrypted_file);
        }

        Commands::Decrypt { input } => {
            let decrypted_file = crypto::decrypt(&cli.passphrase, &input)?;
            println!("Decrypted {} -> {}", input, decrypted_file);
        }
    }

    Ok(())
}
