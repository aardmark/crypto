use clap::{Parser, Subcommand};
use crypto::{Error, Result};
use std::path::Path;

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

// ---- Entrypoint ----
fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { input } => {
            let path = Path::new(&input);
            if !path.exists() {
                return Err(Error::Crypto(String::from("File not found")));
            }
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
