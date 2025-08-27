use clap::{Parser, Subcommand};
use crypto::Result;
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about = "File encryption/decryption utitlity", long_about = None)]
struct Cli {
    /// Subcommand: encrypt or decrypt
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt the input file
    Encrypt {
        /// The passphrase to encrypt the file with
        #[arg(short, long)]
        passphrase: String,

        /// Delete the input file after encryption
        #[arg(short, long)]
        delete: bool,

        /// Input file path to encrypt
        file_name: PathBuf,
    },

    /// Decrypt the input file
    Decrypt {
        /// The passphrase that was used to encrypt the file
        #[arg(short, long)]
        passphrase: String,

        /// Delete the input file after decryption
        #[arg(short, long)]
        delete: bool,

        /// Overwrite existing files
        #[arg(short, long)]
        overwrite: bool,

        /// Input file (must be produced by this tool)
        file_name: PathBuf,
    },
}

// ---- Entrypoint ----
fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt {
            passphrase,
            delete,
            file_name,
        } => {
            let encrypted_file = crypto::encrypt_file(&passphrase, &file_name, delete)?;
            println!("Encrypted {:?} -> {}", file_name, encrypted_file);
        }

        Commands::Decrypt {
            passphrase,
            delete,
            file_name,
            overwrite,
        } => {
            let decrypted_file = crypto::decrypt_file(&passphrase, &file_name, delete, overwrite)?;
            println!("Decrypted {:?} -> {}", file_name, decrypted_file);
        }
    }

    Ok(())
}
