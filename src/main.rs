use clap::{Parser, Subcommand};
use crypto::Result;

#[derive(Parser)]
#[command(author, version, about = "ChaCha20 file encrypt/decrypt with Argon2id KDF, with encrypted filename support", long_about = None)]
struct Cli {
    /// Subcommand: encrypt or decrypt
    #[command(subcommand)]
    command: Commands,

    /// The passphrase used to encrypt/decrypt the file
    #[arg(short, long)]
    passphrase: String,

    /// Delete the input file after encryption/decryption
    #[arg(short, long)]
    delete: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt the input file
    Encrypt {
        /// Input file path to encrypt
        file_name: String,
    },

    /// Decrypt the input file
    Decrypt {
        /// Input file (must be produced by this tool)
        file_name: String,

        /// Overwrite existing files
        #[arg(short, long)]
        overwrite: bool,
    },
}

// ---- Entrypoint ----
fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { file_name } => {
            let encrypted_file = crypto::encrypt_file(&cli.passphrase, &file_name, cli.delete)?;
            println!("Encrypted {} -> {}", file_name, encrypted_file);
        }

        Commands::Decrypt {
            file_name,
            overwrite,
        } => {
            let decrypted_file =
                crypto::decrypt_file(&cli.passphrase, &file_name, cli.delete, overwrite)?;
            println!("Decrypted {} -> {}", file_name, decrypted_file);
        }
    }

    Ok(())
}
