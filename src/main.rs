use clap::{Parser, Subcommand};
use crypto::Result;
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about = "File encryption/decryption utility", long_about = None)]
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

        /// The file(s) to encrypt
        #[clap(value_parser, num_args = 1.., required = true)]
        #[arg(short, long)]
        files: Vec<PathBuf>,
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

        /// The file(s) to decrypt (must have been produced by this tool)
        #[clap(value_parser, num_args = 1.., required = true)]
        #[arg(short, long)]
        files: Vec<PathBuf>,
    },
}

// ---- Entrypoint ----
fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt {
            passphrase,
            delete,
            files,
        } => {
            encrypt_files(&passphrase, &files, delete)?;
        }

        Commands::Decrypt {
            passphrase,
            delete,
            files,
            overwrite,
        } => {
            decrypt_files(&passphrase, &files, delete, overwrite)?;
        }
    }

    Ok(())
}

fn encrypt_files(passphrase: &str, files: &Vec<PathBuf>, delete: bool) -> Result<()> {
    for file_name in files {
        match crypto::encrypt_file(&passphrase, &file_name, delete) {
            Ok(encrypted_file) => {
                println!("Encrypted {:?} -> {:?}", file_name, encrypted_file);
            }
            Err(e) => {
                eprintln!("Could not encrypt {file_name:?}: {e}");
            }
        }
    }
    Ok(())
}

fn decrypt_files(
    passphrase: &str,
    files: &Vec<PathBuf>,
    delete: bool,
    overwrite: bool,
) -> Result<()> {
    for file_name in files {
        match crypto::decrypt_file(&passphrase, &file_name, delete, overwrite) {
            Ok(decrypted_file) => {
                println!("Decrypted {:?} -> {:?}", file_name, decrypted_file);
            }
            Err(e) => {
                eprintln!("Could not decrypt {file_name:?}: {e}");
            }
        }
    }
    Ok(())
}
