# Crypto

A Rust command line program to encrypt and decrypt files.

** WARNING ** This may not be cryptographically secure. I wrote it as a learning exercise for the language. I *believe* I have used the appropriate libraries and techniques.

```
File encryption/decryption utility

Usage: crypto <COMMAND>

Commands:
  encrypt  Encrypt the input file(s)
  decrypt  Decrypt the input file(s) (must have been produced by this tool)
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

```
Encrypt the input file(s)

Usage: crypto encrypt [OPTIONS] --passphrase <PASSPHRASE> --files <FILES>...

Options:
  -p, --passphrase <PASSPHRASE>  The passphrase to encrypt the file with
  -d, --delete                   Delete the input file after encryption
  -f, --files <FILES>...         The file(s) to encrypt
  -h, --help                     Print help
```

```
Decrypt the input file(s)

Usage: crypto decrypt [OPTIONS] --passphrase <PASSPHRASE> --files <FILES>...

Options:
  -p, --passphrase <PASSPHRASE>  The passphrase that was used to encrypt the file
  -d, --delete                   Delete the input file after decryption
  -o, --overwrite                Overwrite existing files
  -f, --files <FILES>...         The file(s) to decrypt (must have been produced by this tool)
  -h, --help                     Print help
  ```
