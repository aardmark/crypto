# Crypto

A Rust command line program to encrypt and decrypt files.

** WARNING ** This may not be cryptographically secure. I wrote it as a learning exercise for the language. I *believe* I have used the appropriate libraries and techniques.

```
File encryption/decryption utitlity

Usage: crypto <COMMAND>

Commands:
  encrypt  Encrypt the input file
  decrypt  Decrypt the input file
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

```
Encrypt the input file

Usage: crypto encrypt [OPTIONS] --passphrase <PASSPHRASE> <FILE_NAME>

Arguments:
  <FILE_NAME>  Input file path to encrypt

Options:
  -p, --passphrase <PASSPHRASE>  The passphrase to encrypt the file with
  -d, --delete                   Delete the input file after encryption
  -h, --help                     Print help
```

```
Decrypt the input file

Usage: crypto decrypt [OPTIONS] --passphrase <PASSPHRASE> <FILE_NAME>

Arguments:
  <FILE_NAME>  Input file (must be produced by this tool)

Options:
  -p, --passphrase <PASSPHRASE>  The passphrase that was used to encrypt the file
  -d, --delete                   Delete the input file after decryption
  -o, --overwrite                Overwrite existing files
  -h, --help                     Print help
  ```
