
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) 
[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)](https://www.rust-lang.org/)

# LocalFileEncryptor

A simple local file encryption CLI tool written in Rust.

### Features
- ChaCha20Poly1305 for encryption
- Argon2 for password based key derivation
- Zeroize for secure memory cleanup

### Usage
```bash
lfe <encrypt/decrypt> <password> <path>
```
**Example**:
  ```
    lfe encrypt password123 journal.txt
    lfe decrypt password123 notes.md
  ```
## Build
```
cargo build --release
```
To use `lfe` system-wide on Windows, add the executable to your **path** environment variable.

For Linux run: 
```bash
sudo mv lfe /usr/local/bin/
```

## Warning!
This tool is experimental and may not work as intended on large files and folders, always back up your data before testing.
There is no password recovery or backup system.
If you forget your password, your data cannot be recovered.
