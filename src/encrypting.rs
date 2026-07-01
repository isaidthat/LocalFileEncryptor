use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use chacha20poly1305::aead::Aead;
use argon2::Argon2;
use rand::RngCore;
use rand::rngs::OsRng;
use std::path::Path;
use std::fs;

const MAGIC: &[u8] = b"ENCR";

pub fn encrypt_file(path: String, password:String) -> Result<Option<String>, Box<dyn std::error::Error>>{

    if Path::new(&path).is_dir() {
        recursively(&path, &password, encrypt_file);
        return Ok(None);
    }

    let data = match fs::read(Path::new(&path)) {
        Ok(d) => d,
        Err(_)=> {println!("skipping {path}"); return Ok(None);}
        
    };

        if data.starts_with(MAGIC) {
        panic!("file is already encrypted");
    }

    let argon2 = Argon2::default();
    let mut salt = [0u8; 16];
    OsRng.try_fill_bytes(&mut salt)?;

    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), &salt, &mut key).expect("failed to hash password");

    let cipher = ChaCha20Poly1305::new((&key).into());

    let mut nonce = [0u8; 12];
    OsRng.try_fill_bytes(&mut nonce).expect("failed to generate nonce");

    let ciphertext = cipher.encrypt(&(nonce).into(), data.as_ref())?;


    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);

    fs::write(&path, out)?;
    println!("encrypted {path}");
    Ok(Some(String::from("successfully encrypted")))

}  

pub fn decrypt_file(path:String, password:String) -> Result<Option<String>, Box<dyn std::error::Error>>{

    
    if Path::new(&path).is_dir() {
        recursively(&path, &password, decrypt_file);
        return Ok(None);
    }
    
    let data = match fs::read(Path::new(&path)) {
        Ok(d) => d,
        Err(_)=> {println!("skipping {path}"); return Ok(None);}
        
    };

    if !data.starts_with(MAGIC) {
        panic!("not encrypted or already decrypted");
    }

    let data = &data[MAGIC.len()..];

    let (salt, rest) = data.split_at(16);
    let (nonce_bytes, ciphertext) = rest.split_at(12);

    
    let argon2 = Argon2::default();

    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), &salt, &mut key).expect("failed to hash password");

    let cipher = ChaCha20Poly1305::new((&key).into());


    let text_bytes = cipher.decrypt(nonce_bytes.try_into()?, ciphertext).expect("failed to decrypt");

    fs::write(&path, text_bytes)?;
    println!("decrypted {path}");
    Ok(Some(String::from("successfully decrypted")))

}


pub fn recursively<F>(path:&String, password:&String, operation: F) where F:Fn(String, String) -> Result<Option<String>, Box<dyn std::error::Error>> {
    for file in fs::read_dir(path).expect("failed to read directory") {
        operation(file.unwrap().path().to_string_lossy().to_string(), password.to_owned()).expect("failed to execute operation");
        }
}