use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;
use rand::rngs::OsRng;
use std::fs;
use std::str;

pub fn generate_hash(password: &str) -> Result<String, argon2::password_hash::Error> {

    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);

    let hash = argon2.hash_password(&password.to_owned().into_bytes(), &salt).expect("failed to generate hash");

    Ok(hash.to_string())
}

pub fn verify_password(password: String) {

    let stored_hash_bytes = fs::read("stored.hash").expect("failed to read hash");
    let stored_hash_str = str::from_utf8(&stored_hash_bytes).expect("hash file is not valid UTF-8");
    let parsed_hash = PasswordHash::new(stored_hash_str).expect("failed to parse hash");

    let result = Argon2::default().verify_password(password.as_bytes(), &parsed_hash);

    match result {
        Ok(_) => println!("correct password"),
        Err(_) => println!("wrong password"),
    }
}

pub fn save_hash(hash: String) -> Result<String, std::io::Error>{
    fs::write("stored.hash", hash).expect("unable to write");
    return Ok("done".to_string())
}
 