use zeroize::Zeroize;
use std::{env, error::Error, fs};
mod hash;
mod helpers;
mod encrypting;


fn help() -> Result<Option<String>, Box<dyn Error>> {  
    println!("usage: lfe <encrypt/decrypt> <password> <path>");
    return Ok(None)
}

fn main() {
    let args: Vec<String> = env::args().collect();

    match args.len() {
        2 => match args[1].as_str() {"setup"=>setup(),"verify"=>hash::verify_password(helpers::input("password: ").unwrap()), _ => {help().unwrap();}}
        4 => match args[1].as_str() {
            "encrypt" => {encrypting::encrypt_file(args[3].to_owned(), args[2].to_owned()).unwrap();},
            "decrypt" => {println!("{}", encrypting::decrypt_file(args[3].to_owned(), args[2].to_owned()).unwrap().unwrap());},
            "save_decryption" => {fs::write(args[3].to_owned(), encrypting::decrypt_file(args[3].to_owned(), args[2].to_owned()).unwrap().unwrap()).unwrap()}
            _ => {help().unwrap();}
        },
        _ => {help().unwrap();}
    }

}


fn setup(){
    let mut password = helpers::input("password: ").unwrap();
    let hash = hash::generate_hash(&password);
    hash::save_hash(hash.unwrap()).unwrap();
    password.zeroize();
}