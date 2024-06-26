# tinycrypt
Small & simple rust encryption library

Tinycript aims to be a small dependency that gives you an encrypt function and a decrypt one. Simple as that. No bloat, no unnecesary dependencies (and featues), and no crazy API.

Uses Argon2 & Aes-gcm-siv for cryptography.

Simple example:
```rust
use tinycrypt::{Encrypt, Decrypt, CryptographyError};
 
let data = "Hello world!";
let secure_password = "password";
 
let encrypted_data: Vec<u8> = encrypt(data.as_bytes(), secure_password.as_bytes()).unwrap();
 
println!("Data encrypted!");
 
let decrypted_data: Vec<u8> = decrypt(&encrypted_data, password.as_bytes()).unwrap();
 
//Can also pattern match, to seperate invalid passwords from actual errors.
match decrypt(&encrypted_data, password.as_bytes()) {
    Ok(data) => (), //do something with data
    Err(password_error @ CryptographyError::IncorrectPassword) => (), //do something with incorrect password
    Err(error) => (), //do something with a different error
}

println!("{}", String::from_utf8(&decrypted_data).unwrap());
```