//! # Tinycrypt
//! A small & simple encryption library.
//! 
//! Exports two functions (encrypt & decrypt) along with an error type (CryptographyError) that implements std::error::Error.
//! 
//! Basic usage:
//! ```rust
//! use tinycrypt::{Encrypt, Decrypt, CryptographyError};
//! 
//! let data = "Hello world!";
//! let secure_password = "password";
//! 
//! let encrypted_data: Vec<u8> = encrypt(data.as_bytes(), secure_password.as_bytes()).unwrap();
//! 
//! println!("Data encrypted!");
//! 
//! let decrypted_data: Vec<u8> = decrypt(&encrypted_data, password.as_bytes()).unwrap();
//! 
//! //Can also pattern match, to seperate invalid passwords from actual errors.
//! match decrypt(&encrypted_data, password.as_bytes()) {
//!     Ok(data) => (), //do something with data
//!     Err(password_error @ CryptographyError::IncorrectPassword) => (), //do something with incorrect password
//!     Err(error) => (), //do something with a different error
//! }
//! 
//! println!("{}", String::from_utf8(&decrypted_data).unwrap());
//! ```


use aes_gcm_siv::{
    aead::{generic_array::GenericArray, rand_core::RngCore, Aead, OsRng},
    Aes256GcmSiv, KeyInit, Nonce,
};
use argon2::Config;
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt::Display};

/// Error type for library, handles bincode encoding/decoding errors and key generation errors.
/// Also provides a unique error for incorrect passwords.
/// 
/// Implements Debug, Display, Error, PartialEq, and Clone
#[derive(Debug, Clone, PartialEq)]
pub enum CryptographyError {
    DecodingFailure,
    EncodingFailure,
    KeyGenerationFailure,
    IncorrectPassword,
}

impl Display for CryptographyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{:?}", self)
    }
}

impl Error for CryptographyError {
    fn description(&self) -> &str {
        match self {
            Self::EncodingFailure => "Failed to encode data",
            Self::DecodingFailure => "Data not valid",
            Self::KeyGenerationFailure => "Failed to create key from password",
            Self::IncorrectPassword => "Given password was incorrect",
        }
    }
}

#[derive(Serialize, Deserialize)]
struct EncryptedFile {
    data: Vec<u8>,
    nonce: [u8; 12],
    salt: [u8; 32],
}

/// Function for encrypting data.
/// Takes any data and password input as a slice (&\[T\]) of u8 (bytes) and returns a Result wrapping a vector of u8.
/// 
/// ```rust
/// let data = "Hello, world!";
/// let password = "password";
/// 
/// let encrypted_data: Vec<u8> = encrypt(data.as_bytes(), password.as_bytes()).expect("Failed to encrypt!");
/// ```
pub fn encrypt(data: &[u8], password: &[u8]) -> Result<Vec<u8>, CryptographyError> {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    let config = Config {
        hash_length: 32,
        ..Default::default()
    };

    let password = argon2::hash_raw(password, &salt, &config)
        .map_err(|_| CryptographyError::KeyGenerationFailure)?;
    let key = GenericArray::from_slice(&password);
    let cipher = Aes256GcmSiv::new(key);

    let mut nonce_rand = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_rand);

    let nonce = Nonce::from_slice(&nonce_rand);
    let ciphertext = cipher
        .encrypt(nonce, data.as_ref())
        .map_err(|_| CryptographyError::IncorrectPassword)?;

    let file = EncryptedFile {
        data: ciphertext,
        nonce: nonce_rand,
        salt,
    };

    bincode::serialize(&file).map_err(|_| CryptographyError::EncodingFailure)
}


/// Function for decrypting data.
/// Takes encrypted data and password input as a slice (&\[T\]) of u8 (bytes) and returns a Result wrapping a vector of u8.
/// 
/// ```rust
/// let data = "Hello, world!";
/// let password = "password";
/// 
/// let encrypted_data: Vec<u8> = encrypt(data.as_bytes(), password.as_bytes()).expect("Failed to encrypt!");
/// 
/// let decrypted_data : Vec<u8>= decrypt(&encrypted_data, password.as_bytes()).expect("Failed to decrypt data!");
/// ```
pub fn decrypt(data: &[u8], password: &[u8]) -> Result<Vec<u8>, CryptographyError> {
    let decoded: EncryptedFile =
        bincode::deserialize(data).map_err(|_| CryptographyError::DecodingFailure)?;
    let config = Config {
        hash_length: 32,
        ..Default::default()
    };
    let password = argon2::hash_raw(password, &decoded.salt, &config)
        .map_err(|_| CryptographyError::KeyGenerationFailure)?;

    let key = GenericArray::from_slice(&password);
    let cipher = Aes256GcmSiv::new(key);
    let nonce = Nonce::from_slice(&decoded.nonce);

    cipher
        .decrypt(nonce, decoded.data.as_ref())
        .map_err(|_| CryptographyError::IncorrectPassword)
}
