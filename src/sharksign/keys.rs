use std::fmt;
use std::error::Error;

use openssl;
use openssl::rsa::Rsa;
use openssl::pkey::{PKey, Id};
use openssl::sign::Signer;
use openssl::hash::MessageDigest;
use openssl::error::ErrorStack;

#[derive(Debug)]
pub enum SharkSignError {
    StringError(String),
    OpensslError(ErrorStack),
}

impl fmt::Display for SharkSignError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SharkSignError::StringError(e) => write!(f, "Internal Error: {}", e),
            SharkSignError::OpensslError(e) => write!(f, "SSL Error: {}", e),
        }
    }
}

impl From<String> for SharkSignError {
    fn from(result: String) -> SharkSignError {
        SharkSignError::StringError(result)
    }
}

impl From<ErrorStack> for SharkSignError {
    fn from(result: ErrorStack) -> SharkSignError {
        SharkSignError::OpensslError(result)
    }
}

impl Error for SharkSignError {
    
}

// configuration for generating a key
pub struct KeyConfig {
    kind: Id,
    size: u32,
    digest: Option<MessageDigest>,
}

pub fn generate(config: &KeyConfig) -> Result<Vec<u8>, SharkSignError> {
    match config.kind {
        openssl::pkey::Id::RSA => Ok(Rsa::generate(config.size)?.private_key_to_pem()?),
        _ => Err(format!("key generation not implemented for key kind: {:?}", config.kind))?
    }
}

pub fn sign(config: &KeyConfig, pem: &[u8], payload: &[u8]) -> Result<Vec<u8>, SharkSignError> {
    let key = match config.kind {
        openssl::pkey::Id::RSA => {
            let rsa = Rsa::private_key_from_pem(pem)?;
            Ok(PKey::from_rsa(rsa)?)
        },
        _ => Err(format!("signing not implemented for key kind: {:?}", config.kind))
    }?;
    match config.digest {
        Some(digest) => {
            let mut signer = Signer::new(digest, &key)?;
            signer.update(payload)?;
            Ok(signer.sign_to_vec()?)
        },
        None => {
            let mut signer = Signer::new_without_digest(&key)?;
            Ok(signer.sign_oneshot_to_vec(payload)?)
        }
    }
}

#[cfg(test)]
mod tests {
    use openssl::sign::Verifier;
    use super::*;

    #[test]
    fn generate_rsa_2048() {
        let config = KeyConfig {
            kind: openssl::pkey::Id::RSA,
            size: 2048,
            digest: None,
        };
        generate(&config).unwrap();
    }

    #[test]
    fn sign_and_verify_rsa_2048() {
        let config = KeyConfig {
            kind: openssl::pkey::Id::RSA,
            size: 2048,
            digest: None,
        };
        let payload = Vec::<u8>::from("this is a string");

        let pem = generate(&config).unwrap();
        let signature = sign(&config, &pem, &payload).unwrap();
        let rsa = Rsa::private_key_from_pem(&pem.as_slice()).unwrap();
        let key = PKey::from_rsa(rsa).unwrap();
        let mut verifier = Verifier::new_without_digest(&key).unwrap();
        assert!(verifier.verify_oneshot(&signature, &payload).unwrap());
    }

    #[test]
    fn sign_and_verify_rsa_2048_sha256() {
        let config = KeyConfig {
            kind: openssl::pkey::Id::RSA,
            size: 2048,
            digest: Some(MessageDigest::sha256()),
        };
        let payload = Vec::<u8>::from("this is another string");

        let pem = generate(&config).unwrap();
        let signature = sign(&config, &pem, &payload).unwrap();
        let rsa = Rsa::private_key_from_pem(&pem.as_slice()).unwrap();
        let key = PKey::from_rsa(rsa).unwrap();
        let mut verifier = Verifier::new(config.digest.unwrap(), &key).unwrap();
        verifier.update(&payload).unwrap();
        assert!(verifier.verify(&signature).unwrap());
    }
}
