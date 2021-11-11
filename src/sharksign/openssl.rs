use std::convert::TryFrom;

use openssl;
use openssl::hash::MessageDigest as MD;
use openssl::rsa::Rsa;
use openssl::pkey::PKey;
use openssl::sign::Signer;

use super::data::{KeyConfig, KeyKind, MessageDigest};
use super::error::{SharkSignError};

pub fn generate(config: &KeyConfig) -> Result<Vec<u8>, SharkSignError> {
    match config.kind {
        KeyKind::RSA => Ok(Rsa::generate(config.size)?.private_key_to_pem()?),
        _ => Err(format!("key generation not implemented for key kind: {:?}", config.kind))?
    }
}

pub fn sign(config: &KeyConfig, pem: &[u8], payload: &[u8]) -> Result<Vec<u8>, SharkSignError> {
    let key = match config.kind {
        KeyKind::RSA => {
            let rsa = Rsa::private_key_from_pem(pem)?;
            Ok(PKey::from_rsa(rsa)?)
        },
        _ => Err(format!("signing not implemented for key kind: {:?}", config.kind))
    }?;
    match config.digest {
        Some(digest) => {
            let mut signer = Signer::new(MD::try_from(digest)?, &key)?;
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
pub fn verify(config: &KeyConfig, pem: &[u8], payload: &[u8], signature: &[u8]) -> Result<(), SharkSignError> {
    use openssl::sign::Verifier;

    let rsa = Rsa::private_key_from_pem(pem)?;
    let key = PKey::from_rsa(rsa)?;
    match config.digest {
        Some(digest) => {
            let mut verifier = Verifier::new(MD::try_from(digest)?, &key)?;
            verifier.update(payload)?;
            if verifier.verify(signature)? {
                Ok(())
            }
            else {
                Err("signature did not validate".to_owned())?
            }
        },
        None => {
            let mut verifier = Verifier::new_without_digest(&key)?;
            if verifier.verify_oneshot(signature, payload)? {
                Ok(())
            }
            else {
                Err("signature did not validate".to_owned())?
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_rsa_2048() {
        let config = KeyConfig {
            kind: KeyKind::RSA,
            size: 2048,
            digest: None,
        };
        generate(&config).unwrap();
    }

    #[test]
    fn sign_and_verify_rsa_2048() {
        let config = KeyConfig {
            kind: KeyKind::RSA,
            size: 2048,
            digest: None,
        };
        let payload = Vec::<u8>::from("this is a string");

        let pem = generate(&config).unwrap();
        let signature = sign(&config, &pem, &payload).unwrap();
        verify(&config, &pem, &payload, &signature).unwrap();
    }

    #[test]
    fn sign_and_verify_rsa_2048_sha256() {
        let config = KeyConfig {
            kind: KeyKind::RSA,
            size: 2048,
            digest: Some(MessageDigest::SHA256),
        };
        let payload = Vec::<u8>::from("this is another string");

        let pem = generate(&config).unwrap();
        let signature = sign(&config, &pem, &payload).unwrap();
        verify(&config, &pem, &payload, &signature).unwrap();
    }
}
