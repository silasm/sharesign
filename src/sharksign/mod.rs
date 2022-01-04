use std::convert::TryInto;
use sharks::{Sharks};

pub mod data;
pub mod state;
pub mod error;
pub mod openssl;
pub mod pgp;
pub use self::openssl as tls;

// result of signing a payload
pub struct Signature {
    signature: Vec<u8>
}

pub fn encrypt_share(cert: &[u8], share: data::Share) -> Result<data::EncryptedShare, error::SharkSignError> {
    Ok(data::EncryptedShare {
        encrypted: pgp::encrypt(cert, &share.data)?,
        signature: share.signature,
    })
}

/*
We only have private keys for openpgp decryption when testing.
*/
#[cfg(test)]
pub fn decrypt_share(cert: &[u8], share: data::EncryptedShare) -> Result<data::Share, error::SharkSignError> {
    Ok(data::Share {
        data: pgp::decrypt::decrypt(cert, &share.encrypted)?,
        signature: share.signature,
    })
}

pub fn generate(approvers: &[String], shares_needed: u8, config: &data::KeyConfig) -> Result<Vec<data::EncryptedShare>, error::SharkSignError> {
    let key = tls::generate(config)?;
    let sharks = Sharks(shares_needed);
    let dealer = sharks.dealer(key.as_slice());
    let mut shares: Vec<data::EncryptedShare> = Vec::new();
    for (cert, shark) in approvers.iter().zip(dealer.take(approvers.len())) {
        let share_bytes = Vec::from(&shark);
        let signature = tls::sign(config, &key, &share_bytes)?;
        shares.push(encrypt_share(cert.as_bytes(), data::Share {
            data: share_bytes,
            signature: signature,
        })?)
    }
    Ok(shares)
}

fn recover(shares_needed: u8, shares: &[data::Share]) -> Result<Vec<u8>, error::SharkSignError> {
    let sharks = Sharks(shares_needed);
    let mut sharkshares = Vec::<sharks::Share>::new();
    for share in shares {
        sharkshares.push(share.try_into().unwrap())
    }
    Ok(sharks.recover(sharkshares.iter())?)
}

pub fn sign(shares_needed: u8, shares: &[data::Share], payload: &[u8], config: &data::KeyConfig) -> Result<Signature, error::SharkSignError> {
    let pem = recover(shares_needed, shares)?;
    let signature = tls::sign(config, pem.as_slice(), payload)?;
    Ok(Signature{
        signature: signature,
    })
}

#[cfg(test)]
pub mod test_data;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_shares_rsa_2048() {
        let config = data::KeyConfig {
            kind: data::KeyKind::RSA,
            size: 2048,
            digest: None,
        };
        let total_shares: usize = 5;
        let shares_needed = 3;
        let pubkeys = &test_data::static_approvers_pub_10()[0..5];
        let privkeys = &test_data::static_approvers_priv_10()[0..5];

        let shares = generate(pubkeys, shares_needed, &config).unwrap();
        assert_eq!(shares.len(), total_shares);

        let shares_plaintext: Vec<data::Share> = shares.into_iter().zip(privkeys).map(
            move |(share, key)| decrypt_share(key.as_bytes(), share).unwrap()
        ).collect();
        recover(shares_needed, &shares_plaintext).unwrap();
    }

    #[test]
    fn recover_static_pem_3_5() {
        recover(3, &test_data::static_shares_3_5()).unwrap();
    }

    #[test]
    fn test_sign_shares_rsa_2048() {
        let config = data::KeyConfig {
            kind: data::KeyKind::RSA,
            size: 2048,
            digest: None,
        };
        let shares = test_data::static_shares_3_5();
        let shares_needed = 3;
        let payload = "Hello, World!".to_owned().into_bytes();
        let signature = sign(shares_needed, &shares, &payload, &config).unwrap();

        let pem = recover(3, &shares).unwrap();
        let public_pem = tls::public_from_private(&config, &pem).unwrap().pem;
        tls::verify(&config, &public_pem, &payload, &signature.signature).unwrap();
    }
}
