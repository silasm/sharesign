use std::convert::TryInto;
use sharks::{Sharks};

pub mod data;
pub mod error;
pub mod openssl;
pub mod pgp;
use self::openssl as tls;

// result of signing a payload
pub struct Signature {
    signature: Vec<u8>
}

pub fn generate(num_shares: u8, shares_needed: u8, config: &data::KeyConfig) -> Result<Vec<data::Share>, error::SharkSignError> {
    let key = tls::generate(config)?;
    let sharks = Sharks(shares_needed);
    // TODO: replace RNG if needed using dealer_rng
    let dealer = sharks.dealer(key.as_slice());
    Ok(dealer.take(num_shares.into()).map(|x| x.into()).collect())
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

pub fn encrypt(cert: &[u8], payload: &[u8]) -> Result<data::Encrypted, error::SharkSignError> {
    Ok(pgp::encrypt(cert, payload)?)
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
        let total_shares = 5;
        let shares_needed = 3;
        let shares = generate(total_shares, shares_needed, &config).unwrap();
        assert_eq!(shares.len(), usize::from(total_shares));
        recover(shares_needed, &shares).unwrap();
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
        tls::verify(&config, &pem, &payload, &signature.signature).unwrap();
    }
}
