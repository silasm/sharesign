use std::convert::TryInto;
use sharks::{Sharks};

pub mod data;
pub mod state;
pub mod error;
pub mod pgp;

use sequoia_openpgp::serialize::SerializeInto;

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

pub fn generate(approvers: &[String], shares_needed: u8, config: &data::KeyConfig) -> Result<data::GeneratedKey, error::SharkSignError> {
    let key = pgp::generate(config)?;
    let tsk_bytes = key.as_tsk().to_vec()?;

    let sharks = Sharks(shares_needed);
    let dealer = sharks.dealer(&tsk_bytes);

    let mut shares: Vec<data::EncryptedShare> = Vec::new();
    for (cert, shark) in approvers.iter().zip(dealer.take(approvers.len())) {
        let share_bytes = Vec::from(&shark);
        let signature = pgp::sign(&tsk_bytes, &share_bytes)?;
        shares.push(encrypt_share(cert.as_bytes(), data::Share {
            data: share_bytes,
            signature: String::from_utf8(signature).unwrap(),
        })?)
    }
    Ok(data::GeneratedKey {
        pubkey: pgp::public_from_private(config, key),
        config: config.clone(),
        shares: shares,
    })
}

fn recover(shares_needed: u8, shares: &[data::Share]) -> Result<Vec<u8>, error::SharkSignError> {
    let sharks = Sharks(shares_needed);
    let mut sharkshares = Vec::<sharks::Share>::new();
    for share in shares {
        sharkshares.push(share.try_into().unwrap())
    }
    Ok(sharks.recover(sharkshares.iter())?)
}

pub fn sign(shares_needed: u8, shares: &[data::Share], payload: &[u8]) -> Result<Signature, error::SharkSignError> {
    let cert = recover(shares_needed, shares)?;
    let signature = pgp::sign(&cert, payload)?;
    Ok(Signature{
        signature: signature,
    })
}

pub mod test_data;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_shares_rsa_2048() {
        let td = test_data::load_test_data_3_5();

        let generated = generate(&td.approvers_pub, td.shares_required, &td.config).unwrap();
        assert_eq!(generated.shares.len(), td.approvers_pub.len());

        let shares_plaintext: Vec<data::Share> = generated.shares.into_iter().zip(td.approvers_priv.iter()).map(
            move |(share, key)| decrypt_share(key.as_bytes(), share).unwrap()
        ).collect();
        recover(td.shares_required, &shares_plaintext).unwrap();
    }

    #[test]
    fn recover_static_pem_3_5() {
        recover(3, &test_data::load_test_data_3_5().decrypted_shares()).unwrap();
    }

    #[test]
    fn test_sign_shares_rsa_2048() {
        use sequoia_openpgp::parse::Parse;

        let td = test_data::load_test_data_3_5();
        let shares = td.decrypted_shares();
        let payload = "Hello, World!".to_owned().into_bytes();
        let signature = sign(td.shares_required, &shares, &payload).unwrap();

        let cert = recover(3, &shares).unwrap();
        let cert = sequoia_openpgp::Cert::from_reader(cert.as_slice()).unwrap();
        let public_cert = pgp::public_from_private(&td.config, cert).pem;
        
        pgp::verify::verify(&public_cert.as_bytes(), &payload, &signature.signature).unwrap();
    }
}
