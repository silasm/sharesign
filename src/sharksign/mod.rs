use sharks::Sharks;

pub mod data;
pub mod state;
pub mod error;
pub mod pgp;

use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::parse::Parse;

// result of signing a payload
#[allow(dead_code)]
pub struct Signature {
    signature: Vec<u8>
}

pub fn generate(approvers: &[pgp::Cert], shares_needed: u8, config: &data::KeyConfig) -> Result<data::GeneratedKey, error::SharkSignError> {
    let key = pgp::generate(config)?;
    let tsk_bytes = key.as_tsk().to_vec()?;

    let sharks = Sharks(shares_needed);
    let dealer = sharks.dealer(&tsk_bytes);

    let mut shares: Vec<data::EncryptedShare> = Vec::new();
    for (cert, shark) in approvers.iter().zip(dealer.take(approvers.len())) {
        shares.push(data::EncryptedShare::new(shark, &key, cert)?);
    }
    Ok(data::GeneratedKey {
        pubkey: pgp::public_from_private(config, key),
        config: config.clone(),
        shares,
    })
}

#[allow(dead_code)]
fn recover(shares_needed: u8, shares: &[data::Share], verify: &pgp::Cert) -> Result<Vec<u8>, error::SharkSignError> {
    let sharks = Sharks(shares_needed);
    let mut sharkshares = Vec::<sharks::Share>::new();
    for share in shares {
        sharkshares.push(share.data(verify)?)
    }
    Ok(sharks.recover(sharkshares.iter())?)
}

#[allow(dead_code)]
pub fn sign(shares_needed: u8, shares: &[data::Share], payload: &[u8], verify: &pgp::Cert) -> Result<Signature, error::SharkSignError> {
    let cert = recover(shares_needed, shares, verify)?;
    let cert = pgp::Cert::from_reader(cert.as_slice())?;
    let signature = pgp::sign(&cert, payload, false)?;
    Ok(Signature{
        signature,
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

        let shares_plaintext: Vec<data::Share> = generated.shares.into_iter().zip(td.approvers_priv().iter()).map(
            move |(share, key)| {
                share.decrypt(&key).unwrap()
            }
        ).collect();
        recover(td.shares_required, &shares_plaintext, &generated.pubkey.cert().unwrap()).unwrap();
    }

    #[test]
    fn recover_static_pem_3_5() {
        let td = test_data::load_test_data_3_5();
        recover(3, &td.decrypted_shares(), &td.verifier()).unwrap();
    }

    #[test]
    fn test_sign_shares_rsa_2048() {
        use sequoia_openpgp::parse::Parse;

        let td = test_data::load_test_data_3_5();
        let shares = td.decrypted_shares();
        let payload = "Hello, World!".to_owned().into_bytes();
        let signature = sign(td.shares_required, &shares, &payload, &td.verifier()).unwrap();

        let cert = recover(3, &shares, &td.verifier()).unwrap();
        let cert = sequoia_openpgp::Cert::from_reader(cert.as_slice()).unwrap();
        let public_cert = pgp::public_from_private(&td.config, cert);
        let cert = pgp::Cert::from_reader(public_cert.pem.as_bytes()).unwrap();
        
        pgp::verify::verify(&cert, &payload, &signature.signature).unwrap();
    }
}
