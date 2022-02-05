use sharks::Sharks;

pub mod data;
pub mod state;
pub mod error;
mod pgp;

use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::parse::Parse;
use error::SharkSignError as SSE;

// result of signing a payload
#[allow(dead_code)]
pub struct Signature {
    signature: Vec<u8>
}

pub fn generate(approvers: &[pgp::Cert], shares_needed: u8, config: &data::KeyConfig) -> Result<data::GeneratedKey, SSE> {
    let key = pgp::generate(config)?;
    let tsk_bytes = key.as_tsk().to_vec()?;

    let sharks = Sharks(shares_needed);
    let dealer = sharks.dealer(&tsk_bytes);

    let mut shares: Vec<data::EncryptedShare> = Vec::new();
    for (cert, shark) in approvers.iter().zip(dealer.take(approvers.len())) {
        let confirm = data::Confirm::default();
        // TODO: save confirm locally for confirmation that share has been
        // received; do not publish
        shares.push(data::EncryptedShare::new(shark, &key, cert, confirm)?);
    }
    Ok(data::GeneratedKey {
        pubkey: key.strip_secret_key_material(),
        config: config.clone(),
        shares,
    })
}

#[allow(dead_code)]
fn recover(shares_needed: u8, shares: &[data::Share], verify: &pgp::Cert) -> Result<Vec<u8>, SSE> {
    let sharks = Sharks(shares_needed);
    let mut sharkshares = Vec::<sharks::Share>::new();
    for share in shares {
        sharkshares.push(share.data(verify)?)
    }
    match sharks.recover(sharkshares.iter()) {
        Ok(bytes) => Ok(bytes),
        Err(str) => Err(SSE::KeyRecovery(str.to_owned())),
    }
}

#[allow(dead_code)]
pub fn sign(shares_needed: u8, shares: &[data::Share], payload: &[u8], verify: &pgp::Cert) -> Result<Signature, SSE> {
    let cert = recover(shares_needed, shares, verify)?;
    let cert = pgp::Cert::from_reader(cert.as_slice())?;
    let signature = pgp::sign(&cert, payload, false)?;
    Ok(Signature{
        signature,
    })
}

#[cfg(test)]
mod test_data;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_shares_rsa_2048() {
        let td = test_data::load_test_data_3_5();

        let generated = generate(&td.approvers_pub, td.shares_required, &td.generated.config).unwrap();
        assert_eq!(generated.shares.len(), td.approvers_pub.len());

        let shares_plaintext: Vec<data::Share> = generated.shares.into_iter().zip(td.approvers_priv().iter()).map(
            move |(share, key)| {
                share.decrypt(&key).unwrap()
            }
        ).map(|x| data::Share::from(x).clone()).collect();
        recover(td.shares_required, &shares_plaintext, &generated.pubkey).unwrap();
    }

    #[test]
    fn recover_static_pem_3_5() {
        let td = test_data::load_test_data_3_5();
        recover(3, &td.decrypted_shares(), &td.generated.pubkey).unwrap();
    }

    #[test]
    fn test_sign_shares_rsa_2048() {
        use sequoia_openpgp::parse::Parse;

        let td = test_data::load_test_data_3_5();
        let shares = td.decrypted_shares();
        let payload = "Hello, World!".to_owned().into_bytes();
        let signature = sign(td.shares_required, &shares, &payload, &td.generated.pubkey).unwrap();

        let cert = recover(3, &shares, &td.generated.pubkey).unwrap();
        let cert = sequoia_openpgp::Cert::from_reader(cert.as_slice()).unwrap();

        pgp::verify::verify(&cert.strip_secret_key_material(), &payload, &signature.signature).unwrap();
    }
}
