use std::io::Write;

extern crate sequoia_openpgp as openpgp;
// use openpgp::cert::prelude::*;
use openpgp::serialize::stream::*;
use openpgp::parse::{Parse};
// use openpgp::policy::Policy;
use openpgp::policy::StandardPolicy;

use super::data::{Encrypted, KeyRef};
use super::error::{SharkSignError};

pub fn encrypt(cert: &[u8], payload: &[u8]) -> Result<Encrypted, SharkSignError> {
    /* parse cert */
    let cert = openpgp::Cert::from_reader(cert)?;

    /* set encryption policy and keys */
    let policy = &StandardPolicy::new();
    let recipients = cert.keys()
        .with_policy(policy, None)
        .supported().alive().revoked(false)
        .for_transport_encryption();

    /* build up the encryption pipeline */
    let mut ciphertext = Vec::new();
    let message = Message::new(&mut ciphertext);
    let message = Encryptor::for_recipients(message, recipients).build()?;
    let mut message = LiteralWriter::new(message).build()?;

    /* encrypt the message into the buffer */
    message.write_all(payload)?;
    message.finalize()?;
    Ok(Encrypted {
        data: ciphertext,
        pubkey: KeyRef {},
    })
}

/*
// only used by tests to verify that encryption works.
// API has no decryption functions (encrypts only when distributing shares)
#[cfg(test)]
pub fn decrypt(_config: &KeyConfig, pem: &[u8], encrypted: Encrypted) -> Result<Vec<u8>, SharkSignError> {
    use openssl::encrypt::Decrypter;
    use openssl::rsa::Padding;

    let rsa = Rsa::private_key_from_pem(pem)?;
    let key = PKey::from_rsa(rsa)?;
    let mut decrypter = Decrypter::new(&key)?;
    decrypter.set_rsa_padding(Padding::PKCS1)?;
    let buffer_len = decrypter.decrypt_len(&encrypted.data)?;
    let mut decrypted = vec![0; buffer_len];
    let decrypted_len = decrypter.decrypt(&encrypted.data, &mut decrypted)?;
    decrypted.truncate(decrypted_len);
    Ok(decrypted)
}
*/

#[cfg(test)]
mod tests {
    use super::*;
    use openpgp::serialize::{Serialize, SerializeInto};
    use openpgp::armor;
    use super::super::test_data;

    // generates 10 certs and outputs them in ascii armor
    // see test_data::static_approvers_10
    // #[test]
    fn generate_certs() {
        let uids = vec![
            "alice", "bob", "chester", "david", "eve",
            "fred", "gus", "henrietta", "irene", "jack",
        ];
        let mut certs: Vec<String> = Vec::new();
        for name in uids {
            let (cert, _rev) = openpgp::cert::CertBuilder::general_purpose(None, Some(format!("{}@example.org", name))).generate().unwrap();
            let armor = String::from_utf8(cert.armored().to_vec().unwrap()).unwrap();
            certs.push(armor);
        }
        print!("{:#?}\n", certs);
        assert!(false);
    }

    #[test]
    fn generate_cert_export_import() {
        let (cert, _rev) = openpgp::cert::CertBuilder::new()
            .generate().unwrap();
        let armor = cert.armored().to_vec().unwrap();
        openpgp::cert::Cert::from_reader(armor.as_slice()).unwrap();
    }

    #[test]
    fn test_encrypt() {
        let approvers = test_data::static_approvers_10();
        let shares = test_data::static_shares_3_5();
        let cert_bytes = approvers[0].as_bytes();
        let share_bytes = &shares[0].data;
        encrypt(cert_bytes, share_bytes).unwrap();
    }
}
