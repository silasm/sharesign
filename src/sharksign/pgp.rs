use std::io::Write;

extern crate sequoia_openpgp as openpgp;
// use openpgp::cert::prelude::*;
use openpgp::serialize::stream::*;
use openpgp::parse::{Parse};
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
    let message = Armorer::new(message).build()?;
    let message = Encryptor::for_recipients(message, recipients).build()?;
    let mut message = LiteralWriter::new(message).build()?;

    /* encrypt the message into the buffer */
    message.write_all(payload)?;
    message.finalize()?;
    Ok(Encrypted {
        data: String::from_utf8(ciphertext).unwrap(),
        pubkey: KeyRef {},
    })
}

// only used by tests to verify that encryption works.
// API has no decryption functions, and encrypts only when distributing shares
// code ripped with minor changes from
// https://docs.sequoia-pgp.org/sequoia_guide/chapter_02/index.html
#[cfg(test)]
pub mod decrypt {
    use std::io;
    use super::*;
    use openpgp::policy::Policy;
    use openpgp::parse::stream::*;
    use openpgp::types::*;
    use openpgp::crypto::SessionKey;
    

    pub fn decrypt(tsk: &[u8], encrypted: &Encrypted) -> Result<Vec<u8>, SharkSignError> {
        /* parse private key cert */
        let tsk = openpgp::Cert::from_reader(tsk)?;

        let policy = openpgp::policy::StandardPolicy::new();
    
        let helper = Helper {
            policy: &policy,
            secret: &tsk,
        };
    
        let mut decryptor = DecryptorBuilder::from_bytes(&encrypted.data)?
            .with_policy(&policy, None, helper)?;
    
        let mut cleartext: Vec<u8> = Vec::new();
        io::copy(&mut decryptor, &mut cleartext)?;
        Ok(cleartext)
    }

    struct Helper<'a> {
        policy: &'a dyn Policy,
        secret: &'a openpgp::Cert,
    }

    impl<'a> VerificationHelper for Helper<'a> {
        /*
           We don't do verification of encrypted messages here.
           Since the same process distributes the public key as the shares,
           there'd be no benefit to the shareholder to verify this way --
           a theoretical attacker could generate and distribute their own
           public key and signature, so verification has to come from TLS
           on the server.

           We *will* sign the shares for the benefit of the *server*, so
           that it can validate shares when they're resubmitted, but that's
           distinct from PGP encryption, which is for the benefit of the
           shareholder clients at share distribution time.
        */
        fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
            Ok(Vec::new())
        }

        fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
            Ok(())
        }
    }
    impl<'a> DecryptionHelper for Helper<'a> {
        fn decrypt<D>(&mut self,
                      pkesks: &[openpgp::packet::PKESK],
                      _skesks: &[openpgp::packet::SKESK],
                       sym_algo: Option<SymmetricAlgorithm>,
                      mut decrypt: D)
                      -> openpgp::Result<Option<openpgp::Fingerprint>>
            where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
        {
            // use the one non-encrypted key in our test certs
            let key = self.secret.keys().unencrypted_secret()
                .with_policy(self.policy, None)
                .for_transport_encryption().nth(0).unwrap().key().clone();
            let mut pair = key.into_keypair().unwrap();

            pkesks[0].decrypt(&mut pair, sym_algo)
                .map(|(algo, session_key)| decrypt(algo, &session_key));

            // XXX: should return recipient cert's fingerprint
            Ok(None)
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::test_data;
    use super::decrypt;
    use openpgp::serialize::SerializeInto;

    #[test]
    fn generate_cert_export_import() {
        let (cert, _rev) = openpgp::cert::CertBuilder::new()
            .generate().unwrap();
        let armor = cert.armored().to_vec().unwrap();
        openpgp::cert::Cert::from_reader(armor.as_slice()).unwrap();
    }

    #[test]
    fn test_encrypt() {
        // TODO: tests at this level should probably be more generic --
        // should be encrypting basic data and leaving shares and such
        // to tests in other modules
        let td = test_data::test_data_3_5();

        let cert_bytes = td.approvers_pub[0].as_bytes();
        let share_bytes = &td.decrypted_shares()[0].data;
        let decrypt_bytes = td.approvers_priv[0].as_bytes();

        let ciphertext = encrypt(cert_bytes, share_bytes).unwrap();
        let decrypted = decrypt::decrypt(decrypt_bytes, &ciphertext).unwrap();

        // first byte of sharks shares is the x-intercept, always cardinally
        // numbered, so the first share will have a first byte of 0x01
        assert_eq!(0x01, decrypted[0]);
    }
}
