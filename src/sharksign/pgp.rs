use std::io::Write;

extern crate sequoia_openpgp as openpgp;
// use openpgp::cert::prelude::*;
use openpgp::serialize::stream::*;
use openpgp::policy::StandardPolicy;
use openpgp::armor;
use openpgp::serialize::SerializeInto;
pub use openpgp::Cert;

use super::data::{Encrypted, KeyRef, KeyConfig, PubKey};
use super::error::{SharkSignError};

pub fn public_from_private(config: &KeyConfig, cert: Cert) -> PubKey {
    PubKey {
        kind: config.kind,
        // serializing without converting to TSK already strips secret key data
        pem: String::from_utf8(cert.armored().to_vec().unwrap()).unwrap(),
    }
}

pub fn generate(config: &KeyConfig) -> openpgp::Result<Cert> {
    // TODO: should respect more fields in config
    let (cert, _revocation) = openpgp::cert::CertBuilder::new()
        .add_userid(config.userid.clone())
        .add_signing_subkey()
        .generate()?;
    Ok(cert)
}

pub fn sign(tsk: &Cert, payload: &[u8]) -> Result<Vec<u8>, SharkSignError> {
    let policy = &StandardPolicy::new();
    let keypair = tsk
        .keys().unencrypted_secret()
        .with_policy(policy, None).alive().revoked(false).for_signing()
        .nth(0).unwrap().key().clone().into_keypair()?;

    let mut sink = Vec::<u8>::new();
    let message = Message::new(&mut sink);
    let message = Armorer::new(message).kind(armor::Kind::Signature).build()?;
    let mut message = Signer::new(message, keypair).detached().build()?;

    message.write_all(payload)?;
    message.finalize()?;

    Ok(sink)
}

pub fn encrypt(cert: &Cert, payload: &[u8]) -> Result<Encrypted, SharkSignError> {
    /* set encryption policy and keys */
    let policy = &StandardPolicy::new();
    let recipients = cert.keys()
        .with_policy(policy, None)
        .supported().alive().revoked(false)
        .for_transport_encryption();

    /* build up the encryption pipeline */
    let mut ciphertext = Vec::new();
    let message = Message::new(&mut ciphertext);
    let message = Armorer::new(message).kind(armor::Kind::Message).build()?;
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

pub mod verify {
    extern crate sequoia_openpgp as openpgp;
    use super::Cert;
    use openpgp::parse::stream::{DetachedVerifierBuilder, VerificationHelper, MessageStructure, MessageLayer};
    use openpgp::parse::Parse;
    use openpgp::policy::StandardPolicy;
    use super::super::error::{SharkSignError};

    pub fn verify(sender: &Cert, payload: &[u8], signature: &[u8]) -> Result<(), SharkSignError> {
        let policy = &StandardPolicy::new();

        let helper = Helper {
            cert: sender,
        };

        let mut verifier = DetachedVerifierBuilder::from_bytes(signature)?
            .with_policy(policy, None, helper)?;

        Ok(verifier.verify_bytes(payload)?)
    }

    struct Helper<'a> {
        cert: &'a Cert,
    }

    impl<'a> VerificationHelper for Helper<'a> {
        fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<Cert>> {
            Ok(vec![self.cert.clone()])
        }

        fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
            let mut good = false;
            for (i, layer) in structure.into_iter().enumerate() {
                 match (i, layer) {
                     (0, MessageLayer::SignatureGroup { results }) => {
                         match results.into_iter().next() {
                             Some(Ok(_)) =>
                                 good = true,
                             Some(Err(e)) =>
                                 return Err(openpgp::Error::from(e).into()),
                             None =>
                                 return Err(anyhow::anyhow!("No signature")),
                         }
                     },
                     _ => return Err(anyhow::anyhow!("Unexpected message structure")),
                 }
            }

            if good {
                Ok(())
            } else {
                Err(anyhow::anyhow!("Signature verification failed"))
            }
        }
    }
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
    use openpgp::parse::Parse;
    use openpgp::types::*;
    use openpgp::crypto::SessionKey;
    

    pub fn decrypt(tsk: &Cert, encrypted: &Encrypted) -> Result<Vec<u8>, SharkSignError> {
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
        secret: &'a Cert,
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
        fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<Cert>> {
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
    use openpgp::parse::Parse;

    #[test]
    fn generate_cert_export_import() {
        let td = test_data::load_test_data_3_5();
        
        let cert = generate(&td.config).unwrap();
        let armor = cert.armored().to_vec().unwrap();
        openpgp::cert::Cert::from_reader(armor.as_slice()).unwrap();
    }

    #[test]
    fn test_encrypt() {
        // TODO: tests at this level should probably be more generic --
        // should be encrypting basic data and leaving shares and such
        // to tests in other modules
        let td = test_data::load_test_data_3_5();

        let cert = &td.approvers_pub()[0];
        let share_bytes = &td.decrypted_shares()[0].data;
        let tsk = &td.approvers_priv()[0];

        let ciphertext = encrypt(cert, share_bytes).unwrap();
        let decrypted = decrypt::decrypt(tsk, &ciphertext).unwrap();

        // first byte of sharks shares is the x-intercept, always cardinally
        // numbered, so the first share will have a first byte of 0x01
        assert_eq!(0x01, decrypted[0]);
    }

    #[test]
    fn test_sign_verify() {
        let td = test_data::load_test_data_3_5();
        let tsk = &td.approvers_priv()[0];
        let cert = &td.approvers_pub()[0];
        let payload = &"Sign me!".as_bytes();

        let signature = sign(tsk, payload).unwrap();
        verify::verify(cert, payload, &signature).unwrap();
    }
}
