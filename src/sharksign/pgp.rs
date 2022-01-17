use std::io::Write;
use std::time::Duration;
use std::convert::TryFrom;

extern crate sequoia_openpgp as openpgp;
// use openpgp::cert::prelude::*;
use openpgp::serialize::stream::*;
use openpgp::policy::StandardPolicy;
use openpgp::types::RevocationKey;
use openpgp::armor;
pub use openpgp::Cert;

use super::data::{Encrypted, KeyConfig};
use super::error::SharkSignError as SSE;

pub fn generate(config: &KeyConfig) -> Result<Cert, SSE> {
    let revoc: Vec<RevocationKey> = config.revocation_keys.iter()
        .map(RevocationKey::from).collect();
    let mut builder = openpgp::cert::CertBuilder::new()
        .set_cipher_suite(config.cipher_suite)
        .add_userid(config.userid.clone())
        .set_validity_period(Option::<Duration>::try_from(&config.validity)?)
        .set_primary_key_flags(config.key_flags())
        .set_revocation_keys(revoc);
    for subconfig in &config.subkeys {
        builder = builder.add_subkey(
            subconfig.key_flags(),
            Option::<Duration>::try_from(&subconfig.validity)?,
            subconfig.cipher_suite,
        );
    }
    // TODO: handle revocation cert somehow.  Can distribute it as a
    // separate share or bundled into the main share.
    let (cert, _rev) = builder.generate()?;
    Ok(cert)
}

pub fn sign(tsk: &Cert, payload: &[u8], attached: bool) -> Result<Vec<u8>, SSE> {
    let policy = &StandardPolicy::new();
    // clippy doesn't need to complain about sequoia's example code
    #[allow(clippy::iter_nth_zero)]
    let keypair = tsk
        .keys().unencrypted_secret()
        .with_policy(policy, None).alive().revoked(false).for_signing()
        .nth(0).unwrap().key().clone().into_keypair()?;

    let mut sink = Vec::<u8>::new();
    let message = Message::new(&mut sink);
    let message = Armorer::new(message).kind(armor::Kind::Signature).build()?;
    let mut message = if ! attached {
        Signer::new(message, keypair).detached().build()
    } else {
        let message = Signer::new(message, keypair).build()?;
        LiteralWriter::new(message).build()
    }?;

    message.write_all(payload)?;
    message.finalize()?;

    Ok(sink)
}

pub fn encrypt(cert: &Cert, payload: &[u8]) -> Result<Encrypted, SSE> {
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
    Ok(Encrypted(String::from_utf8(ciphertext).unwrap()))
}

pub mod verify {
    extern crate sequoia_openpgp as openpgp;
    use std::io;
    use super::Cert;
    use openpgp::parse::stream::{VerifierBuilder, VerificationHelper, MessageStructure, MessageLayer};
    use openpgp::parse::Parse;
    use openpgp::policy::StandardPolicy;
    use super::super::error::SharkSignError as SSE;

    #[cfg(test)]
    pub fn verify(sender: &Cert, payload: &[u8], signature: &[u8]) -> Result<(), SSE> {
        use openpgp::parse::stream::DetachedVerifierBuilder;

        let policy = &StandardPolicy::new();

        let helper = Helper {
            cert: sender,
        };

        let mut verifier = DetachedVerifierBuilder::from_bytes(signature)?
            .with_policy(policy, None, helper)?;

        Ok(verifier.verify_bytes(payload)?)
    }

    pub fn verify_attached(sender: &Cert, payload: &[u8]) -> Result<Vec<u8>, SSE> {
        let policy = &StandardPolicy::new();
        let mut sink = Vec::<u8>::new();

        let helper = Helper {
            cert: sender,
        };

        let mut verifier = VerifierBuilder::from_bytes(payload)?
            .with_policy(policy, None, helper)?;
        io::copy(&mut verifier, &mut sink)?;
        Ok(sink)
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
    

    pub fn decrypt(tsk: &Cert, encrypted: &Encrypted) -> Result<Vec<u8>, SSE> {
        let policy = openpgp::policy::StandardPolicy::new();
    
        let helper = Helper {
            policy: &policy,
            secret: &tsk,
        };
    
        let mut decryptor = DecryptorBuilder::from_bytes(&encrypted.0)?
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
    use openpgp::types::{ReasonForRevocation, RevocationStatus, SignatureType};

    /// checks that the revoker cert:
    /// 1. has its fingerprint listed in the revoked cert's revocation keys
    /// 2. has its fingerprint listed in one of the attached revocation certs
    /// 3. was in fact the one to sign the revocation
    fn confirm_revocation(maybe_revoked: &Cert, revoker: &Cert) -> Result<(), SSE> {
        let p = &StandardPolicy::new();
        let revoker_fp = revoker.fingerprint();

        // check if revoker is listed in maybe_revoked's revocation_keys
        if ! maybe_revoked.revocation_keys(p)
            .map(|x| x.revoker())
            .any(|(_, fingerprint)| *fingerprint == revoker_fp)
        {
            return Err(SSE::NotRevoker);
        }

        // get the primary public keys from both certs
        let revoker = revoker.with_policy(p, None)?
            .primary_key().key().parts_as_public();
        let revoked = maybe_revoked.with_policy(p, None)?
            .primary_key().key().parts_as_public();

        let rev_status = maybe_revoked.revocation_status(p, None);
        if let RevocationStatus::CouldBe(revs) = rev_status {
            // get all revocations possibly signed by revoker
            let mut iter = revs.iter().filter(|rev| {
                    rev.issuer_fingerprints().any(
                         |fp| *fp == revoker_fp
                    )}).peekable();

            // check the signature if there are any
            if iter.peek().is_none() {
                // no revocations found
                Err(SSE::NoRevocation)
            } else if ! iter.any(|rev| {
                let mut rev = (*rev).clone();
                rev.verify_primary_key_revocation(revoker, revoked).is_ok()
            }) {
                // some revocations found, but all failed verification
                Err(SSE::BadSignatureInRevocation)
            } else {
                // we found at least one verified revocation by revoker
                Ok(())
            }
        } else {
            Err(SSE::Unexpected("cert revocation is not in question".to_string()))
        }
    }

    #[test]
    fn generate_cert_export_import() {
        let td = test_data::load_test_data_3_5();
        
        let cert = generate(&td.generated.config).unwrap();
        let armor = cert.armored().to_vec().unwrap();
        openpgp::cert::Cert::from_reader(armor.as_slice()).unwrap();
    }

    #[test]
    fn test_revoke_with_outside_key() {
        let td = test_data::load_test_data_3_5();
        let p = &StandardPolicy::new();

        let mut config = td.generated.config.clone();
        let revoc_pub = &td.approvers_pub[0];
        config.revocation_keys.push(revoc_pub.clone());
        let compromised = generate(&config).unwrap();

        let revkeys = compromised.revocation_keys(p).collect::<Vec<&RevocationKey>>();
        println!("keys designated for revocation: {:#?}", revkeys);
        assert_eq!(revkeys, vec![&revoc_pub.into()]);

        let revoc_priv = &td.approvers_priv()[0];
        let mut revoker = revoc_priv.primary_key()
            .key().clone().parts_into_secret().unwrap()
            .into_keypair().unwrap();
        let rev = compromised.revoke(
            &mut revoker,
            ReasonForRevocation::KeyCompromised,
            b"rowhammer really sucks"
        ).unwrap();
        let compromised = compromised.insert_packets(rev).unwrap();
        // returns CouldBe for outside revocations, yielding verification
        // of both the signature and authorization (presence in
        // revocation_keys) to the caller.
        //
        // TODO: this is messy enough that it should probably be its own
        // function even if that function is only used in tests.
        if let RevocationStatus::CouldBe(revs) = compromised.revocation_status(p, None) {
            assert_eq!(revs.len(), 1);
            let rev = revs[0].clone();

            // revocation fields are what we set them to
            assert_eq!(rev.typ(), SignatureType::KeyRevocation);
            assert_eq!(rev.reason_for_revocation(),
                       Some((ReasonForRevocation::KeyCompromised,
                             "rowhammer really sucks".as_bytes())));

            // key is authorized to revoke, and signature checks out
            confirm_revocation(&compromised, &td.approvers_pub[0]).unwrap();
        }
        else {
            panic!("Unexpected revocation status: {:#?}",
                   compromised.revocation_status(p, None));
        }
    }

    #[test]
    fn test_encrypt() {
        // TODO: tests at this level should probably be more generic --
        // should be encrypting basic data and leaving shares and such
        // to tests in other modules
        let td = test_data::load_test_data_3_5();

        let cert = &td.approvers_pub[0];
        let verify = td.generated.pubkey.clone();
        let share_bytes = &td.decrypted_shares()[0].data(&verify).unwrap();
        let tsk = &td.approvers_priv()[0];

        let ciphertext = encrypt(cert, &Vec::from(share_bytes)).unwrap();
        let decrypted = decrypt::decrypt(tsk, &ciphertext).unwrap();

        // first byte of sharks shares is the x-intercept, always cardinally
        // numbered, so the first share will have a first byte of 0x01
        assert_eq!(0x01, decrypted[0]);
    }

    #[test]
    fn test_sign_verify() {
        let td = test_data::load_test_data_3_5();
        let tsk = &td.approvers_priv()[0];
        let cert = &td.approvers_pub[0];
        let payload = &"Sign me!".as_bytes();

        let signature = sign(tsk, payload, false).unwrap();
        verify::verify(cert, payload, &signature).unwrap();
    }
}
