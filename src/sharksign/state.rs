//! Contains "objects" relating to server state. These are mainly
//! distinct from the "data" module in that they contain extra logic
//! beyond construction/conversion to enforce state invariants.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::collections::HashMap;
use serde::Serialize;

use super::data::{KeyConfig, KeyKind, PubKey, Share, EncryptedShare, Signature};
use super::error::SharkSignError;

// TODO
pub fn now() -> u64 {
    0
}

// TODO
pub fn default_expire() -> u64 {
    0
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignRequest {
    payload: Vec<u8>,
    pub key_config: KeyConfig,
    #[serde(default)]
    pub pubkey: Option<PubKey>,
    #[serde(skip)]
    shares_submitted: Vec<Share>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    signature: Option<Signature>,
    #[serde(skip_deserializing)]
    #[serde(default = "now")]
    ctime: u64, // should be a datetime object
    #[serde(default = "default_expire")]
    expires: u64, // should be a datetime object
}

impl SignRequest {
    pub fn new(payload: &[u8], key_config: KeyConfig) -> Self {
        SignRequest {
            payload: Vec::<u8>::from(payload),
            key_config: key_config,
            pubkey: None,
            shares_submitted: Vec::<Share>::new(),
            signature: None,
            ctime: now(),
            expires: default_expire(),
        }
    }

    pub fn set_expiration(&mut self, expires: u64) {
        self.expires = expires;
    }

    pub fn set_pubkey(&mut self, pubkey: &PubKey) {
        self.pubkey = Some(pubkey.clone());
    }

    /// If there is a public key associated with the sign request,
    /// validate that the submitted share was signed by the
    /// corresponding private key prior to adding it. Without this,
    /// attackers can create a denial of service scenario by submitting
    /// bogus shares, which can interfere with key recovery and/or exhaust
    /// memory.
    pub fn submit_share(&mut self, share: Share) -> Result<(), SharkSignError> {
        let _validation = match &self.pubkey {
            Some(pubkey) => super::tls::verify(
                &self.key_config,
                &pubkey.pem,
                &share.data,
                &share.signature,
            )?,
            None => (),
        };
        self.shares_submitted.push(share);
        Ok(())
    }
}

pub struct State {
    pub sign_requests: Mutex<HashMap<ID, SignRequest>>,
    pub key_gen_requests: Mutex<HashMap<ID, Vec<EncryptedShare>>>,
}

impl State {
    pub fn new() -> State {
        State {
            sign_requests: Mutex::new(HashMap::<ID, SignRequest>::new()),
            key_gen_requests: Mutex::new(HashMap::<ID, Vec<EncryptedShare>>::new()),
        }
    }
}

pub type ID = u64;

pub fn get_id<T: Hash>(input: &T) -> ID{
    let mut s = DefaultHasher::new();
    input.hash(&mut s);
    // TODO: add random value here
    s.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::test_data;

    #[test]
    fn add_signed_share() {
        // TODO: config currently must magically match
        // test_data::generate_shares need to restructure static test
        // data to associate related data.
        let config = KeyConfig {
            kind: KeyKind::RSA,
            size: 2048,
            digest: None,
        };

        let pubkey = &test_data::static_pubkey();
        let share = test_data::static_shares_3_5()[0].to_owned();
        let mut req = SignRequest::new("Sign me!".as_bytes(), config);
        req.set_pubkey(pubkey);
        req.submit_share(share).unwrap();
    }

    #[test]
    fn add_bogus_share() {
        // TODO: config currently must magically match
        // test_data::generate_shares need to restructure static test
        // data to associate related data.
        let config = KeyConfig {
            kind: KeyKind::RSA,
            size: 2048,
            digest: None,
        };

        let pubkey = &test_data::static_pubkey();
        let mut share = test_data::static_shares_3_5()[0].clone();
        // zero the signature so that it fails validation
        for byte in &mut share.signature {
            *byte = 0x00;
        }
        let mut req = SignRequest::new("Sign me!".as_bytes(), config);
        req.set_pubkey(pubkey);
        assert!(req.submit_share(share).is_err());
    }
}
