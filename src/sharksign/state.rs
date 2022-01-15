//! Contains "objects" relating to server state. These are mainly
//! distinct from the "data" module in that they contain extra logic
//! beyond construction/conversion to enforce state invariants.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::collections::HashMap;
use serde::Serialize;

use super::data::{KeyConfig, PubKey, Share, GeneratedKey, Signature, SignRequestSubmit};
use super::error::SharkSignError as SSE;
use sequoia_openpgp::parse::Parse;

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

impl From<SignRequestSubmit> for SignRequest {
    fn from(result: SignRequestSubmit) -> Self {
        SignRequest {
            payload: result.payload,
            key_config: result.key_config,
            pubkey: result.pubkey,
            shares_submitted: Vec::<Share>::new(),
            signature: None,
            ctime: now(),
            expires: result.expires.unwrap_or_else(default_expire),
        }
    }
}

impl SignRequest {
    /// If there is a public key associated with the sign request,
    /// validate that the submitted share was signed by the
    /// corresponding private key prior to adding it. Without this,
    /// attackers can create a denial of service scenario by submitting
    /// bogus shares, which can interfere with key recovery and/or exhaust
    /// memory.
    pub fn submit_share(&mut self, share: Share) -> Result<(), SSE> {
        let _validation = match &self.pubkey {
            Some(pubkey) => {
                let cert = super::pgp::Cert::from_reader(pubkey.pem.as_bytes())?;
                share.data(&cert)?;
            },
            None => (),
        };
        self.shares_submitted.push(share);
        Ok(())
    }
}

pub struct State {
    pub sign_requests: Mutex<HashMap<ID, SignRequest>>,
    pub key_gen_requests: Mutex<HashMap<ID, GeneratedKey>>,
}

impl State {
    pub fn new() -> State {
        State {
            sign_requests: Mutex::new(HashMap::<ID, SignRequest>::new()),
            key_gen_requests: Mutex::new(HashMap::<ID, GeneratedKey>::new()),
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
        let td = test_data::load_test_data_3_5();

        let share = td.decrypted_shares()[0].clone();
        let submit = SignRequestSubmit {
            payload: Vec::from("Sign me!".as_bytes()),
            key_config: td.generated.config,
            expires: None,
            pubkey: Some(PubKey::from(&td.generated.pubkey)),
        };
        let mut req = SignRequest::from(submit);
        req.submit_share(share).unwrap();
    }

    /*
    #[test]
    fn add_bogus_signature_share() {
        let td = test_data::load_test_data_3_5();

        let mut share = td.decrypted_shares()[0].clone();
        // zero the signature so that it fails validation
        // unsafe: because overwriting bytes in a string; zeroing the whole
        // thing will yield valid utf8 so this is not a concern.
        unsafe {
            for byte in &mut share.signature.as_bytes_mut().iter_mut() {
                *byte = 0x00;
            }
        }
        let mut req = SignRequest::new("Sign me!".as_bytes(), td.config);
        req.set_pubkey(&td.pubkey);
        assert!(req.submit_share(share).is_err());
    }
    */
}
