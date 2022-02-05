//! Contains "objects" relating to server state. These are mainly
//! distinct from the "data" module in that they contain extra logic
//! beyond construction/conversion to enforce state invariants.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::convert::TryFrom;
use std::collections::HashMap;
use serde::{Serialize, Serializer, Deserialize};
use serde::ser::SerializeStruct;

use super::data::{KeyConfig, Share, GeneratedKey, Signature, SignRequestSubmit, ArmoredCert, KeyID, DistributedShare, Confirm};
use super::error::SharkSignError as SSE;
use sequoia_openpgp::Cert;

// TODO
pub fn now() -> u64 {
    0
}

// TODO
pub fn default_expire() -> u64 {
    0
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GeneratedShare {
    distribute: DistributedShare,
    confirm: Confirm,
}

#[derive(Clone)]
pub struct SignRequest {
    payload: Vec<u8>,
    pub key_config: KeyConfig,
    pub pubkey: Option<Cert>,
    shares_submitted: Vec<Share>,
    signature: Option<Signature>,
    ctime: u64, // should be a datetime object
    expires: u64, // should be a datetime object
}

impl Serialize for SignRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SignRequest", 7)?;
        state.serialize_field("payload", &self.payload)?;
        state.serialize_field("keyConfig", &self.key_config)?;
        if let Some(pubkey) = &self.pubkey {
            match ArmoredCert::try_from(pubkey) {
                Ok(cert) => state.serialize_field("pubkey", &cert)?,
                Err(e) => return Err(serde::ser::Error::custom(format!("{:?}", e))),
            };
        }
        // do not serialize unencrypted shares
        if let Some(signature) = &self.signature {
            state.serialize_field("signature", &signature)?;
        }
        state.serialize_field("ctime", &self.ctime)?;
        state.serialize_field("expires", &self.expires)?;
        state.end()
    }
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
                share.data(pubkey)?;
            },
            None => (),
        };
        self.shares_submitted.push(share);
        Ok(())
    }
}

pub struct State {
    pub sign_requests: Mutex<HashMap<ID, SignRequest>>,
    pub key_gen_requests: Mutex<HashMap<KeyID, GeneratedKey>>,
}

impl Default for State {
    fn default() -> State {
        State {
            sign_requests: Mutex::new(HashMap::<ID, SignRequest>::new()),
            key_gen_requests: Mutex::new(HashMap::<KeyID, GeneratedKey>::new()),
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
            pubkey: Some(td.generated.pubkey),
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
