//! Contains "objects" relating to server state. These are mainly
//! distinct from the "data" module in that they contain extra logic
//! beyond construction/conversion to enforce state invariants.

use std::fmt;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::convert::TryFrom;
use std::collections::HashMap;
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use serde::ser::SerializeStruct;
use serde::de::{self, Visitor, SeqAccess, MapAccess, Unexpected};

use super::data::{KeyConfig, Share, Signature, SignRequestSubmit, ArmoredCert, KeyID, EncryptedShare, DistributedShare, Confirm};
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

// publishable results of generating a key
#[derive(Clone)]
pub struct GeneratedKey {
    pub pubkey: Cert,
    pub config: KeyConfig,
    pub shares: Vec<(EncryptedShare, Confirm)>,
}

impl Serialize for GeneratedKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("GeneratedKey", 3)?;
        match ArmoredCert::try_from(&self.pubkey) {
            Ok(cd) => state.serialize_field("pubkey", &cd)?,
            Err(e) => return Err(serde::ser::Error::custom(format!("{:?}", e))),
        };
        state.serialize_field("config", &self.config)?;
        state.serialize_field("shares", &self.shares)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for GeneratedKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field { Pubkey, Config, Shares }
    
        struct GeneratedKeyVisitor;
        impl<'de> Visitor<'de> for GeneratedKeyVisitor {
            type Value = GeneratedKey;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct GeneratedKey")
            }
    
            fn visit_seq<V>(self, mut seq: V) -> Result<GeneratedKey, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let s: String = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let pubkey = match Cert::try_from(ArmoredCert(s.clone())) {
                    Ok(cert) => cert,
                    Err(_) => return Err(
                        de::Error::invalid_value(Unexpected::Str(&s), &self)
                    ),
                };
                let config = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let shares = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;
                Ok(GeneratedKey { pubkey, config, shares })
            }
    
            fn visit_map<V>(self, mut map: V) -> Result<GeneratedKey, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut pubkey = None;
                let mut config = None;
                let mut shares = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Pubkey => {
                            if pubkey.is_some() {
                                return Err(de::Error::duplicate_field("pubkey"));
                            }
                            let s: String = map.next_value()?;
                            match Cert::try_from(ArmoredCert(s.clone())) {
                                Ok(cert) => pubkey = Some(cert),
                                Err(_) => return Err(
                                    de::Error::invalid_value(Unexpected::Str(&s), &self)
                                ),
                            };
                        },
                        Field::Config => {
                            if config.is_some() {
                                return Err(de::Error::duplicate_field("config"));
                            }
                            config = Some(map.next_value()?);
                        },
                        Field::Shares => {
                            if shares.is_some() {
                                return Err(de::Error::duplicate_field("shares"));
                            }
                            shares = Some(map.next_value()?);
                        },
                    }
                }
                let pubkey = pubkey.ok_or_else(
                    || de::Error::missing_field("pubkey"))?;
                let config = config.ok_or_else(
                    || de::Error::missing_field("config"))?;
                let shares = shares.ok_or_else(
                    || de::Error::missing_field("shares"))?;
                Ok(GeneratedKey { pubkey, config, shares })
            }
        }
    
            const FIELDS: &[&str] = &["pubkey", "config", "shares"];
        deserializer.deserialize_struct("GeneratedKey", FIELDS, GeneratedKeyVisitor)
    }
}

impl Hash for GeneratedKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        ArmoredCert::try_from(&self.pubkey).unwrap().hash(state);
        self.config.hash(state);
        self.shares.hash(state);
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
