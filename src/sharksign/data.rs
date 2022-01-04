use std::hash::Hash;
use std::convert::{TryFrom, TryInto};
use serde::{Serialize,Deserialize};

use super::error::SharkSignError;

#[derive(Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct Share {
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedShare {
    pub encrypted: Encrypted,
    pub signature: Vec<u8>,
}

impl TryFrom<&Share> for sharks::Share {
    type Error = SharkSignError;
    fn try_from(value: &Share) -> Result<sharks::Share, SharkSignError> {
        Ok(sharks::Share::try_from(value.data.as_slice())?)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Hash)]
pub enum KeyKind {
    RSA,
    Unknown, // just to get rid of "impossible match" warnings
}

impl TryFrom<openssl::pkey::Id> for KeyKind {
    type Error = SharkSignError;
    fn try_from(value: openssl::pkey::Id) -> Result<KeyKind, SharkSignError> {
        match value {
            openssl::pkey::Id::RSA => Ok(KeyKind::RSA),
            _ => Err(format!("openssl key kind {:?} not supported by sharksign", value))?
        }
    }
}

impl TryFrom<KeyKind> for openssl::pkey::Id {
    type Error = SharkSignError;
    fn try_from(value: KeyKind) -> Result<openssl::pkey::Id, SharkSignError> {
        match value {
            KeyKind::RSA => Ok(openssl::pkey::Id::RSA),
            _ => Err(format!("sharksign key kind {:?} not supported for openssl backend", value))?
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Hash)]
pub enum MessageDigest {
    SHA256,
    Unknown, // just to get rid of "impossible match" warnings
}

impl TryFrom<openssl::hash::MessageDigest> for MessageDigest {
    type Error = SharkSignError;
    fn try_from(value: openssl::hash::MessageDigest) -> Result<MessageDigest, SharkSignError> {
        match value.type_() {
            openssl::nid::Nid::SHA256 => Ok(MessageDigest::SHA256),
            nid => Err(format!("openssl message digest {:?} not supported by sharksign", nid))?
        }
    }
}

impl TryFrom<MessageDigest> for openssl::hash::MessageDigest {
    type Error = SharkSignError;
    fn try_from(value: MessageDigest) -> Result<openssl::hash::MessageDigest, SharkSignError> {
        match value {
            MessageDigest::SHA256 => Ok(openssl::hash::MessageDigest::sha256()),
            _ => Err(format!("sharksign message digest {:?} not supported for openssl backend", value))?
        }
    }
}

// configuration for generating a key
#[derive(Serialize, Deserialize, Hash, Clone)]
#[serde(rename_all = "camelCase")]
pub struct KeyConfig {
    pub kind: KeyKind,
    pub size: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub digest: Option<MessageDigest>,
}

#[derive(Deserialize, Hash)]
#[serde(rename_all = "camelCase")]
pub struct SignRequestSubmit {
    pub payload: Vec<u8>,
    pub key_config: KeyConfig,
    pub expires: Option<u64>,
    pub pubkey: Option<PubKey>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareSubmit {
    pub to_be_signed: Vec<u8>,
    pub share: Share,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Signature {
    approvers: Vec<Vec<u8>>,
    signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Hash, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PubKey {
    pub kind: KeyKind,
    pub pem: Vec<u8>,
}

impl<T: openssl::pkey::HasPublic> TryFrom<openssl::pkey::PKey<T>> for PubKey {
    type Error = SharkSignError;
    fn try_from(value: openssl::pkey::PKey<T>) -> Result<PubKey, SharkSignError> {
        Ok(PubKey {
            kind: value.id().try_into()?,
            pem: value.public_key_to_pem()?,
        })
    }
}

impl TryFrom<&PubKey> for openssl::pkey::PKey<openssl::pkey::Public> {
    type Error = SharkSignError;
    fn try_from(value: &PubKey) -> Result<openssl::pkey::PKey<openssl::pkey::Public>, SharkSignError> {
        Ok(openssl::pkey::PKey::<openssl::pkey::Public>::public_key_from_pem(&value.pem)?)
    }
}


#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct KeyRef {
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HashDigest {
}

#[derive(Serialize, Deserialize, Hash)]
#[serde(rename_all = "camelCase")]
pub struct KeyGenRequest {
    pub key_config: KeyConfig,
    pub approvers: Vec<String>,
    pub shares_required: u8,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Encrypted {
    pub data: String,
    pub pubkey: KeyRef,
}
