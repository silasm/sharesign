use std::convert::TryFrom;
use serde::{Serialize,Deserialize};

use super::error::SharkSignError;

#[derive(Deserialize)]
pub struct Share {
    data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum KeyKind {
    RSA,
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

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum MessageDigest {
    SHA256,
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
#[derive(Serialize, Deserialize)]
pub struct KeyConfig {
    pub kind: KeyKind,
    pub size: u32,
    pub digest: Option<MessageDigest>,
}

#[derive(Deserialize)]
pub struct SignRequestSubmit {
    payload: Vec<u8>,
    key_config: KeyConfig,
}

pub struct SignRequest {
    payload: Vec<u8>,
    key_config: KeyConfig,
    shares_submitted: Vec<Share>,
    signature: Option<Signature>,
    ctime: u64, // should be a datetime object
    expires: u64, // should be a datetime object
}

#[derive(Deserialize)]
pub struct ShareSubmit {
    to_be_signed: Vec<u8>,
    share: Share,
}

#[derive(Serialize)]
pub struct Signature {
    approvers: Vec<Vec<u8>>,
    signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct PubKey {
}

#[derive(Serialize, Deserialize)]
pub struct KeyRef {
}

#[derive(Serialize, Deserialize)]
pub struct HashDigest {
}

#[derive(Serialize, Deserialize)]
pub struct KeyGenRequest {
    key_config: KeyConfig,
    approvers: Vec<PubKey>,
    shares_required: u8,
}
