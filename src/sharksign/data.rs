use std::hash::Hash;
use std::convert::TryFrom;
use serde::{Serialize,Deserialize};

use super::error::SharkSignError;

#[derive(Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct Share {
    pub data: Vec<u8>,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Clone, Hash)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedShare {
    pub encrypted: Encrypted,
    pub signature: String,
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

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Hash)]
pub enum MessageDigest {
    SHA256,
    Unknown, // just to get rid of "impossible match" warnings
}

// configuration for generating a key
#[derive(Serialize, Deserialize, Hash, Clone)]
#[serde(rename_all = "camelCase")]
pub struct KeyConfig {
    pub kind: KeyKind,
    pub userid: String,
    pub size: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub digest: Option<MessageDigest>,
}

// publishable results of generating a key
#[derive(Serialize, Hash, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedKey {
    pub pubkey: PubKey,
    pub config: KeyConfig,
    pub shares: Vec<EncryptedShare>,
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

#[derive(Serialize, Deserialize, Clone, Hash)]
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

#[derive(Serialize, Deserialize, Clone, Hash)]
#[serde(rename_all = "camelCase")]
pub struct Encrypted {
    pub data: String,
    pub pubkey: KeyRef,
}
