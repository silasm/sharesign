use std::hash::Hash;
use std::convert::TryFrom;
use serde::{Serialize,Deserialize};

use super::error::SharkSignError;
use super::pgp::Cert;

pub mod serde_cert {
    use std::fmt;
    use std::hash::{Hash, Hasher};
    use std::ops::Deref;
    use sequoia_openpgp::Cert;
    use sequoia_openpgp::parse::Parse;
    use sequoia_openpgp::serialize::SerializeInto;
    use serde::{Serialize, Deserialize, Serializer, Deserializer};
    use serde::de;

    struct AsciiArmoredCert;
    #[derive(Clone)]
    pub struct CertDef(Cert);

    impl  Hash for CertDef {
        fn hash<H: Hasher>(&self, state: &mut H) {
            let CertDef(cert) = self;
            cert.armored().to_vec().unwrap().hash(state);
        }
    }

    impl  Serialize for CertDef {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let CertDef(cert) = self;
            match cert.armored().to_vec() {
                Ok(vec) => match String::from_utf8(vec) {
                    Ok(string) => serializer.serialize_str(&string),
                    Err(_) => panic!("armored cert failed to convert to utf8!"),
                },
                Err(_) => panic!("failed to serialize cert to vec!"),
            }
        }
    }

    impl <'de> de::Visitor<'de> for AsciiArmoredCert {
        type Value = Cert;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "an ascii-armored PGP cert")
        }

        fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
        where
            E: de::Error
        {
            match Cert::from_reader(s.as_bytes()) {
                Ok(cert) => Ok(cert),
                Err(_) => Err(de::Error::invalid_value(de::Unexpected::Str(s), &self))
            }
        }
    }

    impl <'de> Deserialize<'de> for CertDef {
        fn deserialize<D>(deserializer: D) -> Result<CertDef, D::Error>
        where
            D: Deserializer<'de>,
        {
            Ok(CertDef(deserializer.deserialize_str(AsciiArmoredCert)?))
        }
    }

    impl From<Cert> for CertDef {
        fn from(result: Cert) -> CertDef {
            CertDef(result)
        }
    }

    impl Deref for CertDef {
        type Target = Cert;
        fn deref(&self) -> &Self::Target {
            let CertDef(cert) = self;
            cert
        }
    }
}

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
    Rsa,
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
    approvers: Vec<serde_cert::CertDef>,
    signature: Vec<u8>,
}

impl Signature {
    #[allow(dead_code)]
    pub fn new(approvers: Vec<Cert>, signature: &[u8]) -> Self {
        Signature {
            approvers: approvers.into_iter().map(|x| x.into()).collect(),
            signature: Vec::from(signature),
        }
    }

    #[allow(dead_code)]
    pub fn approvers(&self) -> Vec<&Cert> {
        self.approvers.iter().map(|x| &**x).collect()
    }
}

#[derive(Serialize, Deserialize, Hash, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PubKey {
    pub kind: KeyKind,
    pub pem: String,
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
    pub shares_required: u8,
    approvers: Vec<serde_cert::CertDef>,
}

impl KeyGenRequest {
    #[allow(dead_code)]
    pub fn new(config: KeyConfig, approvers: Vec<Cert>, required: u8) -> Self {
        KeyGenRequest {
            key_config: config,
            approvers: approvers.into_iter().map(|x| x.into()).collect(),
            shares_required: required,
        }
    }

    pub fn approvers(&self) -> Vec<&Cert> {
        self.approvers.iter().map(|x| &**x).collect()
    }
}

#[derive(Serialize, Deserialize, Clone, Hash)]
#[serde(rename_all = "camelCase")]
pub struct Encrypted {
    pub data: String,
    pub pubkey: KeyRef,
}
