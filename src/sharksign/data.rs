use std::hash::{Hash, Hasher};
use std::convert::TryFrom;
use serde::{Serialize,Deserialize};
use sequoia_openpgp::serialize::SerializeInto;

use super::error::SharkSignError;
use super::pgp::Cert;

pub mod serde_vec_cert {
    use std::fmt;
    use sequoia_openpgp::Cert;
    use sequoia_openpgp::parse::Parse;
    use sequoia_openpgp::serialize::SerializeInto;
    use serde::{Serializer, Deserializer};
    use serde::de::{Visitor, SeqAccess, Error, Unexpected};
    use serde::ser::SerializeSeq;

    pub fn serialize<S>(vec: &[Cert], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(vec.len()))?;
        for cert in vec {
            match cert.armored().to_vec() {
                Ok(vec_cert) => match String::from_utf8(vec_cert) {
                    Ok(string) => seq.serialize_element(&string)?,
                    Err(e) => panic!("armored text is not utf-8: {:?}", e),
                },
                Err(e) => panic!("couldn't convert cert to vec: {:?}", e),
            };
        }
        seq.end()
    }

    struct AsciiArmoredCert;
    impl <'de> Visitor<'de> for AsciiArmoredCert {
        type Value = Vec<Cert>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "an ascii-armored PGP cert")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>
        {
            let mut vec = Vec::<Cert>::with_capacity(seq.size_hint().unwrap_or(0));

            while let Some(s) = seq.next_element::<String>()? {
                match Cert::from_reader(s.as_bytes()) {
                    Ok(cert) => vec.push(cert),
                    Err(_) => return Err(Error::invalid_value(Unexpected::Str(&s), &self)),
                };
            };
            Ok(vec)
        }
    }

    pub fn deserialize<'de,D>(deserializer: D) -> Result<Vec<Cert>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(AsciiArmoredCert)
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
    #[serde(with = "serde_vec_cert")]
    pub approvers: Vec<Cert>,
    pub signature: Vec<u8>,
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

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyGenRequest {
    pub key_config: KeyConfig,
    pub shares_required: u8,
    #[serde(with = "serde_vec_cert")]
    pub approvers: Vec<Cert>,
}

impl Hash for KeyGenRequest {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key_config.hash(state);
        self.shares_required.hash(state);
        for cert in &self.approvers {
            let vec = cert.to_vec().unwrap();
            vec.hash(state);
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Hash)]
#[serde(rename_all = "camelCase")]
pub struct Encrypted {
    pub data: String,
    pub pubkey: KeyRef,
}
