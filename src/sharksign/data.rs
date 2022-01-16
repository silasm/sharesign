use std::fmt;
use std::hash::{Hash, Hasher};
use std::convert::{TryInto, TryFrom};
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use serde::de::{self, Visitor, SeqAccess, MapAccess, Unexpected};
use serde::ser::SerializeStruct;
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::parse::Parse;

use super::error::SharkSignError as SSE;
use super::pgp::Cert;
use super::pgp;


#[derive(Serialize, Deserialize, Hash, Clone)]
pub struct ArmoredCert(String);

impl TryFrom<&Cert> for ArmoredCert {
    type Error = SSE;
    fn try_from(result: &Cert) -> Result<ArmoredCert, Self::Error> {
        match result.armored().to_vec() {
            Ok(vec_cert) => match String::from_utf8(vec_cert) {
                Ok(string) => Ok(ArmoredCert(string)),
                Err(e) => {
                    let message = format!("armored text is not utf-8: {:?}", e);
                    Err(SSE::Unexpected(message))
                },
            },
            Err(e) => {
                let message = format!("couldn't convert cert to vec: {:?}", e);
                Err(SSE::Unexpected(message))
            },
        }
    }
}

impl TryFrom<ArmoredCert> for Cert {
    type Error = SSE;
    fn try_from(result: ArmoredCert) -> Result<Cert, Self::Error> {
        let ArmoredCert(string) = result;
        Ok(Cert::from_reader(string.as_bytes())?)
    }
}

pub mod serde_vec_cert {
    use std::fmt;
    use std::convert::TryFrom;
    use sequoia_openpgp::Cert;
    use sequoia_openpgp::parse::Parse;
    use serde::{Serializer, Deserializer};
    use serde::de::{Visitor, SeqAccess, Error, Unexpected};
    use serde::ser::{self, SerializeSeq};

    use super::ArmoredCert;

    pub fn serialize<S>(vec: &[Cert], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(vec.len()))?;
        for cert in vec {
            match ArmoredCert::try_from(cert) {
                Ok(cd) => seq.serialize_element(&cd)?,
                Err(e) => return Err(ser::Error::custom(format!("{:?}", e))),
            };
        }
        seq.end()
    }

    struct AsciiArmoredCertVec;
    impl <'de> Visitor<'de> for AsciiArmoredCertVec {
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
        deserializer.deserialize_seq(AsciiArmoredCertVec)
    }

}

#[derive(Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct Share {
    data: Vec<u8>,
}

impl Share {
    pub fn data(&self, verify: &Cert) -> Result<sharks::Share,SSE> {
        let bytes = pgp::verify::verify_attached(verify, &self.data)?;
        match bytes.as_slice().try_into() {
            Ok(share) => Ok(share),
            Err(str) => Err(SSE::Unexpected(str.to_owned())),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Hash)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedShare {
    encrypted: Encrypted,
}

impl EncryptedShare {
    pub fn new(data: sharks::Share, sign: &Cert, encrypt: &Cert) -> Result<EncryptedShare, SSE> {
        let signed = pgp::sign(sign, &Vec::from(&data), true)?;
        let encrypted = pgp::encrypt(encrypt, &signed)?;
        Ok(EncryptedShare {
            encrypted,
        })
    }

    #[cfg(test)]
    pub fn decrypt(self, decrypt: &Cert) -> Result<Share, SSE> {
        Ok(Share {
            data: pgp::decrypt::decrypt(decrypt, &self.encrypted)?,
        })
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
#[derive(Clone)]
pub struct GeneratedKey {
    pub pubkey: Cert,
    pub config: KeyConfig,
    pub shares: Vec<EncryptedShare>,
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

#[derive(Clone)]
pub struct SignRequestSubmit {
    pub payload: Vec<u8>,
    pub key_config: KeyConfig,
    pub expires: Option<u64>,
    pub pubkey: Option<Cert>,
}

impl Hash for SignRequestSubmit {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.payload.hash(state);
        self.key_config.hash(state);
        self.expires.hash(state);
        match &self.pubkey {
            Some(key) => ArmoredCert::try_from(key).unwrap().hash(state),
            None => (),
        };
    }
}

impl<'de> Deserialize<'de> for SignRequestSubmit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "camelCase")]
        enum Field { Payload, KeyConfig, Expires, Pubkey }
    
        struct SignRequestSubmitVisitor;
        impl<'de> Visitor<'de> for SignRequestSubmitVisitor {
            type Value = SignRequestSubmit;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct SignRequestSubmit")
            }
    
            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let payload = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let key_config = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let expires = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;
                let s: String = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(3, &self))?;
                let pubkey = match Cert::try_from(ArmoredCert(s.clone())) {
                    Ok(cert) => Some(cert),
                    Err(_) => return Err(
                        de::Error::invalid_value(Unexpected::Str(&s), &self)
                    ),
                };
                Ok(SignRequestSubmit { payload, key_config, expires, pubkey })
            }
    
            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut payload = None;
                let mut key_config = None;
                let mut expires = None;
                let mut pubkey = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Payload => {
                            if payload.is_some() {
                                return Err(de::Error::duplicate_field("payload"))
                            }
                            payload = Some(map.next_value()?);
                        }
                        Field::KeyConfig => {
                            if payload.is_some() {
                                return Err(de::Error::duplicate_field("keyConfig"))
                            }
                            key_config = Some(map.next_value()?);
                        }
                        Field::Expires => {
                            if payload.is_some() {
                                return Err(de::Error::duplicate_field("expires"))
                            }
                            expires = Some(map.next_value()?);
                        }
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
                    }
                }
                let payload = payload.ok_or_else(
                    || de::Error::missing_field("payload"))?;
                let key_config = key_config.ok_or_else(
                    || de::Error::missing_field("keyConfig"))?;
                Ok(SignRequestSubmit { payload, key_config, expires, pubkey })
            }
        }
    
        const FIELDS: &[&str] = &["payload", "keyConfig", "expires", "pubkey"];
        deserializer.deserialize_struct("GeneratedKey", FIELDS, SignRequestSubmitVisitor)
    }
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

impl From<&Cert> for PubKey {
    fn from(result: &Cert) -> PubKey {
        let ArmoredCert(pem) = ArmoredCert::try_from(result).unwrap();
        PubKey {
            kind: KeyKind::Rsa,
            pem,
        }
    }
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
            ArmoredCert::try_from(cert).unwrap().hash(state);
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Hash)]
#[serde(rename_all = "camelCase")]
pub struct Encrypted {
    pub data: String,
    pub pubkey: KeyRef,
}

#[cfg(test)]
mod tests {
    use super::super::test_data;

    #[test]
    fn test_decrypt_and_verify_share() {
        let td = test_data::load_test_data_3_5();

        let encrypted_share = td.generated.shares[0].clone();
        println!("encrypted: {}", encrypted_share.encrypted.data);

        let decrypted = encrypted_share.decrypt(&td.approvers_priv()[0]).unwrap();
        println!("decrypted: {}", String::from_utf8_lossy(&decrypted.data));

        let verifier = td.generated.pubkey;
        let verified = decrypted.data(&verifier).unwrap();
        println!("verified: {}", String::from_utf8_lossy(&Vec::from(&verified)));
    }
}
