use std::hash::{Hash, Hasher};
use std::convert::TryInto;
use serde::{Serialize, Deserialize};

use super::error::SharkSignError as SSE;
use super::pgp::Cert;
use super::pgp;

pub mod cert_traits {
    use std::hash::{Hash, Hasher};
    use sequoia_openpgp::Cert;
    use sequoia_openpgp::serialize::SerializeInto;
    use serde::Serializer;

    pub fn cert_to_armored<S>(cert: &Cert) -> Result<String, S::Error>
    where
        S: Serializer
    {
        match cert.armored().to_vec() {
            Ok(vec_cert) => match String::from_utf8(vec_cert) {
                Ok(string) => Ok(string),
                Err(e) => {
                    let message = format!("armored text is not utf-8: {:?}", e);
                    Err(serde::ser::Error::custom(message))
                },
            },
            Err(e) => {
                let message = format!("couldn't convert cert to vec: {:?}", e);
                Err(serde::ser::Error::custom(message))
            },
        }
    }

    pub fn hash<H: Hasher>(cert: &Cert, state: &mut H) {
        let vec = cert.to_vec().unwrap();
        vec.hash(state);
    }
}


pub mod serde_vec_cert {
    use std::fmt;
    use sequoia_openpgp::Cert;
    use sequoia_openpgp::parse::Parse;
    use serde::{Serializer, Deserializer};
    use serde::de::{Visitor, SeqAccess, Error, Unexpected};
    use serde::ser::SerializeSeq;

    pub fn serialize<S>(vec: &[Cert], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(vec.len()))?;
        for cert in vec {
            seq.serialize_element(
                &super::cert_traits::cert_to_armored::<S>(cert)?
            )?;
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
#[derive(Serialize, Hash, Clone)]
pub struct GeneratedKey {
    pub pubkey: PubKey,
    pub config: KeyConfig,
    pub shares: Vec<EncryptedShare>,
}

#[derive(Deserialize, Hash, Clone)]
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

impl PubKey {
    #[cfg(test)]
    pub fn cert(&self) -> Result<Cert, SSE> {
        use sequoia_openpgp::parse::Parse;
        Ok(sequoia_openpgp::Cert::from_reader(self.pem.as_bytes())?)
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
            cert_traits::hash(cert, state);
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
    use sequoia_openpgp::parse::Parse;

    #[test]
    fn test_decrypt_and_verify_share() {
        let td = test_data::load_test_data_3_5();

        let encrypted_share = td.shares[0].clone();
        println!("encrypted: {}", encrypted_share.encrypted.data);

        let decrypted = encrypted_share.decrypt(&td.approvers_priv()[0]).unwrap();
        println!("decrypted: {}", String::from_utf8_lossy(&decrypted.data));

        let verifier = sequoia_openpgp::Cert::from_reader(td.pubkey.pem.as_bytes()).unwrap();
        let verified = decrypted.data(&verifier).unwrap();
        println!("verified: {}", String::from_utf8_lossy(&Vec::from(&verified)));
    }
}
