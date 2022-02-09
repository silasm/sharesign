use std::fmt;
use std::hash::{Hash, Hasher};
use std::convert::{TryInto, TryFrom};
use std::ops::Deref;
use std::time::{Duration, SystemTime};
use rand::Rng;

use serde::{Serialize, Deserialize, Serializer, Deserializer};
use serde::de::{self, Visitor, SeqAccess, MapAccess, Unexpected};
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::parse::Parse;

pub use sequoia_openpgp::cert::prelude::CipherSuite;
pub use sequoia_openpgp::types::KeyFlags;
pub use sequoia_openpgp::Cert;
use sequoia_openpgp::{Packet, Message};

use super::error::SharkSignError as SSE;
use super::pgp;


#[derive(Serialize, Deserialize, Hash, Clone)]
pub struct ArmoredCert(pub String);

impl TryFrom<&Cert> for ArmoredCert {
    type Error = SSE;
    fn try_from(result: &Cert) -> Result<ArmoredCert, Self::Error> {
        match result.armored().to_vec() {
            Ok(vec_cert) => Ok(ArmoredCert(String::from_utf8(vec_cert)?)),
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
            write!(formatter, "a sequence of ascii-armored PGP certs")
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

static SHARE_MAGIC: [u8; 5] = [0x50, 0xa2, 0xe5, 0x19, 0x11];

#[derive(Deserialize, Serialize, Clone, Default, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Share {
    data: String,
}

impl Share {
    pub fn data(&self, verify: &Cert) -> Result<sharks::Share,SSE> {
        let bytes = pgp::verify::verify_attached(verify, self.data.as_bytes())?;
        if bytes[0..=SHARE_MAGIC.len()].iter().zip(&SHARE_MAGIC).any(|(x,y)| x!=y) {
            Err(SSE::BadMagic(bytes))
        }
        else {
            match bytes[SHARE_MAGIC.len()..].try_into() {
                Ok(share) => Ok(share),
                Err(str) => Err(SSE::Unexpected(str.to_owned())),
            }
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct DistributedShare {
    pub confirm_receipt: Confirm,
    pub signed: Share,
}

impl From<DistributedShare> for Share {
    fn from(result: DistributedShare) -> Self {
        result.signed
    }
}

/// Wrapper type for 8 random bytes injected into the encrypted
/// but unsigned part of a distributed share, that the shareholder
/// can resubmit to confirm receipt of the share, allowing the server
/// to remove the encrypted share from memory
#[derive(Serialize, Deserialize, Clone, Hash, Debug, PartialEq, Eq)]
pub struct Confirm(
    #[serde(with = "hex")]
    [u8; 6]
);

impl Default for Confirm {
    fn default() -> Confirm {
        let mut rng = rand::thread_rng();
        Confirm::from_rng(&mut rng)
    }
}

impl Deref for Confirm {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Confirm {
    fn from_rng<T: Rng>(rng: &mut T) -> Confirm {
        let mut bytes = [0u8; 6];
        for p in &mut bytes {
            *p = rng.gen();
        }
        Confirm(bytes)
    }
}

#[derive(Serialize, Deserialize, Clone, Hash)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedShare(Encrypted);

impl Deref for EncryptedShare {
    type Target = Encrypted;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl EncryptedShare {
    pub fn new(data: sharks::Share, sign: &Cert, encrypt: &Cert, confirm_receipt: Confirm) -> Result<EncryptedShare, SSE> {
        // TODO: confirm/enforce no-realloc here, once we get around to
        // properly zeroing secrets (shares/privkeys)
        let share_bytes = Vec::from(&data);

        // append magic string for server-side verification that this
        // isn't a random signed message
        let mut with_magic: Vec<u8> = SHARE_MAGIC.to_vec();
        with_magic.extend(share_bytes);

        let signed = Share {
            data: String::from_utf8(pgp::sign(sign, &with_magic, true)?)?,
        };

        // attach a random string in the encrypted (but not signed) part of
        // the message, which the client will resubmit to confirm receipt
        // of the newly-generated share, at which point it can be deleted
        // from the server's memory
        // TODO: randomize
        let distrib = DistributedShare { confirm_receipt, signed };

        let json = serde_json::to_string(&distrib).unwrap();
        let encrypted = pgp::encrypt(encrypt, json.as_bytes())?;
        Ok(EncryptedShare(encrypted))
    }

    pub fn decrypt(self, decrypt: &Cert) -> Result<DistributedShare, SSE> {
        let decrypted = String::from_utf8(self.0.decrypt(decrypt)?)?;
        Ok(serde_json::from_str(&decrypted).unwrap())
    }
}

#[derive(Debug, Clone)]
pub struct Fingerprint(Vec<u8>);


#[derive(Clone, Copy, Debug, Serialize, Deserialize, Hash)]
pub enum KeyKind {
    Rsa,
    Unknown, // just to get rid of "impossible match" warnings
}

/// Flags that can be set when generating a key or subkey
#[derive(Serialize, Deserialize, Hash, Clone)]
#[serde(rename_all = "camelCase")]
pub enum KeyFlag {
    /// Private key can be used to sign other keys
    Certification,
    /// Private key can be used to sign data
    Signing,
    /// Public key can be used to encrypt messages for transport
    TransportEncryption,
    /// Public key can be used to encrypt data for storage (e.g. backups)
    StorageEncryption,
    /// Private key can be used to authenticate to other systems
    Authentication,
    /// Private key may be split using a sharing scheme (e.g. sharesign itself)
    Split,
    /// Private key may be owned in full by more than one individual
    Group,
}

fn convert_flags(named: &[KeyFlag]) -> KeyFlags {
    let mut flags = KeyFlags::empty();
    for flag in named {
        match flag {
            KeyFlag::Certification => flags = flags.set_certification(),
            KeyFlag::Signing => flags = flags.set_signing(),
            KeyFlag::TransportEncryption => flags = flags.set_transport_encryption(),
            KeyFlag::StorageEncryption => flags = flags.set_storage_encryption(),
            KeyFlag::Authentication => flags = flags.set_authentication(),
            KeyFlag::Split => flags = flags.set_split_key(),
            KeyFlag::Group => flags = flags.set_group_key(),
        }
    }
    flags
}

/// How long before the key expires, if it expires at all.
///
/// Can be sent as For(Duration) but will be immediately converted to
/// Until(SystemTime) for consistent display. Note that PGP certs don't
/// track time especially precisely, so e.g. nanosecond specifications
/// will be dropped by sequoia.
#[derive(Serialize, Deserialize, Hash, Clone)]
#[serde(rename_all = "camelCase")]
pub enum Validity {
    /// The key does not expire
    DoesNotExpire,
    /// The key expires after creation time + duration
    For(Duration),
    /// The key expires at a particular point in time
    Until(SystemTime),
}

impl TryFrom<&Validity> for Option<Duration> {
    type Error = SSE;
    fn try_from(result: &Validity) -> Result<Option<Duration>, SSE> {
        match result {
            Validity::DoesNotExpire => Ok(None),
            Validity::For(d) => Ok(Some(*d)),
            Validity::Until(t) => match t.duration_since(SystemTime::now()) {
                Ok(d) => Ok(Some(d)),
                Err(e) => Err(SSE::Config(format!("got negative duration validity: {:?}", e))),
            },
        }
    }
}

/// shim to derive for remote CipherSuite type
#[derive(Serialize, Deserialize, Hash)]
#[serde(remote = "CipherSuite")]
enum CipherSuiteDef {
    Cv25519,
    RSA3k,
    P256,
    P384,
    P521,
    RSA2k,
    RSA4k,
}

// convenient for impl Hash below
impl From<CipherSuite> for CipherSuiteDef {
    fn from(result: CipherSuite) -> CipherSuiteDef {
        match result {
            CipherSuite::Cv25519 => CipherSuiteDef::Cv25519,
            CipherSuite::RSA3k => CipherSuiteDef::RSA3k,
            CipherSuite::P256 => CipherSuiteDef::P256,
            CipherSuite::P384 => CipherSuiteDef::P384,
            CipherSuite::P521 => CipherSuiteDef::P521,
            CipherSuite::RSA2k => CipherSuiteDef::RSA2k,
            CipherSuite::RSA4k => CipherSuiteDef::RSA4k,
        }
    }
}

/// Configuration for generating a subkey
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SubkeyConfig {
    #[serde(with = "CipherSuiteDef")]
    pub cipher_suite: CipherSuite,
    pub flags: Vec<KeyFlag>,
    pub validity: Validity,
}

impl Hash for SubkeyConfig {
    fn hash<H: Hasher>(&self, state: &mut H) {
        CipherSuiteDef::from(self.cipher_suite).hash(state);
        self.flags.hash(state);
        self.validity.hash(state);
    }
}

impl SubkeyConfig {
    pub fn key_flags(&self) -> KeyFlags {
        convert_flags(&self.flags)
    }
}

/// Configuration for generating a primary key and subkeys
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct KeyConfig {
    #[serde(with = "CipherSuiteDef")]
    pub cipher_suite: CipherSuite,
    pub subkeys: Vec<SubkeyConfig>,
    pub flags: Vec<KeyFlag>,
    pub validity: Validity,
    pub userid: String,
    #[serde(with="serde_vec_cert")]
    pub revocation_keys: Vec<Cert>,
}

impl Hash for KeyConfig {
    fn hash<H: Hasher>(&self, state: &mut H) {
        CipherSuiteDef::from(self.cipher_suite).hash(state);
        self.subkeys.hash(state);
        self.flags.hash(state);
        self.validity.hash(state);
        self.userid.hash(state);
    }
}

impl KeyConfig {
    pub fn key_flags(&self) -> KeyFlags {
        convert_flags(&self.flags)
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

#[derive(Deserialize, Clone)]
pub struct KeyRef {}

#[derive(Deserialize, Clone)]
pub struct HashDigest {}

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

// newtype for custom trait impls
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyID(pub sequoia_openpgp::KeyID);
impl Deref for KeyID {
    type Target = sequoia_openpgp::KeyID;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for KeyID {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for KeyID {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>
    {
        struct KeyIDVisitor;
        impl<'de> Visitor<'de> for KeyIDVisitor {
            type Value = KeyID;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an openPGP key ID as a hex string")
            }
    
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> where
                E: serde::de::Error
            {
                match sequoia_openpgp::KeyID::from_hex(v) {
                    Ok(id) => Ok(KeyID(id)),
                    Err(_) => Err(de::Error::invalid_value(Unexpected::Str(v), &self)),
                }
            }
        }
    
        deserializer.deserialize_str(KeyIDVisitor)
    }

}

#[derive(Serialize, Deserialize, Clone, Hash)]
#[serde(rename_all = "camelCase")]
pub struct Encrypted(pub String);

impl Encrypted {
    pub fn decrypt(self, decrypt: &Cert) -> Result<Vec<u8>, SSE> {
        pgp::decrypt::decrypt(decrypt, &self)
    }

    pub fn recipients(&self) -> Result<Vec<KeyID>, SSE> {
        // coercing into a message this way is unsafe for untrusted data.
        // as of writing this we're only running this on messages we've
        // generated ourselves.
        let msg = Message::from_reader(self.0.as_bytes())?;
        // for each top-level PKESK packet, return the KeyID of the
        // recipient, and collate into a Vec.
        Ok(msg.descendants().flat_map(|x| match x {
            Packet::PKESK(pkesk) => Some(KeyID(pkesk.recipient().clone())),
            _ => None,
        }).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_data;
    use super::*;
    use sequoia_openpgp::{Packet, KeyID};
    use sequoia_openpgp::policy::StandardPolicy;

    #[test]
    fn test_decrypt_and_verify_share() {
        let td = test_data::load_test_data_3_5();

        let (encrypted_share, _) = td.generated.shares[0].clone();
        println!("encrypted: {}", encrypted_share.0.0);

        let decrypted = encrypted_share.decrypt(&td.approvers_priv()[0]).unwrap();
        println!("decrypted: {:#?}", &decrypted);

        let verifier = td.generated.pubkey;
        let verified = Share::from(decrypted).data(&verifier).unwrap();
        println!("verified: {}", String::from_utf8_lossy(&Vec::from(&verified)));
    }

    #[test]
    fn test_packet_parser() {
        let cert = test_data::load_test_data_3_5().approvers_pub[0].clone();
        let policy = StandardPolicy::new();

        let msg = pgp::encrypt(&cert, "encrypt me!".as_bytes()).unwrap();
        let msg = Message::from_reader(msg.0.as_bytes()).unwrap();
        let msg_recipients: Vec<&KeyID> = msg.descendants().flat_map(|x| match x {
            Packet::PKESK(pkesk) => Some(pkesk.recipient()),
            _ => None,
        }).collect();

        let cert_recipients = cert.keys()
            .with_policy(&policy, None)
            .supported().alive().revoked(false)
            .for_transport_encryption();
        assert!(cert_recipients
            .map(|x| x.keyid())
            .all(|x| msg_recipients.iter().any(|y| **y == x)))
    }
}
