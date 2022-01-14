extern crate sequoia_openpgp as openpgp;
use serde::{Serialize, Deserialize};
use super::data;

use openpgp::serialize::SerializeInto;
use super::pgp::Cert;

#[derive(Serialize, Deserialize)]
pub struct TestData {
    pub config: data::KeyConfig,
    pub pubkey: data::PubKey,
    pub shares: Vec<data::EncryptedShare>,
    pub shares_required: u8,
    approvers_pub: Vec<data::serde_cert::CertDef>,
    // string for now as this would be the only place we'd serialize
    // secret keys; handle manually rather than via serde
    approvers_priv: Vec<String>,
}

impl TestData {
    #[allow(dead_code)]
    pub fn new(config: data::KeyConfig, pubkey: data::PubKey, shares: Vec<data::EncryptedShare>, shares_required: u8, approvers: Vec<Cert>) -> TestData {
        let approvers_pub = approvers.iter().map(|x| {
            x.clone().into()
        }).collect();
        let approvers_priv = approvers.iter().map(|x| {
            let vec = x.as_tsk().armored().to_vec().unwrap();
            String::from_utf8(vec).unwrap()
        }).collect();
        TestData {
            config,
            pubkey,
            shares,
            shares_required,
            approvers_pub,
            approvers_priv,
        }
    }

    #[cfg(test)]
    pub fn decrypted_shares(&self) -> Vec<data::Share> {
        self.shares.clone().into_iter().zip(self.approvers_priv().iter())
            .map(|(share, key)| {
                super::decrypt_share(&key, share).unwrap()
            })
            .collect()
    }

    #[cfg(test)]
    pub fn approvers_pub(&self) -> Vec<&Cert> {
        self.approvers_pub.iter().map(|x| &**x).collect()
    }

    #[cfg(test)]
    pub fn approvers_priv(&self) -> Vec<Cert> {
        use openpgp::parse::Parse;
        self.approvers_priv.iter().map(|x| Cert::from_reader(x.as_bytes()).unwrap()).collect()
    }
}

#[cfg(test)]
pub fn load_test_data(path: &std::path::Path) -> TestData {
    use std::fs::File;
    let errmsg = format!("failed to load test_data file from path {:?}; generate it with `cargo run --bin generate' from the base directory before running tests.", path);
    let f = File::open(path).unwrap_or_else(|_error| {
        panic!("{}", errmsg);
    });
    serde_json::from_reader(f).unwrap_or_else(|_error| {
        panic!("{}", errmsg);
    })
}

#[cfg(test)]
pub fn load_test_data_3_5() -> TestData {
    use std::path::Path;
    let path = Path::new("test_data/3_5.json");
    load_test_data(&path)
}
