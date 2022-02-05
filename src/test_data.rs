#![allow(dead_code)]
extern crate sequoia_openpgp as openpgp;
use serde::{Serialize, Deserialize};

// NOTE: when including this file with "mod test_data;" (e.g.  in
// binary crates), ensure that sharesign/data.rs is in scope in the
// parent scope, or this will fail to resolve and break compilation.
use super::data;
use data::Cert;

use openpgp::serialize::SerializeInto;

#[derive(Serialize, Deserialize)]
pub struct TestData {
    pub generated: data::GeneratedKey,
    pub shares_required: u8,
    #[serde(with="data::serde_vec_cert")]
    pub approvers_pub: Vec<Cert>,
    // string for now as this would be the only place we'd serialize
    // secret keys; handle manually rather than via serde
    approvers_priv: Vec<String>,
}

impl TestData {
    #[allow(dead_code)]
    pub fn new(generated: data::GeneratedKey, shares_required: u8, approvers_pub: Vec<Cert>) -> TestData {
        let approvers_priv = approvers_pub.iter().map(|x| {
            let vec = x.as_tsk().armored().to_vec().unwrap();
            String::from_utf8(vec).unwrap()
        }).collect();
        TestData {
            generated,
            shares_required,
            approvers_pub,
            approvers_priv,
        }
    }

    #[cfg(test)]
    pub fn decrypted_shares(&self) -> Vec<data::Share> {
        self.generated.shares.clone().into_iter().zip(self.approvers_priv().iter())
            .map(|((share, _confirm), key)| {
                share.decrypt(&key).unwrap().into()
            })
            .collect()
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
    let f = File::open(path).unwrap_or_else(|error| {
        panic!("{}. Error: {:?}", errmsg, error);
    });
    serde_json::from_reader(f).unwrap_or_else(|error| {
        panic!("{}. Error: {:?}", errmsg, error);
    })
}

#[cfg(test)]
pub fn load_test_data_3_5() -> TestData {
    use std::path::Path;
    let path = Path::new("test_data/3_5.json");
    load_test_data(&path)
}
