extern crate sequoia_openpgp as openpgp;
use serde::{Serialize, Deserialize};
use super::data;
use std::fs::File;
use std::path::Path;

#[derive(Serialize, Deserialize)]
pub struct TestData {
    pub config: data::KeyConfig,
    pub pubkey: data::PubKey,
    pub shares: Vec<data::EncryptedShare>,
    pub shares_required: u8,
    pub approvers_pub: Vec<String>,
    pub approvers_priv: Vec<String>,
}

#[cfg(test)]
impl TestData {
    pub fn decrypted_shares(&self) -> Vec<data::Share> {
        self.shares.clone().into_iter().zip(self.approvers_priv.iter())
            .map(|(share, key)| super::decrypt_share(key.as_bytes(), share).unwrap())
            .collect()
    }
}

#[cfg(test)]
pub fn load_test_data(path: &std::path::Path) -> TestData {
    let f = File::open(path).unwrap();
    serde_json::from_reader(f).unwrap()
}

#[cfg(test)]
pub fn load_test_data_3_5() -> TestData {
    let path = Path::new("test_data/3_5.json");
    load_test_data(&path)
}
