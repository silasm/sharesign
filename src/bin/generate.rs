extern crate sequoia_openpgp as openpgp;
use std::fs;
use std::fs::File;
use std::path::Path;

#[path = "../sharksign/mod.rs"]
mod sharksign;
use sharksign::test_data::TestData;
use sharksign::data::{self, KeyFlags, Validity, CipherSuite, Cert};

fn main() {
    let path = Path::new("test_data/3_5.json");
    let config = data::KeyConfig {
        cipher_suite: CipherSuite::RSA2k,
        subkeys: vec![
            data::SubkeyConfig {
                cipher_suite: CipherSuite::RSA2k,
                flags: vec![KeyFlags::Signing],
                validity: Validity::DoesNotExpire,
            },
        ],
        flags: vec![KeyFlags::Certification],
        validity: Validity::DoesNotExpire,
        userid: "alice@example.org".to_string(),
    };
    write_test_data(path, &config, 5, 3);
}

pub fn generate_tsks(total: u8) -> Vec<Cert> {
    let uids = vec![
        "alice", "bob", "chester", "david", "eve",
        "fred", "gus", "henrietta", "irene", "jack",
    ];
    let mut x = 0;
    std::iter::repeat_with(
        || { let tmp = x; x = (x + 1) % uids.len(); &uids[tmp] }
    ).take(total.into()).map(|name| {
        let (cert, _rev) = openpgp::cert::CertBuilder::general_purpose(None, Some(format!("{}@example.org", name))).generate().unwrap();
        cert
    }).collect()
}

pub fn generate_test_data(config: &data::KeyConfig, total: u8, required: u8) -> TestData {
    let approvers = generate_tsks(total);
    let generated = sharksign::generate(&approvers, required, config).unwrap();
    TestData::new(
        generated,
        required,
        approvers,
    )
}

pub fn write_test_data(path: &std::path::Path, config: &data::KeyConfig, total: u8, required: u8) {
    fs::create_dir_all("test_data").unwrap();
    let mut nf = File::create(path).unwrap();
    let td = generate_test_data(config, total, required);
    let json = serde_json::to_string(&td).unwrap();
    std::io::copy(&mut json.as_bytes(), &mut nf).unwrap();
}

