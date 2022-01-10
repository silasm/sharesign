extern crate sequoia_openpgp as openpgp;
use openpgp::serialize::SerializeInto;
use std::fs;
use std::fs::File;
use std::path::Path;

#[path = "../sharksign/mod.rs"]
mod sharksign;
use sharksign::test_data::TestData;
use sharksign::data;

fn main() {
    let path = Path::new("test_data/3_5.json");
    let config = data::KeyConfig {
        kind: data::KeyKind::RSA,
        size: 2048,
        digest: None,
    };
    write_test_data(path, &config, 5, 3);
}

pub fn generate_tsks(total: u8) -> Vec<openpgp::Cert> {
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
    let approvers_pub: Vec<String> = approvers.iter().map(
        |x| String::from_utf8(x.armored().to_vec().unwrap()).unwrap()
    ).collect();
    let approvers_priv: Vec<String> = approvers.iter().map(
        |x| String::from_utf8(x.as_tsk().armored().to_vec().unwrap()).unwrap()
    ).collect();

    let generated = sharksign::generate(approvers_pub.as_slice(), required, &config).unwrap();
    TestData {
        config: config.clone(),
        pubkey: generated.pubkey,
        shares: generated.shares,
        shares_required: required,
        approvers_pub,
        approvers_priv,
    }
}

pub fn write_test_data(path: &std::path::Path, config: &data::KeyConfig, total: u8, required: u8) {
    fs::create_dir_all("test_data").unwrap();
    let mut nf = File::create(path).unwrap();
    let td = generate_test_data(config, total, required);
    let json = serde_json::to_string(&td).unwrap();
    std::io::copy(&mut json.as_bytes(), &mut nf).unwrap();
}

