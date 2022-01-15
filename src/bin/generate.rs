extern crate sequoia_openpgp as openpgp;
use std::fs;
use std::fs::File;
use std::path::Path;
use openpgp::serialize::SerializeInto;

#[path = "../sharksign/mod.rs"]
mod sharksign;
use sharksign::test_data::TestData;
use sharksign::data;
use sharksign::pgp::Cert;

fn main() {
    let path = Path::new("test_data/3_5.json");
    let config = data::KeyConfig {
        kind: data::KeyKind::Rsa,
        userid: "alice@example.org".to_string(),
        size: 2048,
        digest: None,
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
    let armored = String::from_utf8(generated.pubkey.armored().to_vec().unwrap()).unwrap();
    TestData::new(
        config.clone(),
        data::PubKey {
            pem: armored,
            kind: data::KeyKind::Rsa,
        },
        generated.shares,
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

