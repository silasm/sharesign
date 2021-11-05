use std::error::Error;
use sharks::{Sharks, Share};

mod keys;

// result of signing a payload
pub struct Signature {}
// public key for encrypting a share for distribution
pub struct PubKey {}
// dummy type for encrypted return
pub struct Encrypted {}

pub fn generate(num_shares: usize, shares_needed: u8, config: &keys::KeyConfig) -> Result<Vec<Share>, Box<dyn Error>> {
    let key = keys::generate(&config)?;
    let sharks = Sharks(shares_needed);
    // TODO: replace RNG if needed using dealer_rng
    let dealer = sharks.dealer(key.as_slice());
    Ok(dealer.take(num_shares).collect())
}

pub fn sign(shares_needed: u8, shares: &[Share], payload: &[u8], config: keys::KeyConfig) -> Result<Signature, Box<dyn Error>> {
    let sharks = Sharks(shares_needed);
    let pem = sharks.recover(shares)?;
    let _signature = keys::sign(&config, pem.as_slice(), payload)?;
    Ok(Signature{})
}

pub fn encryptshare(_share: Share, _pubkey: PubKey) -> Encrypted {
    // pubkey_encrypt(Vec::from(&share).as_slice(), pubkey)
    assert!(false);
    return Encrypted {}
}
