use secp256k1zkp as secp;
use secp::key::{SecretKey, PublicKey, ZERO_KEY};

pub struct RevelioSPK {
  c1: SecretKey,
  c2: SecretKey,
  s1: SecretKey,
  s2: SecretKey,
  s3: SecretKey,
}

impl RevelioSPK {
  pub fn new() -> RevelioSPK {
    RevelioSPK {
      c1: ZERO_KEY,
      c2: ZERO_KEY,
      s1: ZERO_KEY,
      s2: ZERO_KEY,
      s3: ZERO_KEY,
    }
  }
}
