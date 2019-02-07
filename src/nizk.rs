use rand::thread_rng;
use secp256k1zkp as secp;
use secp::Secp256k1;
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

  pub fn create_spk_from_decoykey (
    output: PublicKey,
    keyimage: PublicKey,
    dkey: SecretKey,
    blinding_point: PublicKey, // G
    value_point: PublicKey,    // H
    keyimage_point: PublicKey, // G'
  ) -> RevelioSPK {
    let mut rng = thread_rng();
    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

    let mut rspk = RevelioSPK::new();
    let mut r3 = SecretKey::new(&secp_inst, &mut rng);
    rspk.c1 = SecretKey::new(&secp_inst, &mut rng);
    rspk.s1 = SecretKey::new(&secp_inst, &mut rng);
    rspk.s2 = SecretKey::new(&secp_inst, &mut rng);

    rspk
  }

}
