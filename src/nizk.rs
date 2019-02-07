use digest::Digest;
use sha2::Sha256;
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
    let r3 = SecretKey::new(&secp_inst, &mut rng);
    rspk.c1 = SecretKey::new(&secp_inst, &mut rng);
    rspk.s1 = SecretKey::new(&secp_inst, &mut rng);
    rspk.s2 = SecretKey::new(&secp_inst, &mut rng);

    // Calculation of V_1 = s_1*G + s_2*H + c_1*X    where X = C_i
    let s1_g = PublicKey::from_secret_key(&secp_inst, &rspk.s1).unwrap();
    let mut s2_h = value_point.clone();
    s2_h.mul_assign(&secp_inst, &rspk.s2).unwrap();
    let mut c1_x = output.clone();
    c1_x.mul_assign(&secp_inst, &rspk.c1).unwrap();
    let v1 = PublicKey::from_combination(&secp_inst, vec![&s1_g, &s2_h, &c1_x]).unwrap();

    // Calculation of V_2 = s_1*G' + s_2*H + c_1*Y   where Y = I_i
    let mut s1_gp = keyimage_point.clone();
    s1_gp.mul_assign(&secp_inst, &rspk.s1).unwrap();
    let mut c1_y = keyimage.clone();
    c1_y.mul_assign(&secp_inst, &rspk.c1).unwrap();
    let v2 = PublicKey::from_combination(&secp_inst, vec![&s1_gp, &s2_h, &c1_y]).unwrap();

    // Calculation of r_3*G'
    let mut r3_gp = keyimage_point.clone();
    r3_gp.mul_assign(&secp_inst, &r3).unwrap();

    let mut hasher = Sha256::new();
    hasher.input(blinding_point.serialize_vec(&secp_inst, true)); // Hash G
    hasher.input(keyimage_point.serialize_vec(&secp_inst, true)); // Hash G'
    hasher.input(value_point.serialize_vec(&secp_inst, true));    // Hash H
    hasher.input(output.serialize_vec(&secp_inst, true));         // Hash C_i
    hasher.input(keyimage.serialize_vec(&secp_inst, true));       // Hash I_i
    hasher.input(v1.serialize_vec(&secp_inst, true));             // Hash V_1
    hasher.input(v2.serialize_vec(&secp_inst, true));             // Hash V_2
    hasher.input(r3_gp.serialize_vec(&secp_inst, true));          // Hash r_3*G'

    let hash_scalar = SecretKey::from_slice(&secp_inst, &hasher.result()).unwrap();

    rspk
  }

}
