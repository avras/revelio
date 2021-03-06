use digest::Digest;
use sha2::Sha256;
use rand::thread_rng;
use secp256k1zkp as secp;
use secp::Secp256k1;
use secp::key::{SecretKey, PublicKey, ZERO_KEY};

/// The number curve_order-1 encoded as a secret key
pub const MINUS_ONE_KEY: SecretKey = SecretKey([
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40
]);

#[derive(Copy, Clone)]
pub struct RevelioPoK {
  c1: SecretKey,
  c2: SecretKey,
  s1: SecretKey,
  s2: SecretKey,
  s3: SecretKey,
}

impl RevelioPoK {
  pub fn new() -> RevelioPoK {
    RevelioPoK {
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
    blinding_gen: PublicKey, // G
    value_gen: PublicKey,    // H
    keyimage_gen: PublicKey, // G'
  ) -> RevelioPoK {
    let mut rng = thread_rng();
    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

    let mut rspk = RevelioPoK::new();
    let r3 = SecretKey::new(&secp_inst, &mut rng);
    rspk.c1 = SecretKey::new(&secp_inst, &mut rng);
    rspk.s1 = SecretKey::new(&secp_inst, &mut rng);
    rspk.s2 = SecretKey::new(&secp_inst, &mut rng);

    // Calculation of V_1 = s_1*G + s_2*H + c_1*X    where X = C_i
    let s1_g = PublicKey::from_secret_key(&secp_inst, &rspk.s1).unwrap();
    let mut s2_h = value_gen.clone();
    s2_h.mul_assign(&secp_inst, &rspk.s2).unwrap();
    let mut c1_x = output.clone();
    c1_x.mul_assign(&secp_inst, &rspk.c1).unwrap();
    let v1 = PublicKey::from_combination(&secp_inst, vec![&s1_g, &s2_h, &c1_x]).unwrap();

    // Calculation of V_2 = s_1*G' + s_2*H + c_1*Y   where Y = I_i
    let mut s1_gp = keyimage_gen.clone();
    s1_gp.mul_assign(&secp_inst, &rspk.s1).unwrap();
    let mut c1_y = keyimage.clone();
    c1_y.mul_assign(&secp_inst, &rspk.c1).unwrap();
    let v2 = PublicKey::from_combination(&secp_inst, vec![&s1_gp, &s2_h, &c1_y]).unwrap();

    // Calculation of r_3*G'
    let mut r3_gp = keyimage_gen.clone();
    r3_gp.mul_assign(&secp_inst, &r3).unwrap();

    // Calculation of H(S || V_1 || V_2 || r_3*G')
    let mut hasher = Sha256::new();
    hasher.input(blinding_gen.serialize_vec(&secp_inst, true)); // Hash G
    hasher.input(keyimage_gen.serialize_vec(&secp_inst, true)); // Hash G'
    hasher.input(value_gen.serialize_vec(&secp_inst, true));    // Hash H
    hasher.input(output.serialize_vec(&secp_inst, true));       // Hash C_i
    hasher.input(keyimage.serialize_vec(&secp_inst, true));     // Hash I_i
    hasher.input(v1.serialize_vec(&secp_inst, true));           // Hash V_1
    hasher.input(v2.serialize_vec(&secp_inst, true));           // Hash V_2
    hasher.input(r3_gp.serialize_vec(&secp_inst, true));        // Hash r_3*G'

    let hash_scalar = SecretKey::from_slice(&secp_inst, &hasher.result()).unwrap();

    // Calculation of -c_1
    let mut minus_c1 = rspk.c1;
    minus_c1.mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();

    // Calculation of c_2
    rspk.c2 = hash_scalar;                                      // c_2 = H(S...r_3*G')
    rspk.c2.add_assign(&secp_inst, &minus_c1).unwrap();         // c_2 = H(S...r_3*G') - c_1

    // Calculation of s_3
    rspk.s3 = dkey;                                             // s_3 = gamma
    rspk.s3.mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();    // s_3 = -gamma
    rspk.s3.mul_assign(&secp_inst, &rspk.c2).unwrap();          // s_3 = -c_2*gamma
    rspk.s3.add_assign(&secp_inst, &r3).unwrap();               // s_3 = r_3 - c_2*gamma

    rspk
  }

  pub fn create_spk_from_representation (
    output: PublicKey,
    keyimage: PublicKey,
    blinding_factor: SecretKey,
    amount: u64,
    blinding_gen: PublicKey, // G
    value_gen: PublicKey,    // H
    keyimage_gen: PublicKey, // G'
  ) -> RevelioPoK {
    let mut rng = thread_rng();
    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

    let mut rspk = RevelioPoK::new();
    let r1 = SecretKey::new(&secp_inst, &mut rng);
    let r2 = SecretKey::new(&secp_inst, &mut rng);
    rspk.c2 = SecretKey::new(&secp_inst, &mut rng);
    rspk.s3 = SecretKey::new(&secp_inst, &mut rng);

    // Calculation of V_3 = s_3*G' + c_2*Y   where Y = I_i
    let mut s3_gp = keyimage_gen.clone();
    s3_gp.mul_assign(&secp_inst, &rspk.s3).unwrap();
    let mut c2_y = keyimage.clone();
    c2_y.mul_assign(&secp_inst, &rspk.c2).unwrap();
    let v3 = PublicKey::from_combination(&secp_inst, vec![&s3_gp, &c2_y]).unwrap();

    // Calculation of r_1*G + r_2*H
    let r1_g = PublicKey::from_secret_key(&secp_inst, &r1).unwrap();
    let mut r2_h = value_gen.clone();
    r2_h.mul_assign(&secp_inst, &r2).unwrap();
    let r1g_r2h = PublicKey::from_combination(&secp_inst, vec![&r1_g, &r2_h]).unwrap();

    // Calculation of r_1*G' + r_2*H
    let mut r1_gp = keyimage_gen.clone();
    r1_gp.mul_assign(&secp_inst, &r1).unwrap();
    let r1gp_r2h = PublicKey::from_combination(&secp_inst, vec![&r1_gp, &r2_h]).unwrap();

    // Calculation of H(S || r_1*G + r_2*H || r_1*G'+r_2*H || V_3)
    let mut hasher = Sha256::new();
    hasher.input(blinding_gen.serialize_vec(&secp_inst, true)); // Hash G
    hasher.input(keyimage_gen.serialize_vec(&secp_inst, true)); // Hash G'
    hasher.input(value_gen.serialize_vec(&secp_inst, true));    // Hash H
    hasher.input(output.serialize_vec(&secp_inst, true));       // Hash C_i
    hasher.input(keyimage.serialize_vec(&secp_inst, true));     // Hash I_i
    hasher.input(r1g_r2h.serialize_vec(&secp_inst, true));      // Hash r_1*G + r_2*H
    hasher.input(r1gp_r2h.serialize_vec(&secp_inst, true));     // Hash r_1*G' + r_2*H
    hasher.input(v3.serialize_vec(&secp_inst, true));           // Hash V_3

    let hash_scalar = SecretKey::from_slice(&secp_inst, &hasher.result()).unwrap();

    // Calculation of -c_2
    let mut minus_c2 = rspk.c2;
    minus_c2.mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();

    // Calculation of c_1
    rspk.c1 = hash_scalar;                                      // c_1 = H(S...V_3)
    rspk.c1.add_assign(&secp_inst, &minus_c2).unwrap();         // c_1 = H(S...V_3) - c_2

    // Calculation of s_1
    rspk.s1 = blinding_factor;                                  // s_1 = alpha
    rspk.s1.mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();    // s_1 = -alpha
    rspk.s1.mul_assign(&secp_inst, &rspk.c1).unwrap();          // s_1 = -c_1*alpha
    rspk.s1.add_assign(&secp_inst, &r1).unwrap();               // s_1 = r_1 - c_1*alpha

    // Calculation of s_2
    rspk.s2 = RevelioPoK::amount_to_key(&secp_inst, amount);                                    // s_2 = beta
    rspk.s2.mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();    // s_2 = -beta
    rspk.s2.mul_assign(&secp_inst, &rspk.c1).unwrap();          // s_2 = -c_1*beta
    rspk.s2.add_assign(&secp_inst, &r2).unwrap();               // s_2 = r_2 - c_1*beta

    rspk
  }

  pub fn amount_to_key (secp_inst: &Secp256k1, amount: u64) -> SecretKey {
    assert!(amount != 0);
    // Converting u64 amount to a scalar i.e. SecretKey
    let amount_as_bytes = amount.to_be_bytes();
    let mut amount_scalar_vec = vec![0u8; 24];
    amount_scalar_vec.extend_from_slice(&amount_as_bytes);
    let amount_scalar = SecretKey::from_slice(&secp_inst, amount_scalar_vec.as_slice()).unwrap();

    amount_scalar
  }

  pub fn verify_spk (
    output: &PublicKey,
    keyimage: &PublicKey,
    blinding_gen: &PublicKey, // G
    value_gen: &PublicKey,    // H
    keyimage_gen: &PublicKey, // G'
    rspk: &RevelioPoK
  ) -> bool {
    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

    // Calculation of V_1 = s_1*G + s_2*H + c_1*X    where X = C_i
    let s1_g = PublicKey::from_secret_key(&secp_inst, &rspk.s1).unwrap();
    let mut s2_h = value_gen.clone();
    s2_h.mul_assign(&secp_inst, &rspk.s2).unwrap();
    let mut c1_x = output.clone();
    c1_x.mul_assign(&secp_inst, &rspk.c1).unwrap();
    let v1 = PublicKey::from_combination(&secp_inst, vec![&s1_g, &s2_h, &c1_x]).unwrap();

    // Calculation of V_2 = s_1*G' + s_2*H + c_1*Y   where Y = I_i
    let mut s1_gp = keyimage_gen.clone();
    s1_gp.mul_assign(&secp_inst, &rspk.s1).unwrap();
    let mut c1_y = keyimage.clone();
    c1_y.mul_assign(&secp_inst, &rspk.c1).unwrap();
    let v2 = PublicKey::from_combination(&secp_inst, vec![&s1_gp, &s2_h, &c1_y]).unwrap();

    // Calculation of V_3 = s_3*G' + c_2*Y   where Y = I_i
    let mut s3_gp = keyimage_gen.clone();
    s3_gp.mul_assign(&secp_inst, &rspk.s3).unwrap();
    let mut c2_y = keyimage.clone();
    c2_y.mul_assign(&secp_inst, &rspk.c2).unwrap();
    let v3 = PublicKey::from_combination(&secp_inst, vec![&s3_gp, &c2_y]).unwrap();

    // Calculation of H(S || V_1 || V_2 || V_3)
    let mut hasher = Sha256::new();
    hasher.input(blinding_gen.serialize_vec(&secp_inst, true)); // Hash G
    hasher.input(keyimage_gen.serialize_vec(&secp_inst, true)); // Hash G'
    hasher.input(value_gen.serialize_vec(&secp_inst, true));    // Hash H
    hasher.input(output.serialize_vec(&secp_inst, true));       // Hash C_i
    hasher.input(keyimage.serialize_vec(&secp_inst, true));     // Hash I_i
    hasher.input(v1.serialize_vec(&secp_inst, true));           // Hash V_1
    hasher.input(v2.serialize_vec(&secp_inst, true));           // Hash V_2
    hasher.input(v3.serialize_vec(&secp_inst, true));           // Hash V_3

    let hash_scalar = SecretKey::from_slice(&secp_inst, &hasher.result()).unwrap();

    let mut c_sum = rspk.c1;
    c_sum.add_assign(&secp_inst, &rspk.c2).unwrap();

    c_sum == hash_scalar
  }
}

#[derive(Copy, Clone)]
pub struct RepresentationPoK {
  c:  SecretKey,
  s1: SecretKey,
  s2: SecretKey,
}

impl RepresentationPoK {
  pub fn new() -> RepresentationPoK {
    RepresentationPoK {
      c:  ZERO_KEY,
      s1: ZERO_KEY,
      s2: ZERO_KEY,
    }
  }

pub fn create_representation_spk (
    output: PublicKey,
    blinding_factor: SecretKey, // alpha
    amount: u64,                // beta
    blinding_gen: PublicKey,    // G
    value_gen: PublicKey,       // H
  ) -> RepresentationPoK {
    let mut rng = thread_rng();
    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

    let mut rep_spk = RepresentationPoK::new();
    let r1 = SecretKey::new(&secp_inst, &mut rng);
    let r2 = SecretKey::new(&secp_inst, &mut rng);

    // Calculation of r_1*G + r_2*H
    let r1_g = PublicKey::from_secret_key(&secp_inst, &r1).unwrap();
    let mut r2_h = value_gen.clone();
    r2_h.mul_assign(&secp_inst, &r2).unwrap();
    let r1g_r2h = PublicKey::from_combination(&secp_inst, vec![&r1_g, &r2_h]).unwrap();

    // Calculation of H(S || r_1*G + r_2*H)
    let mut hasher = Sha256::new();
    hasher.input(blinding_gen.serialize_vec(&secp_inst, true)); // Hash G
    hasher.input(value_gen.serialize_vec(&secp_inst, true));    // Hash H
    hasher.input(output.serialize_vec(&secp_inst, true));       // Hash \sum C_i
    hasher.input(r1g_r2h.serialize_vec(&secp_inst, true));      // Hash r_1*G + r_2*H

    let hash_scalar = SecretKey::from_slice(&secp_inst, &hasher.result()).unwrap();

    // Calculation of c
    rep_spk.c = hash_scalar;                                       // c = H(S...V_3)

    // Calculation of s_1
    rep_spk.s1 = blinding_factor;                                  // s_1 = alpha
    rep_spk.s1.mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();    // s_1 = -alpha
    rep_spk.s1.mul_assign(&secp_inst, &rep_spk.c).unwrap();         // s_1 = -c*alpha
    rep_spk.s1.add_assign(&secp_inst, &r1).unwrap();               // s_1 = r_1 - c*alpha

    // Calculation of s_2
    rep_spk.s2 = RevelioPoK::amount_to_key(&secp_inst, amount);    // s_2 = beta
    rep_spk.s2.mul_assign(&secp_inst, &MINUS_ONE_KEY).unwrap();    // s_2 = -beta
    rep_spk.s2.mul_assign(&secp_inst, &rep_spk.c).unwrap();         // s_2 = -c*beta
    rep_spk.s2.add_assign(&secp_inst, &r2).unwrap();               // s_2 = r_2 - c*beta

    rep_spk
  }

  pub fn verify_representation_spk (
    output: &PublicKey,
    blinding_gen: &PublicKey, // G
    value_gen: &PublicKey,    // H
    rep_spk: &RepresentationPoK,
  ) -> bool {
    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

    // Calculation of V = s_1*G + s_2*H + c*X    where X = \sum C_i
    let s1_g = PublicKey::from_secret_key(&secp_inst, &rep_spk.s1).unwrap();
    let mut s2_h = value_gen.clone();
    s2_h.mul_assign(&secp_inst, &rep_spk.s2).unwrap();
    let mut c_x = output.clone();
    c_x.mul_assign(&secp_inst, &rep_spk.c).unwrap();
    let v = PublicKey::from_combination(&secp_inst, vec![&s1_g, &s2_h, &c_x]).unwrap();

    // Calculation of H(S || V)
    let mut hasher = Sha256::new();
    hasher.input(blinding_gen.serialize_vec(&secp_inst, true)); // Hash G
    hasher.input(value_gen.serialize_vec(&secp_inst, true));    // Hash H
    hasher.input(output.serialize_vec(&secp_inst, true));       // Hash \sum C_i
    hasher.input(v.serialize_vec(&secp_inst, true));           // Hash V

    let hash_scalar = SecretKey::from_slice(&secp_inst, &hasher.result()).unwrap();

    rep_spk.c == hash_scalar
  }
}



#[cfg(test)]
mod test {
  use rand::thread_rng;
  use secp256k1zkp as secp;
  use secp::Secp256k1;
  use secp::key::{SecretKey, PublicKey, ZERO_KEY, ONE_KEY};
  use super::{RevelioPoK, RepresentationPoK, MINUS_ONE_KEY};
  use super::super::exchange::RevelioGrinExchange;


  #[test]
  fn revelio_decoy_spk_gen_verify() {
    let mut rng = thread_rng();
    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

    let (_sk, output) = secp_inst.generate_keypair(&mut rng).unwrap();

    let blinding_basepoint = Secp256k1::commit(&secp_inst, 0, ONE_KEY).unwrap()
                              .to_pubkey(&secp_inst).unwrap();                 // 1*G + 0*H
    let value_basepoint = Secp256k1::commit(&secp_inst, 1, ZERO_KEY).unwrap()
                              .to_pubkey(&secp_inst).unwrap();                 // 0*G + 1*H
    let keyimage_basepoint = RevelioGrinExchange::create_keyimage(0, ONE_KEY);        // 1*G' +0*H

    let dkey = SecretKey::new(&secp_inst, &mut rng);
    let mut keyimage = keyimage_basepoint.clone();
    keyimage.mul_assign(&secp_inst, &dkey).unwrap();

    let rspk = RevelioPoK::create_spk_from_decoykey(
                              output,
                              keyimage,
                              dkey,
                              blinding_basepoint,
                              value_basepoint,
                              keyimage_basepoint,
                            );
    let result = RevelioPoK::verify_spk(
                              &output,
                              &keyimage,
                              &blinding_basepoint,
                              &value_basepoint,
                              &keyimage_basepoint,
                              &rspk,
                            );
    assert!(result);
  }

  #[test]
  fn revelio_representation_spk_gen_verify() {
    let mut rng = thread_rng();
    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

    let blind = SecretKey::new(&secp_inst, &mut rng);
    let amount = 250u64;
    let output = Secp256k1::commit(&secp_inst, amount, blind).unwrap()
                              .to_pubkey(&secp_inst).unwrap();
    let keyimage = RevelioGrinExchange::create_keyimage(amount, blind);

    let blinding_basepoint = Secp256k1::commit(&secp_inst, 0, ONE_KEY).unwrap()
                              .to_pubkey(&secp_inst).unwrap();                 // 1*G + 0*H
    let value_basepoint = Secp256k1::commit(&secp_inst, 1, ZERO_KEY).unwrap()
                              .to_pubkey(&secp_inst).unwrap();                 // 0*G + 1*H
    let keyimage_basepoint = RevelioGrinExchange::create_keyimage(0, ONE_KEY);        // 1*G' +0*H

    let rspk = RevelioPoK::create_spk_from_representation(
                              output,
                              keyimage,
                              blind,
                              amount,
                              blinding_basepoint,
                              value_basepoint,
                              keyimage_basepoint,
                            );
    let result = RevelioPoK::verify_spk(
                              &output,
                              &keyimage,
                              &blinding_basepoint,
                              &value_basepoint,
                              &keyimage_basepoint,
                              &rspk,
                            );
    assert!(result);
  }

  #[test]
  fn simple_representation_spk_gen_verify() {
    let mut rng = thread_rng();
    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

    let blind1 = SecretKey::new(&secp_inst, &mut rng);
    let blind2 = SecretKey::new(&secp_inst, &mut rng);
    let amount1 = 250u64;
    let amount2 = 350u64;

    let output1 = Secp256k1::commit(&secp_inst, amount1, blind1).unwrap()
                              .to_pubkey(&secp_inst).unwrap();
    let output2 = Secp256k1::commit(&secp_inst, amount2, blind2).unwrap()
                              .to_pubkey(&secp_inst).unwrap();

    let blinding_basepoint = Secp256k1::commit(&secp_inst, 0, ONE_KEY).unwrap()
                              .to_pubkey(&secp_inst).unwrap();                 // 1*G + 0*H
    let value_basepoint = Secp256k1::commit(&secp_inst, 1, ZERO_KEY).unwrap()
                              .to_pubkey(&secp_inst).unwrap();                 // 0*G + 1*H

    let mut blind = blind1;
    blind.add_assign(&secp_inst, &blind2).unwrap();

    let output = PublicKey::from_combination(&secp_inst, vec![&output1, &output2]).unwrap();
    let amount = amount1 + amount2;

    let rep_spk = RepresentationPoK::create_representation_spk(
                    output,
                    blind,
                    amount,
                    blinding_basepoint,
                    value_basepoint,
                  );
    let result = RepresentationPoK::verify_representation_spk(
                    &output,
                    &blinding_basepoint,
                    &value_basepoint,
                    &rep_spk,
                  );

    assert!(result);
  }

  #[test]
  fn check_minus_one_key() {
    let mut rng = thread_rng();
    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

    let (mut sk, pk) = secp_inst.generate_keypair(&mut rng).unwrap();

    sk.add_assign(&secp_inst, &ONE_KEY).unwrap(); // Added one to the secret key sk
    let pk1 = PublicKey::from_secret_key(&secp_inst, &sk).unwrap();               // pk1 = (sk+1)*G
    let pk2 = PublicKey::from_secret_key(&secp_inst, &MINUS_ONE_KEY).unwrap();    // pk2 = (-1)*G
    let pk3 = PublicKey::from_combination(&secp_inst, vec![&pk1, &pk2]).unwrap(); // pk3 = pk1+pk2
    assert!(pk3 == pk);  // Check that (sk+1)*G + (-1)*G = sk*G
  }

  #[test]
  fn check_amount_to_key() {
    let mut rng = thread_rng();
    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

    let (sk, pk) = secp_inst.generate_keypair(&mut rng).unwrap();  // pk = sk*G
    let amount = 25;
    let c_pk = Secp256k1::commit(&secp_inst, amount, sk).unwrap()
                  .to_pubkey(&secp_inst).unwrap();                 // sk*G + 25*H

    let value_basepoint = Secp256k1::commit(&secp_inst, 1, ZERO_KEY).unwrap()
                              .to_pubkey(&secp_inst).unwrap();     // 0*G + 1*H
    let amount_scalar = RevelioPoK::amount_to_key(&secp_inst, amount);

    let mut ah = value_basepoint.clone();
    ah.mul_assign(&secp_inst, &amount_scalar).unwrap();    //25*H
    let skg_ah = PublicKey::from_combination(&secp_inst, vec![&pk, &ah]).unwrap(); // sk*G + 25*H

    assert!(c_pk == skg_ah); // Check the commitment public key is the same via both calculations
  }

}
