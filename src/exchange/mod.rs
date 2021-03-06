use digest::Digest;
use sha2::Sha256;
use rand::{thread_rng, Rng};
use rand::seq::SliceRandom;
use secp256k1zkp as secp;
use secp::Secp256k1;
use secp::key::{SecretKey, PublicKey, ZERO_KEY};

use super::nizk::{RevelioPoK, RepresentationPoK};

const MAX_AMOUNT_PER_OUTPUT: u64 = 1000;

pub const GENERATOR_G : [u8;65] = [
    0x04,
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
    0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
    0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65,
    0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
    0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19,
    0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8
];

pub const GENERATOR_H : [u8;65] = [
    0x04,
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
    0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5,
    0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
    0x31, 0xd3, 0xc6, 0x86, 0x39, 0x73, 0x92, 0x6e,
    0x04, 0x9e, 0x63, 0x7c, 0xb1, 0xb5, 0xf4, 0x0a,
    0x36, 0xda, 0xc2, 0x8a, 0xf1, 0x76, 0x69, 0x68,
    0xc3, 0x0c, 0x23, 0x13, 0xf3, 0xa3, 0x89, 0x04
];

pub const GENERATOR_J_COMPR : [u8;33] = [
    0x02,
    0xb8, 0x60, 0xf5, 0x67, 0x95, 0xfc, 0x03, 0xf3,
    0xc2, 0x16, 0x85, 0x38, 0x3d, 0x1b, 0x5a, 0x2f,
    0x29, 0x54, 0xf4, 0x9b, 0x7e, 0x39, 0x8b, 0x8d,
    0x2a, 0x01, 0x93, 0x93, 0x36, 0x21, 0x15, 0x5f
];

pub struct SimpleProof {
  pub own_list: Vec<PublicKey>,
  pub rep_spk: RepresentationPoK,
  blinding_basepoint: PublicKey,
  value_basepoint: PublicKey,
}

impl SimpleProof {
  pub fn new(own_list_size: usize) -> SimpleProof {
    let zeropk = PublicKey::new();
    let empty_spk = RepresentationPoK::new();
    SimpleProof {
      own_list: vec![zeropk; own_list_size],
      rep_spk: empty_spk,
      blinding_basepoint: zeropk,
      value_basepoint: zeropk,
    }
  }

  pub fn verify(&self) -> bool {
    assert!(self.own_list.len() != 0);

    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);

    let mut sum_outputs = self.own_list[0];
    for output in &self.own_list[1..] {
      sum_outputs = PublicKey::from_combination(&secp_inst, vec![&sum_outputs, &output]).unwrap(); // sum_outputs += output
    }

    RepresentationPoK::verify_representation_spk(
      &sum_outputs,
      &self.blinding_basepoint,
      &self.value_basepoint,
      &self.rep_spk,
    )
  }
}

pub struct SimpleGrinExchange {
  own_list_size: usize,
  simple_proof: SimpleProof,
  own_keys: Vec<SecretKey>,
  own_amounts: Vec<u64>,
}

impl SimpleGrinExchange {
  pub fn new(olist_size: usize) -> SimpleGrinExchange  {

    let mut simproof = SimpleProof::new(olist_size);
    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);
    let mut okeys = vec![ZERO_KEY; olist_size];
    let mut amounts = vec![0u64; olist_size];

    let mut rng = thread_rng();

    for i in 0..olist_size {
      okeys[i] = SecretKey::new(&secp_inst, &mut rng);
      amounts[i] = rng.gen_range(1, MAX_AMOUNT_PER_OUTPUT);
      simproof.own_list[i] = Secp256k1::commit(&secp_inst, amounts[i], okeys[i]).unwrap()
                                .to_pubkey(&secp_inst).unwrap();
    }

    simproof.blinding_basepoint = PublicKey::from_slice(&secp_inst, &GENERATOR_G).unwrap();
    simproof.value_basepoint = PublicKey::from_slice(&secp_inst, &GENERATOR_H).unwrap();

    SimpleGrinExchange  {
      own_list_size: olist_size,
      simple_proof: simproof,
      own_keys: okeys,
      own_amounts: amounts,
    }
  }

  pub fn generate_proof(&mut self) -> SimpleProof {

    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);
    let mut sum_outputs = self.simple_proof.own_list[0];
    let mut total_blinding_factor = self.own_keys[0];
    let mut sum_amount = self.own_amounts[0];

    for i in 1..self.own_list_size {
      sum_outputs = PublicKey::from_combination(&secp_inst, vec![&sum_outputs, &self.simple_proof.own_list[i]]).unwrap(); // sum_outputs += output
      total_blinding_factor.add_assign(&secp_inst, &self.own_keys[i]).unwrap();
      sum_amount += &self.own_amounts[i];
    }

    self.simple_proof.rep_spk = RepresentationPoK::create_representation_spk(
                                  sum_outputs,
                                  total_blinding_factor,
                                  sum_amount,
                                  self.simple_proof.blinding_basepoint, // G
                                  self.simple_proof.value_basepoint,    // H
                                );

    SimpleProof {
      own_list: self.simple_proof.own_list.clone(),
      rep_spk: self.simple_proof.rep_spk.clone(),
      blinding_basepoint: self.simple_proof.blinding_basepoint,
      value_basepoint: self.simple_proof.value_basepoint,
    }
  } // end generate_proof
} // end SimpleGrinExchange implementation

pub struct RevelioProof {
  pub anon_list: Vec<PublicKey>,
  pub keyimage_list: Vec<PublicKey>,
  pub spk_list: Vec<RevelioPoK>,
  blinding_basepoint: PublicKey,
  value_basepoint: PublicKey,
  keyimage_basepoint: PublicKey,
}

impl RevelioProof {
  pub fn new(anon_list_size: usize) -> RevelioProof {
    let zeropk = PublicKey::new();
    let empty_spk = RevelioPoK::new();
    RevelioProof {
      anon_list: vec![zeropk; anon_list_size],
      keyimage_list: vec![zeropk; anon_list_size],
      spk_list: vec![empty_spk; anon_list_size],
      blinding_basepoint: zeropk,
      value_basepoint: zeropk,
      keyimage_basepoint: zeropk,
    }
  }

  pub fn verify(&self) -> bool {
    assert!(self.anon_list.len() == self.keyimage_list.len());
    assert!(self.anon_list.len() == self.spk_list.len());
    assert!(self.anon_list.len() != 0);

    for i in 0..self.anon_list.len() {
      if RevelioPoK::verify_spk(
        &self.anon_list[i],
        &self.keyimage_list[i],
        &self.blinding_basepoint,
        &self.value_basepoint,
        &self.keyimage_basepoint,
        &self.spk_list[i],
      ) == false {
        return false;
      } // end if
    } // end for

    true
  }
}

pub struct RevelioGrinExchange {
  anon_list_size: usize,
  revelio_proof: RevelioProof,
  own_keys: Vec<SecretKey>,
  own_amounts: Vec<u64>,
  _decoy_keys_seed: SecretKey,
  decoy_keys: Vec<SecretKey>,
}

impl RevelioGrinExchange {
  pub fn new(alist_size: usize, olist_size: usize) -> RevelioGrinExchange  {

    let mut revproof = RevelioProof::new(alist_size);
    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);
    let mut okeys = Vec::new();
    let mut amounts = vec![0u64; alist_size];
    let mut dkeys = vec![ZERO_KEY; alist_size];

    let mut rng = thread_rng();

    for i in 0..alist_size {
      if i < olist_size {
        okeys.push(SecretKey::new(&secp_inst, &mut rng));
      } else {
        okeys.push(ZERO_KEY)
      }
    }

    // Randomly permuting the own outputs
    okeys.shuffle(&mut rng);

    // Long-term secret key used to seed creation of decoy keys
    let dkeys_seed = SecretKey::new(&secp_inst, &mut rng);

    // Initialize SHA256 to generate decoy keys
    let mut hasher = Sha256::new();

    for i in 0..alist_size {
      if okeys[i] != ZERO_KEY {
        amounts[i] = rng.gen_range(1, MAX_AMOUNT_PER_OUTPUT);
        revproof.anon_list[i] = Secp256k1::commit(&secp_inst, amounts[i], okeys[i]).unwrap()
                                  .to_pubkey(&secp_inst).unwrap();
        revproof.keyimage_list[i] = RevelioGrinExchange ::create_keyimage(amounts[i], okeys[i]); // I_i = alpha*G' + beta*H
      } else {
        let temp_sk = SecretKey::new(&secp_inst, &mut rng);
        revproof.anon_list[i] = PublicKey::from_secret_key(&secp_inst, &temp_sk).unwrap();
        hasher.input(dkeys_seed);                                                  // Hash k_exch
        hasher.input(revproof.anon_list[i].serialize_vec(&secp_inst, true));       // Hash C_i
        dkeys[i] = SecretKey::from_slice(&secp_inst, &hasher.clone().result()).unwrap();
        revproof.keyimage_list[i] = RevelioGrinExchange ::create_keyimage(0, dkeys[i]); // I_i = SHA256(k_exch, C_i)*G' + 0*H
        hasher.reset();
      }
    }

    revproof.blinding_basepoint = PublicKey::from_slice(&secp_inst, &GENERATOR_G).unwrap();
    revproof.value_basepoint = PublicKey::from_slice(&secp_inst, &GENERATOR_H).unwrap();
    revproof.keyimage_basepoint = PublicKey::from_slice(&secp_inst, &GENERATOR_J_COMPR).unwrap();

    RevelioGrinExchange  {
      anon_list_size: alist_size,
      revelio_proof: revproof,
      own_keys: okeys,
      own_amounts: amounts,
      _decoy_keys_seed: dkeys_seed,
      decoy_keys: dkeys,
    }
  }

  /// Generating key image commitment
  pub fn create_keyimage(amount: u64, blinding: SecretKey) -> PublicKey {
    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);
    let keyimage_gen = PublicKey::from_slice(&secp_inst, &GENERATOR_J_COMPR).unwrap();
    let value_gen = PublicKey::from_slice(&secp_inst, &GENERATOR_H).unwrap();

    let mut blind_gp = keyimage_gen.clone();
    blind_gp.mul_assign(&secp_inst, &blinding).unwrap();

    let keyimage = if amount == 0u64 {
      blind_gp
    } else {
      let amount_sk = RevelioPoK::amount_to_key(&secp_inst, amount);
      let mut amount_pk = value_gen.clone();
      amount_pk.mul_assign(&secp_inst, &amount_sk).unwrap();

      PublicKey::from_combination(&secp_inst, vec![&blind_gp, &amount_pk]).unwrap()
    };
    keyimage
  }

  pub fn generate_proof(&mut self) -> RevelioProof {

    for i in 0..self.anon_list_size {
      if self.own_keys[i] != ZERO_KEY {
        self.revelio_proof.spk_list[i] = RevelioPoK::create_spk_from_representation(
                                            self.revelio_proof.anon_list[i],
                                            self.revelio_proof.keyimage_list[i],
                                            self.own_keys[i],
                                            self.own_amounts[i],
                                            self.revelio_proof.blinding_basepoint,  // G
                                            self.revelio_proof.value_basepoint,     // H
                                            self.revelio_proof.keyimage_basepoint,  // G'
                                          );
      } else {
        self.revelio_proof.spk_list[i] = RevelioPoK::create_spk_from_decoykey(
                                            self.revelio_proof.anon_list[i],
                                            self.revelio_proof.keyimage_list[i],
                                            self.decoy_keys[i],
                                            self.revelio_proof.blinding_basepoint,  // G
                                            self.revelio_proof.value_basepoint,     // H
                                            self.revelio_proof.keyimage_basepoint,  // G'
                                          );
      } // end if-else
    } // end for

    RevelioProof {
      anon_list: self.revelio_proof.anon_list.clone(),
      keyimage_list: self.revelio_proof.keyimage_list.clone(),
      spk_list: self.revelio_proof.spk_list.clone(),
      blinding_basepoint: self.revelio_proof.blinding_basepoint,
      value_basepoint: self.revelio_proof.value_basepoint,
      keyimage_basepoint: self.revelio_proof.keyimage_basepoint,
    }
  } // end generate_proof

} // end RevelioGrinExchange implementation

#[cfg(test)]
mod test {
  use secp256k1zkp as secp;
  use secp::Secp256k1;
  use secp::key::{PublicKey, ZERO_KEY, ONE_KEY};
  use super::{GENERATOR_G, GENERATOR_H, GENERATOR_J_COMPR};
  use super::RevelioGrinExchange ;


  #[test]
  fn check_generators() {
    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);
    let blind_gen1 = Secp256k1::commit(&secp_inst, 0, ONE_KEY).unwrap()
                              .to_pubkey(&secp_inst).unwrap();                  // 1*G + 0*H
    let value_gen1 = Secp256k1::commit(&secp_inst, 1, ZERO_KEY).unwrap()
                              .to_pubkey(&secp_inst).unwrap();                  // 0*G + 1*H
    let keyim_gen1 = RevelioGrinExchange ::create_keyimage(0, ONE_KEY);              // 1*G' +0*H

    let blind_gen2 = PublicKey::from_slice(&secp_inst, &GENERATOR_G).unwrap();
    let value_gen2 = PublicKey::from_slice(&secp_inst, &GENERATOR_H).unwrap();
    let keyim_gen2 = PublicKey::from_slice(&secp_inst, &GENERATOR_J_COMPR).unwrap();

    assert!(blind_gen1 == blind_gen2);
    assert!(value_gen1 == value_gen2);
    assert!(keyim_gen1 == keyim_gen2);
  }
}
