use rand::{thread_rng, Rng};
use rand::seq::SliceRandom;
use secp256k1zkp as secp;
use secp::Secp256k1;
use secp::key::{SecretKey, PublicKey, ZERO_KEY, ONE_KEY};
use secp::pedersen::Commitment;
use secp::ffi;
use secp::constants;

use super::nizk::RevelioSPK;

const MAX_AMOUNT_PER_OUTPUT: u64 = 1000;

pub struct RevelioProof {
  pub anon_list: Vec<PublicKey>,
  pub keyimage_list: Vec<PublicKey>,
  pub spk_list: Vec<RevelioSPK>,
  blinding_basepoint: PublicKey,
  value_basepoint: PublicKey,
  keyimage_basepoint: PublicKey,
}

impl RevelioProof {
  pub fn new(anon_list_size: usize) -> RevelioProof {
    let zeropk = PublicKey::new();
    let empty_spk = RevelioSPK::new();
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
      if RevelioSPK::verify_spk(
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

pub struct GrinExchange {
  anon_list_size: usize,
  own_list_size: usize,
  revelio_proof: RevelioProof,
  own_keys: Vec<SecretKey>,
  own_amounts: Vec<u64>,
  decoy_keys: Vec<SecretKey>,
}

impl GrinExchange{
  pub fn new(alist_size: usize, olist_size: usize) -> GrinExchange {

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


    for i in 0..alist_size {
      if okeys[i] != ZERO_KEY {
        amounts[i] = rng.gen_range(0, MAX_AMOUNT_PER_OUTPUT);
        revproof.anon_list[i] = Secp256k1::commit(&secp_inst, amounts[i], okeys[i]).unwrap()
                                  .to_pubkey(&secp_inst).unwrap();
        revproof.keyimage_list[i] = GrinExchange::create_keyimage(amounts[i], okeys[i])
                                      .to_pubkey(&secp_inst).unwrap();
      } else {
        let temp_sk = SecretKey::new(&secp_inst, &mut rng);
        revproof.anon_list[i] = PublicKey::from_secret_key(&secp_inst, &temp_sk).unwrap();
        dkeys[i] = SecretKey::new(&secp_inst, &mut rng);
        revproof.keyimage_list[i] = PublicKey::from_secret_key(&secp_inst, &dkeys[i]).unwrap();
      }
    }

    revproof.blinding_basepoint = Secp256k1::commit(&secp_inst, 0, ONE_KEY).unwrap()
                          .to_pubkey(&secp_inst).unwrap();                 // 1*G + 0*H
    revproof.value_basepoint = Secp256k1::commit(&secp_inst, 1, ZERO_KEY).unwrap()
                          .to_pubkey(&secp_inst).unwrap();                 // 0*G + 1*H
    revproof.keyimage_basepoint = GrinExchange::create_keyimage(0, ONE_KEY)
                          .to_pubkey(&secp_inst).unwrap();                 // 1*G' +0*H

    GrinExchange {
      anon_list_size: alist_size,
      own_list_size: olist_size,
      revelio_proof: revproof,
      own_keys: okeys,
      own_amounts: amounts,
      decoy_keys: dkeys,
    }
  }

  /// Generating key image commitment
  pub fn create_keyimage(amount: u64, blinding: SecretKey) -> Commitment {
    let flag = ffi::SECP256K1_START_SIGN | ffi::SECP256K1_START_VERIFY;
    let ctx = unsafe { ffi::secp256k1_context_create(flag) };

    let mut commit_i = [0; constants::PEDERSEN_COMMITMENT_SIZE_INTERNAL];

    unsafe {
      ffi::secp256k1_pedersen_commit(
        ctx,
        commit_i.as_mut_ptr(),
        blinding.as_ptr(),
        amount,
        constants::GENERATOR_H.as_ptr(),
        constants::GENERATOR_PUB_J_RAW.as_ptr(),
      )
    };

    let commit_o = unsafe {
      let mut c_out = Commitment::from_vec(vec![0; constants::PEDERSEN_COMMITMENT_SIZE]);
      ffi::secp256k1_pedersen_commitment_serialize(
        ctx,
        c_out.as_mut_ptr(),
        commit_i.as_ptr(),
      );
      c_out
    };
    unsafe { ffi::secp256k1_context_destroy(ctx) };
    commit_o
  }

  pub fn generate_proof(&mut self) -> RevelioProof {

    for i in 0..self.anon_list_size {
      if self.own_keys[i] != ZERO_KEY {
        self.revelio_proof.spk_list[i] = RevelioSPK::create_spk_from_representation(
                                            self.revelio_proof.anon_list[i],
                                            self.revelio_proof.keyimage_list[i],
                                            self.own_keys[i],
                                            self.own_amounts[i],
                                            self.revelio_proof.blinding_basepoint,  // G
                                            self.revelio_proof.value_basepoint,     // H
                                            self.revelio_proof.keyimage_basepoint,  // G'
                                          );
      } else {
        self.revelio_proof.spk_list[i] = RevelioSPK::create_spk_from_decoykey(
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

}
