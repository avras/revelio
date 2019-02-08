use rand::thread_rng;
use digest::Digest;
use sha2::Sha256;
use secp256k1zkp as secp;
use secp::Secp256k1;
use secp::key::{SecretKey, PublicKey, ONE_KEY, ZERO_KEY};
use secp::pedersen::Commitment;
use nizk::MINUS_ONE_KEY;

mod exchange;
mod nizk;

fn main() {
    let mut hasher = Sha256::new();
    hasher.input(b"Hello, world!");
    
    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);
    let _commit = Commitment::from_vec(vec![0]);
    let (mut sk, mut pk) = secp_inst.generate_keypair(&mut thread_rng()).unwrap();
    hasher.input(pk.serialize_vec(&secp_inst, true));
    let result = hasher.result();
    println!("{:x}", result);

    sk.add_assign(&secp_inst, &ONE_KEY).unwrap(); // Added one to the secret key sk
    let pk1 = PublicKey::from_secret_key(&secp_inst, &sk).unwrap();               // pk1 = (sk+1)*G
    let pk2 = PublicKey::from_secret_key(&secp_inst, &MINUS_ONE_KEY).unwrap();    // pk2 = (-1)*G
    let pk3 = PublicKey::from_combination(&secp_inst, vec![&pk1, &pk2]).unwrap(); // pk3 = pk1+pk2
    assert!(pk3 == pk);  // Check that (sk+1)*G + (-1)*G = sk*G

    let amount = 25;
    let c_pk = Secp256k1::commit(&secp_inst, amount, sk).unwrap()
                  .to_pubkey(&secp_inst).unwrap();                 // sk*G + 25*H
    pk = PublicKey::from_secret_key(&secp_inst, &sk).unwrap();     // sk*G

    let v_basepoint = Secp256k1::commit(&secp_inst, 1, ZERO_KEY).unwrap()
                          .to_pubkey(&secp_inst).unwrap();                 // 0*G + 1*H

    // Converting u64 amount to a scalar i.e. SecretKey
    let amount_as_bytes = amount.to_be_bytes();
    let mut amount_scalar_vec = vec![0u8; 24];
    amount_scalar_vec.extend_from_slice(&amount_as_bytes);
    let amount_scalar = SecretKey::from_slice(&secp_inst, amount_scalar_vec.as_slice()).unwrap();

    let mut ah = v_basepoint.clone();
    ah.mul_assign(&secp_inst, &amount_scalar).unwrap();    //25*H
    let skg_ah = PublicKey::from_combination(&secp_inst, vec![&pk, &ah]).unwrap(); // sk*G + 25*H
    assert!(c_pk == skg_ah); // Check the commitment public key is the same via both calculations

}

