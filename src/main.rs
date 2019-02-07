use rand::thread_rng;
use digest::Digest;
use sha2::Sha256;
use secp256k1zkp as secp;
use secp::Secp256k1;
use secp::key::{SecretKey, PublicKey};
use secp::pedersen::Commitment;

mod exchange;
mod nizk;

fn main() {
    let mut hasher = Sha256::new();
    hasher.input(b"Hello, world!");
    
    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);
    let _commit = Commitment::from_vec(vec![0]);
    let (_sk, pk) = secp_inst.generate_keypair(&mut thread_rng()).unwrap();
    hasher.input(pk.serialize_vec(&secp_inst, true));
    let result = hasher.result();
    println!("{:x}", result);
}

