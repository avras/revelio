use rand::thread_rng;
use digest::Digest;
use sha2::Sha256;
use secp256k1zkp as secp;
use secp::Secp256k1;
use secp::key::SecretKey;
use secp::pedersen::Commitment;

mod exchange;
mod nizk;

fn main() {
    let mut hasher = Sha256::new();
    hasher.input(b"Hello, world!");
    let _result = hasher.result();
    
    let secp_inst = Secp256k1::with_caps(secp::ContextFlag::Commit);
    let _commit = Commitment::from_vec(vec![0]);
    let _sk = SecretKey::new(&secp_inst, &mut thread_rng());
}

