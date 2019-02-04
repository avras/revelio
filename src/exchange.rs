use secp256k1zkp as secp;
use secp::pedersen::Commitment;

pub struct RevelioProof {
  pub anonlist: Vec<Commitment>, 
  pub keyimagelist: Vec<Commitment>, 
}
