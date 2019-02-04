use secp256k1zkp as secp;
use secp::key::SecretKey;

pub struct RevelioNIZK {
  c1: SecretKey,
  c2: SecretKey,
  s1: SecretKey,
  s2: SecretKey,
  s3: SecretKey,
}
