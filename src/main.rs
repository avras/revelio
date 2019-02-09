use exchange::GrinExchange;

mod exchange;
mod nizk;

fn main() {
    
    let mut grin_exch = GrinExchange::new(100, 10);
    let revelio_proof = grin_exch.generate_proof();
    if revelio_proof.verify() == true {
      println!("Proof verification succeeded");
    } else {
      println!("Proof verification failed");
    }
}

