extern crate structopt;
use structopt::StructOpt;

use std::time::{Instant, Duration};
use exchange::GrinExchange;

mod exchange;
mod nizk;

#[derive(Debug, StructOpt)]
#[structopt(name = "revelio", about = "Revelio proof generation simulator.")]
struct Opt {
  //#[structopt(short = "a", long = "anonsize")]
  anon_list_size: usize,
  //#[structopt(short = "o", long = "ownsize")]
  own_list_size: usize,
  #[structopt(short = "n", long = "numiter", default_value = "1")]
  num_iter: u32,
}

fn main() {
    let opt = Opt::from_args();

    let num_iter = opt.num_iter;
    let mut grin_exch = GrinExchange::new(opt.anon_list_size, opt.own_list_size);
    let mut revelio_proof;
    let mut gen_proof_start;
    let mut gen_proof_end;
    let mut ver_proof_start;
    let mut ver_proof_end;
    let mut total_gen_proof_duration = Duration::new(0, 0);
    let mut total_ver_proof_duration = Duration::new(0, 0);
    
    let sim_start = Instant::now();

    for _i in 0..num_iter {
      gen_proof_start = Instant::now();
      revelio_proof = grin_exch.generate_proof();
      gen_proof_end = Instant::now();
      total_gen_proof_duration += gen_proof_end.duration_since(gen_proof_start);

      ver_proof_start = Instant::now();
      assert!(revelio_proof.verify());
      ver_proof_end = Instant::now();
      total_ver_proof_duration += ver_proof_end.duration_since(ver_proof_start);
    }

    let sim_end = Instant::now();
    println!("Total simulation time = {:?}", sim_end.duration_since(sim_start));

    println!("Options = {:?}", opt);
    println!("Average proof generation time = {:?}",
      total_gen_proof_duration.checked_div(num_iter).unwrap());
    println!("Average proof verification time = {:?}",
      total_ver_proof_duration.checked_div(num_iter).unwrap());
}

