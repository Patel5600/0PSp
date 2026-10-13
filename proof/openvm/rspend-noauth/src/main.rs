use openvm::io::{read_vec, reveal_bytes32};
use psp_openvm_rspend_noauth::verify_noauth_witness;

fn main() {
    let witness = read_vec();
    let public_digest = verify_noauth_witness(&witness)
        .expect("partial NOAUTH spend relation validation failed");
    reveal_bytes32(public_digest);
}
