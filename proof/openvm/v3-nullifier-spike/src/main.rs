use openvm::io::{read_vec, reveal_bytes32};
use psp_openvm_v3_nullifier_spike::verify_v3_nullifier_witness;

fn main() {
    let witness = read_vec();
    let public_statement_digest = verify_v3_nullifier_witness(&witness)
        .expect("V3 nullifier feasibility-spike relation rejected its witness");
    reveal_bytes32(public_statement_digest);
}
