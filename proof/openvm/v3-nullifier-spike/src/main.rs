use openvm::io::{read_vec, reveal_bytes32};
use psp_openvm_v3_nullifier_spike::{spend_v3, verify_v3_nullifier_witness};

fn main() {
    let witness = read_vec();
    let public_statement_digest = if witness.starts_with(spend_v3::SPEND_WITNESS_MAGIC) {
        spend_v3::verify_v3_spend_witness(&witness)
    } else {
        verify_v3_nullifier_witness(&witness)
    }
    .expect("V3 nullifier/spend candidate relation rejected its witness");
    reveal_bytes32(public_statement_digest);
}
