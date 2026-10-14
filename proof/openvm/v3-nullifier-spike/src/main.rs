use openvm::io::{read_vec, reveal_u32};
use psp_openvm_v3_nullifier_spike::{spend_v3, verify_v3_nullifier_witness};

fn main() {
    let witness = read_vec();
    let public_statement_digest = if witness.starts_with(spend_v3::SPEND_WITNESS_MAGIC) {
        spend_v3::verify_v3_spend_witness(&witness)
    } else {
        verify_v3_nullifier_witness(&witness)
    }
    .expect("V3 nullifier/spend candidate relation rejected its witness");

    // The high-level openvm::io::reveal_u32 API takes a WORD INDEX and
    // multiplies it by four internally. Writing indexes 0..15 therefore emits
    // the contiguous digest at byte offsets 0, 4, ..., 60.
    for (index, chunk) in public_statement_digest.chunks_exact(4).enumerate() {
        let word = u32::from_le_bytes(chunk.try_into().expect("four-byte digest chunk"));
        reveal_u32(word, index);
    }
}
