# Proof-System Feasibility — Current Obstruction and Decision Record

**Status:** Feasibility analysis, not a proof of impossibility and not an implementation specification.

## Executive summary

The current LoTRS selection proof is designed for a particular family of lattice relations. The 0PSP nullifier relation uses SHAKE256, a bit-level sponge with nonlinear Keccak operations. Merely appending a coin commitment or other linear data to a LoTRS selection vector does not prove that a public nullifier is the hash of a hidden input.

This is a scope statement about the documented proof relation, not an impossibility theorem for all lattice zero-knowledge proofs. A separately designed proof system might express the hash relation; its security and cost must be demonstrated.

## What the LoTRS selection layer must prove

Let the public structured key table be \(P\) and let \(b\) be a hidden one-hot selection vector. The existing construction proves a relation tailored to its table and signature equations. If coin data is appended to each column, a modified selection proof may be able to bind a selected linear commitment to the same index. That modification is not shown to prove a SHAKE computation.

## Why SHAKE is a separate relation

The intended nullifier statement is:

\[
\nu=\operatorname{SHAKE256}_{384}(\mathsf{domain}\parallel\mathsf{version}\parallel coin\_id\parallel r_{\mathrm{nf}}).
\]

Keccak-f[1600] has nonlinear bit-level operations. A linear relation proof over a polynomial ring cannot evaluate those gates merely by appending more linear columns. A separate nonlinear proof system or a different nullifier construction is required.

For a 90-byte input, one SHAKE256 rate block is sufficient under the fixed proposed encoding. A count of \(24\times1600=38{,}400\) chi-layer bit operations is not a full AIR constraint count, proof size, or runtime estimate.

## Architecture options

### Option A: Extended LoTRS relation plus auxiliary STARK

Specify a concrete bridge commitment, then prove in the lattice layer that the selected hidden coin opens to the same bridge value bound to the wallet key and authorization. The STARK must prove the bridge opening and hash relation. Both systems must use exactly the same canonical input, public commitment and parameters. This path requires a real lattice commitment with demonstrated hiding and binding; the bare equation \(B=A_1m_x+A_2\tau_B\bmod q\) does not establish those properties.

### Option B: A proof system that natively handles the full relation

Evaluate another lattice-based or post-quantum proof system that can establish coin membership, authorization and the hash relation within one compatible proof. Its security reduction and concrete costs need independent analysis.

### Option C: Change the nullifier construction

Investigate a nullifier function whose correctness relation is efficient to prove in the selected system. Any replacement must still provide deterministic asset binding, collision safety, unlinkability, and resistance to unauthorized/nullifier-substitution spends under an explicit model.

## Cost claims

The previous proof-size figures of roughly 35–48 KiB for the hash proof and 90–100 KiB or 118.62–119.75 KiB for the combined package are unverified projections. They must not be presented as benchmark results. A valid comparison requires a compiled implementation, exact AIR and backend configuration, actual zero-knowledge mode, serialized proof sizes, runtime, peak memory, and explicit soundness parameters.

Plonky3 is a toolkit with multiple backends. Its documented BinaryPcs example is explicitly not zero knowledge. A hiding PCS in another configuration would not alone establish zero knowledge of all application witnesses or transcript fields.

Sources:
- LoTRS: https://eprint.iacr.org/2026/974 and https://github.com/lotrs-sig/lotrs
- Plonky3 documentation: https://github.com/Plonky3/Plonky3/blob/main/README.md and https://github.com/Plonky3/Plonky3/blob/main/docs/architecture.md
- SHAKE specification: https://csrc.nist.gov/pubs/fips/202/final

## Decision

The SHAKE equation is not natively established by the current LoTRS selection proof as documented. This is not a general impossibility result. The cross-layer bridge and complete proof system remain open research tasks; no cryptographic implementation GO decision is made by this document.
