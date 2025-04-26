use anyhow::{anyhow, bail, ensure, Context, Result};
use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_groth16::Proof;
use base64;
use num_bigint::BigUint;
use serde::Deserialize;
use std::io::Cursor;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
// ─────────────────── helpers ────────────────────

fn str_to_fq(s: &str) -> Result<Fq> {
    // accept decimal or 0x-hex
    let (digits, radix) = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        (hex, 16)
    } else {
        (s, 10)
    };
    let n = BigUint::parse_bytes(digits.as_bytes(), radix)
        .ok_or_else(|| anyhow!("invalid integer {:?}", s))?;
    Ok(Fq::from_be_bytes_mod_order(&n.to_bytes_be()))
}

// ─────────────────── JSON shape ─────────────────

#[derive(Debug, Deserialize)]
struct JsProof {
    pi_a: [String; 3],
    pi_b: [[String; 2]; 3], // row0=x, row1=y, row2=[1,0]
    pi_c: [String; 3],
}

// ─────────────────── converters ──────────────────

fn proof_from_snarkjs_json(json: &str) -> Result<Proof<Bn254>> {
    let p: JsProof = serde_json::from_str(json)?;

    // --- A -----------------------------------------------------------
    let g1: G1Affine = G1Projective::new_unchecked(
        str_to_fq(&p.pi_a[0])?,          // instead of (&p.pi_a[0]).into()
        str_to_fq(&p.pi_a[1])?,          // instead of (&p.pi_a[1]).into()
        str_to_fq(&p.pi_a[2])?,          // instead of (&p.pi_a[2]).into()
    )
        .into();

    // --- B -----------------------------------------------------------
    let g2: G2Affine = G2Projective::new_unchecked(
        Fq2::new(
            str_to_fq(&p.pi_b[0][0])?,   
            str_to_fq(&p.pi_b[0][1])?,   
        ),
        Fq2::new(
            str_to_fq(&p.pi_b[1][0])?,   
            str_to_fq(&p.pi_b[1][1])?,   
        ),
        Fq2::new(
            str_to_fq(&p.pi_b[2][0])?,  
            str_to_fq(&p.pi_b[2][1])?,   
        ),
    )
        .into();

    // --- C -----------------------------------------------------------
    let g3: G1Affine = G1Projective::new_unchecked(
        str_to_fq(&p.pi_c[0])?,          
        str_to_fq(&p.pi_c[1])?,          
        str_to_fq(&p.pi_c[2])?,          
    )
        .into();

    Ok(Proof { a: g1, b: g2, c: g3 })
}


fn proof_from_ark_bytes(raw: &[u8]) -> Result<Proof<Bn254>> {
    let mut cur = Cursor::new(raw);
    match raw.len() {
        259 => Ok(Proof::<Bn254>::deserialize_uncompressed(&mut cur)
            .context("uncompressed deserialize failed")?),
        192 => Ok(Proof::<Bn254>::deserialize_compressed(&mut cur)
            .context("compressed deserialize failed")?),
        n => bail!("unknown proof binary size: {n} bytes"),
    }
}

/// Unified entry-point: give it the **base-64 string** you receive from the
/// client (could be raw Ark bytes, could be SnarkJS JSON). It returns an Ark
/// `Proof<Bn254>` or an error.
pub fn base64_to_proof(b64: &str) -> Result<Proof<Bn254>> {
    let bytes = base64::decode(b64.trim())?;

    // branch A: looks like UTF-8 JSON
    if let Ok(txt) = std::str::from_utf8(&bytes) {
        if txt.trim_start().starts_with('{') {
            return proof_from_snarkjs_json(txt);
        }
    }

    // branch B: assume Ark binary
    proof_from_ark_bytes(&bytes)
}

// (optional) Ark proof → base-64 (uncompressed)
pub fn proof_to_base64_uncompressed(p: &Proof<Bn254>) -> Result<String> {
    let mut buf = Vec::with_capacity(259);
    p.serialize_uncompressed(&mut buf)?;
    Ok(base64::encode(buf))
}
