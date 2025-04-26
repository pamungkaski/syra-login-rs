use ark_serialize::CanonicalDeserialize;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose as b64, Engine as _};
use num_bigint::BigUint;
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use proof::base64_to_proof;

// Ark‑circom + Ark‑works -------------------------------------------------------------------------
use ark_bn254::{Bn254, Fr, Fq, Fq2, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_groth16::{Groth16, Proof};
use ark_snark::SNARK;
use ark_ff::{BigInteger256, PrimeField};
use crate::proof;
// -------------------------------------------------------------------------------------------------
//  Constants & embedded assets
// -------------------------------------------------------------------------------------------------

/// Match the limb size used in the Circom input generator.
pub const CHUNK_BITS: usize = 121;

/// Verification key in *SnarkJS JSON* format.
const VK_JSON: &str = include_str!("./verification_key.json");

// -------------------------------------------------------------------------------------------------
//  Google JWK parsing
// -------------------------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kid: String,
    n: String,
    e: String,
    #[serde(rename = "kty")] _kty: String,
    #[serde(rename = "alg")] _alg: String,
}

// -------------------------------------------------------------------------------------------------
//  Verifier
// -------------------------------------------------------------------------------------------------

pub struct Verifier {
    vk: ark_groth16::VerifyingKey<Bn254>,
    http: Client,
}

impl Verifier {
    pub async fn new() -> Result<Self> {
        let vk = parse_vk_json(VK_JSON)?;
        Ok(Self { vk, http: Client::new() })
    }

    pub async fn verify(&self, sub: &str, kid: &str, proof_b64: &str) -> Result<bool, anyhow::Error> {
        // 1. Google key
        let jwk = self.fetch_google_key(kid).await?;

        // 2. RSA modulus → limbs
        let limbs = chunk_modulus(&jwk.n, CHUNK_BITS)?;

        // 3. Public inputs
        // 1) main.sub  (output)  – decimal → Fr
        let sub_big = BigUint::parse_bytes(sub.as_bytes(), 10)
            .ok_or_else(|| anyhow!("sub is not valid decimal"))?;
        let sub_fr  = biguint_to_fr(sub_big);

        let mut public_inputs = vec![sub_fr];   // IC[1]

        // 2) main.pubkey[0..16]  – 17 limbs, little-endian
        public_inputs.extend(limbs.into_iter().map(biguint_to_fr));   // IC[2]..IC[18]

        // 3) main.subStatement   – same value again
        public_inputs.push(sub_fr);             // IC[19]

        // 4. Decode proof
        let proof     = base64_to_proof(&proof_b64)?;

        // 5. Verify (using ark‑circom’s reduction)
        let pvk = Groth16::<Bn254>::process_vk(&self.vk)?;
        let verified = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof)?;
        Ok(verified)
    }

    async fn fetch_google_key(&self, kid: &str) -> Result<Jwk> {
        let set: JwkSet = self
            .http
            .get("https://www.googleapis.com/oauth2/v3/certs")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        set.keys.into_iter()
            .find(|k| k.kid == kid)
            .ok_or_else(|| anyhow!("kid '{kid}' not found"))
    }
}

// -------------------------------------------------------------------------------------------------
//  VK JSON → Ark struct
// -------------------------------------------------------------------------------------------------

fn parse_vk_json(json_str: &str) -> Result<ark_groth16::VerifyingKey<Bn254>> {
    let v: Value = serde_json::from_str(json_str)?;
    Ok(ark_groth16::VerifyingKey {
        alpha_g1: json_to_g1(&v, "vk_alpha_1")?,
        beta_g2:  json_to_g2(&v, "vk_beta_2")?,
        gamma_g2: json_to_g2(&v, "vk_gamma_2")?,
        delta_g2: json_to_g2(&v, "vk_delta_2")?,
        gamma_abc_g1: json_to_g1_vec(&v, "IC")?,
    })
}

// ---- helpers (JSON → points) -------------------------------------------------------------------

fn json_to_g1(v: &Value, key: &str) -> Result<G1Affine> {
    let coords: Vec<String> = v[key].as_array().ok_or_else(|| anyhow!("{key} not array"))?
        .iter().map(|s| s.as_str().unwrap().to_string()).collect();
    Ok(G1Affine::from(G1Projective::new(
        fq_from_dec(&coords[0])?,
        fq_from_dec(&coords[1])?,
        fq_from_dec(&coords[2])?,
    )))
}

fn json_to_g1_vec(v: &Value, key: &str) -> Result<Vec<G1Affine>> {
    let list = v[key].as_array().ok_or_else(|| anyhow!("{key} not array"))?;
    list.iter().map(|triple| {
        let coords: Vec<String> = triple.as_array().unwrap()
            .iter().map(|s| s.as_str().unwrap().to_string()).collect();
        Ok(G1Affine::from(G1Projective::new(
            fq_from_dec(&coords[0])?,
            fq_from_dec(&coords[1])?,
            fq_from_dec(&coords[2])?,
        )))
    }).collect()
}

fn json_to_g2(v: &Value, key: &str) -> Result<G2Affine> {
    let arr = v[key].as_array().ok_or_else(|| anyhow!("{key} not array"))?;
    let x = Fq2::new( fq_from_dec(arr[0][0].as_str().unwrap())?, fq_from_dec(arr[0][1].as_str().unwrap())? );
    let y = Fq2::new( fq_from_dec(arr[1][0].as_str().unwrap())?, fq_from_dec(arr[1][1].as_str().unwrap())? );
    let z = Fq2::new( fq_from_dec(arr[2][0].as_str().unwrap())?, fq_from_dec(arr[2][1].as_str().unwrap())? );
    Ok(G2Affine::from(G2Projective::new(x, y, z)))
}

fn fq_from_dec(s: &str) -> Result<Fq> {
    // 1. parse the decimal string
    let n = BigUint::parse_bytes(s.as_bytes(), 10)
        .ok_or_else(|| anyhow!("invalid decimal"))?;

    // 2. fit it into 256 bits
    let bi = BigInteger256::try_from(n)
        .map_err(|_| anyhow!("value doesn't fit into 256 bits"))?;

    // 3. turn it into an Fq element
    Fq::from_bigint(bi)
        .ok_or_else(|| anyhow!("integer is not a canonical Fq element"))
}

// -------------------------------------------------------------------------------------------------
//  Misc helpers
// -------------------------------------------------------------------------------------------------

fn chunk_modulus(n_b64url: &str, chunk_bits: usize) -> Result<Vec<BigUint>> {
    let n_bytes = b64::URL_SAFE_NO_PAD.decode(n_b64url)?;
    let mut n = BigUint::from_bytes_be(&n_bytes);
    let mask = (BigUint::from(1u32) << chunk_bits) - BigUint::from(1u32);
    let mut limbs = Vec::new();
    while n > BigUint::default() {
        limbs.push(&n & &mask);
        n >>= chunk_bits;
    }
    Ok(limbs)
}

fn hash_to_fr(data: &[u8]) -> Fr {
    let mut tmp = [0u8; 32];
    tmp.copy_from_slice(blake3::hash(data).as_bytes());
    Fr::from_le_bytes_mod_order(&tmp)
}

fn biguint_to_fr(x: BigUint) -> Fr {
    Fr::from_le_bytes_mod_order(&x.to_bytes_le())
}
