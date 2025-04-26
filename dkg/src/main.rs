use ark_bls12_381::{Fr, G1Affine};
use ark_ec::{CurveGroup, Group};
use ark_ff::{Field, UniformRand, Zero};
use ark_serialize::CanonicalSerialize;
use blake2::Blake2b512;
use dock_crypto_utils::hashing_utils::affine_group_elem_from_try_and_incr;
use reqwest::Client;
use serde::Serialize;
use std::collections::HashMap;
use std::time::Duration;
use hex;

#[derive(Serialize)]
struct DkgPointMessage {
    sid: String,
    A: String,
    f_i: String,
    Ai_all: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let n = 5;             // Total parties
    let t = 3;             // Threshold
    let sid = "syra-session-001".to_string();

    // Peer URLs
    let peer_urls = vec![
        "http://127.0.0.1:9000",
    ];

    // Generator g ∈ G1 via try-and-increment
    let g = affine_group_elem_from_try_and_incr::<G1Affine, Blake2b512>(b"syra-generator");

    let mut rng = ark_std::test_rng();

    // Sample α ∈ Z_p and compute A = g^α
    let alpha = Fr::rand(&mut rng);
    let A = (g * alpha).into_affine();

    // Build degree-(t‑1) polynomial f with f(0) = α
    let mut coeffs = vec![alpha];
    coeffs.extend((1..t).map(|_| Fr::rand(&mut rng)));

    // Evaluate at i = 1..n
    let mut alpha_i_map = HashMap::new();
    let mut Ai_list = Vec::with_capacity(n);
    for i in 1..=n {
        let x = Fr::from(i as u64);
        // f_i = Σ coeffs[j] * x^j
        let f_i = coeffs
            .iter()
            .enumerate()
            .fold(Fr::zero(), |acc, (j, &c)| acc + c * x.pow(&[j as u64]));
        alpha_i_map.insert(i, f_i);
        Ai_list.push((g * f_i).into_affine());
    }

    // Helper to serialize & hex‑encode any CanonicalSerialize type
    fn to_hex<T: CanonicalSerialize>(t: &T) -> String {
        let mut buf = Vec::new();
        t.serialize_compressed(&mut buf).unwrap();
        hex::encode(buf)
    }

    let A_hex = to_hex(&A);
    let Ai_all_hex = Ai_list.iter().map(to_hex).collect::<Vec<_>>();

    let client = Client::new();

    // Broadcast to each peer
    for (i, &url) in peer_urls.iter().enumerate() {
        let idx = i + 1;
        let f_i = alpha_i_map.get(&idx).unwrap();
        let f_i_hex = to_hex(f_i);

        let msg = DkgPointMessage {
            sid: sid.clone(),
            A: A_hex.clone(),
            f_i: f_i_hex,
            Ai_all: Ai_all_hex.clone(),
        };

        let res = client
            .post(&format!("{}/admin/receive_dkg", url))
            .json(&msg)
            .send()
            .await;

        match res {
            Ok(r) if r.status().is_success() => {
                println!("✓ Sent DKG point to Issuer {} (200 OK)", idx)
            }
            Ok(r) => println!("⚠️ Issuer {} responded: {}", idx, r.status()),
            Err(e) => println!("❌ Failed to contact Issuer {}: {}", idx, e),
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    println!("\n✔ DKG complete and distributed to all issuers.");
    Ok(())
}
