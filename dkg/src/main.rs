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


/// # Workflow
/// 1. Derive generator `g ∈ G1` via try-and-increment.  
/// 2. Sample secret `α ∈ Fr` and compute public `A = g^α`.  
/// 3. Build random polynomial `f(x)` of degree `t−1` with `f(0)=α`.  
/// 4. For each i in 1..=n:  
///    - Evaluate share `f_i = f(i)`.  
///    - Compute commitment `A_i = g^{f_i}`.  
/// 5. Serialize and hex-encode `A`, each `f_i`, and the list of all `A_i`.  
/// 6. For each peer URL, construct a `DkgPointMessage { sid, A, f_i, Ai_all }`  
///    and send it via `POST /admin/receive_dkg`.  
/// 7. Log success or failure for each peer, sleeping 100 ms between requests.  
/// 8. Print completion confirmation when done.
///
/// # Pseudocode
/// ```text
/// // Setup parameters
/// n ← 5; t ← 3; sid ← "syra-session-001"
/// peer_urls ← ["http://127.0.0.1:9000"]
///
/// // Generator in G1
/// g ← hash_to_G1("syra-generator")
///
/// // Sample secret and compute public A
/// α ← random_Fr()
/// A ← g^α
///
/// // Build polynomial f of degree t−1 with f(0)=α
/// coeffs ← [α] + [random_Fr() for _ in 1..t]
///
/// // Evaluate shares and commitments
/// for i in 1..=n:
///     x ← Fr::from(i)
///     f_i ← evaluate_polynomial(coeffs, x)
///     A_i ← g^f_i
///     store f_i in alpha_i_map[i]
///     append A_i to Ai_list
///
/// // Hex-encode values
/// A_hex ← hex_encode(A)
/// Ai_all_hex ← [hex_encode(A_i) for A_i in Ai_list]
///
/// // Broadcast to peers
/// for (index, url) in peer_urls:
///     f_i_hex ← hex_encode(alpha_i_map[index+1])
///     msg ← { sid, A: A_hex, f_i: f_i_hex, Ai_all: Ai_all_hex }
///     res ← HTTP_POST(url + "/admin/receive_dkg", json=msg)
///     if res.status is success:
///         log("✓ Sent DKG point to Issuer {} (200 OK)", index+1)
///     else:
///         log("⚠️ Issuer {} responded: {}", index+1, res.status)
///     sleep(100 ms)
///
/// log("✔ DKG complete and distributed to all issuers.")
/// ```
///
/// # Errors
/// Returns an error if any cryptographic operation, serialization, or HTTP request fails.
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
