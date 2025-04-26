mod jwt_proof_verifier;
mod proof;

use actix_web::{post, web, App, HttpServer, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

use ark_bls12_381::{Fr, G1Affine, G2Affine};
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake2::Blake2b512;
use dock_crypto_utils::hashing_utils::{
    affine_group_elem_from_try_and_incr,
    field_elem_from_try_and_incr,
};
use jwt_proof_verifier::Verifier;

use hex;

#[derive(Deserialize)]
struct DkgPointMessage {
    A: String,
    f_i: String,
    Ai_all: Vec<String>,
}

#[derive(Deserialize)]
struct GenerateKeyRequest {
    /// plain‐text user identifier
    user_id: String,
    kid: String,       // Google key-id
    proof: String,
}

#[derive(Serialize, Clone)]
struct StoredDkgState {
    /// group public key A = g^α
    ivk: String,
    /// this node’s secret share r_i
    isk_i: String,
    /// this node’s commitment ĭvk_i = g^{r_i}
    hat_ivk_i: String,
    /// all commitments from the DKG: [g^{f(1)}, …, g^{f(n)}]
    Ai_all: Vec<String>,
}

#[derive(Serialize)]
struct GenerateKeyResponse {
    ivk: String,
    usk: String,
    usk_hat: String,
}

struct AppState {
    /// None until receive_dkg runs; then Some(state) forever
    dkg: Mutex<Option<StoredDkgState>>,
    verifier: Arc<Verifier>,
}

/// # Arguments
/// * `state: web::Data<AppState>`  
///   Shared application state containing a `Mutex<Option<StoredDkgState>>` for DKG data.  
/// * `msg: web::Json<DkgPointMessage>`  
///   The JSON body with fields:  
///   - `A: String` — the aggregated public key point in G1 (hex-compressed).  
///   - `f_i: String` — this node’s secret share in Fr (hex-compressed).  
///   - `Ai_all: Vec<String>` — all participants’ public points for audit/logging.  
///
/// # Returns
/// - `200 OK` with body `"OK"` on success or if already initialized.  
///
/// # Pseudocode
/// ```text
/// // 0) Acquire lock on DKG state
/// lock = state.dkg.lock()
///
/// // 1) If already initialized, skip further processing
/// if lock.is_some():
///     log("DKG already initialized; skipping")
///     return Ok("OK")
///
/// // 2) Deserialize A ∈ G1Affine from hex
/// A_bytes    = hex::decode(msg.A)
/// _ivk_pt    = G1Affine::deserialize_compressed(A_bytes)
///
/// // 3) Deserialize r_i ∈ Fr from hex
/// fi_bytes   = hex::decode(msg.f_i)
/// isk_i      = Fr::deserialize_compressed(fi_bytes)
///
/// // 4) Recompute generator g1 in G1
/// g1         = affine_group_elem_from_try_and_incr("syra-generator")
///
/// // 5) Compute this node’s partial IVK share ĭvk_i = g1 * r_i
/// hat_ivk_i_pt = (g1 * isk_i).into_affine()
/// hat_ivk_i    = hex::encode( hat_ivk_i_pt.serialize_compressed() )
///
/// // 6) Store ivk, isk_i, hat_ivk_i, and Ai_all in memory
/// stored = StoredDkgState {
///     ivk: msg.A,
///     isk_i: msg.f_i,
///     hat_ivk_i,
///     Ai_all: msg.Ai_all.clone(),
/// }
/// *lock = Some(stored)
///
/// log("DKG state initialized in memory")
/// return Ok("OK")
/// ```
///
/// # Notes
/// - Subsequent calls simply return `"OK"` without reinitializing.
/// - Panics if hex decoding or deserialization fails, indicating malformed input.
///
#[post("/admin/receive_dkg")]
async fn receive_dkg(
    state: web::Data<AppState>,
    msg: web::Json<DkgPointMessage>,
) -> impl Responder {
    let mut lock = state.dkg.lock().unwrap();

    // If we already have DKG state, skip
    if lock.is_some() {
        println!("⚠️ DKG already initialized; skipping");
        return HttpResponse::Ok().body("OK");
    }

    // 1) Deserialize A ∈ G1Affine
    let a_bytes = hex::decode(&msg.A).expect("invalid hex for A");
    let _ivk_pt = G1Affine::deserialize_compressed(&mut &a_bytes[..])
        .expect("failed to deserialize A");

    // 2) Deserialize r_i ∈ Fr
    let fi_bytes = hex::decode(&msg.f_i).expect("invalid hex for f_i");
    let isk_i = Fr::deserialize_compressed(&mut &fi_bytes[..])
        .expect("failed to deserialize f_i");

    // 3) Recompute g ∈ G1
    let g1 = affine_group_elem_from_try_and_incr::<G1Affine, Blake2b512>(b"syra-generator");

    // 4) Compute ĭvk_i = g1 * r_i
    let hat_ivk_i_pt = (g1 * isk_i).into_affine();
    let mut buf = Vec::new();
    hat_ivk_i_pt.serialize_compressed(&mut buf).unwrap();
    let hat_ivk_i = hex::encode(buf);

    // 5) Store everything in memory
    let stored = StoredDkgState {
        ivk: msg.A.clone(),
        isk_i: msg.f_i.clone(),
        hat_ivk_i,
        Ai_all: msg.Ai_all.clone(),
    };
    *lock = Some(stored);

    println!("✔ DKG state initialized in memory");
    HttpResponse::Ok().body("OK")
}

/// # Arguments
/// * `state: web::Data<AppState>`  
///   Shared application state, containing:
///   - `dkg: Option<DKGState>`: holds the server’s distributed key share (must be present).  
///   - `verifier`: a proof verifier for user identity.  
/// * `req: web::Json<GenerateKeyRequest>`  
///   The JSON body with fields:  
///   - `user_id: String` — the client’s identifier.  
///   - `kid: String` — key identifier.  
///   - `proof: String` — a cryptographic proof binding `user_id` and `kid`.  
///
/// # Returns
/// - `200 OK` with JSON `GenerateKeyResponse { ivk, usk, usk_hat }` on success.  
/// - `400 Bad Request` if the DKG state is not initialized.  
/// - `401 Unauthorized` if proof verification fails or the proof is invalid.  
///
/// # Pseudocode
/// ```text
/// // 1) Ensure DKG has been run and retrieve stored state
/// if state.dkg is None:
///     return BadRequest("DKG not initialized")
/// stored = state.dkg.clone()
///
/// // 2) Verify the user’s proof
/// verified = verifier.verify(req.user_id, req.kid, req.proof)
/// if not verified:
///     return Unauthorized("invalid proof")
///
/// // 3) Derive field element s = H_to_Fr(user_id)
/// s = field_elem_from_try_and_incr(user_id.bytes)
///
/// // 4) Deserialize this node’s secret share isk_i
/// isk_i_bytes = hex::decode(stored.isk_i)
/// isk_i = Fr.deserialize(isk_i_bytes)
///
/// // 5) Compute inv = (s + isk_i)^{-1} in the field Fr
/// inv = (s + isk_i).inverse()
///
/// // 6) Hash to group generators g1 (in G1) and g2 (in G2)
/// g1 = H_to_G1("syra-generator")
/// g2 = H_to_G2("syra-generator-2")
///
/// // 7) Exponentiate generators by inv to get the user’s secret keys
/// usk    = hex_encode(g1 * inv)
/// usk_hat= hex_encode(g2 * inv)
///
/// // 8) Respond with the public IVK plus the two secret key shares
/// return Ok(GenerateKeyResponse { ivk: stored.ivk, usk, usk_hat })
/// ```
///
/// # Errors
/// - Returns `400 Bad Request` if the DKG state is uninitialized.
/// - Returns `401 Unauthorized` if proof verification fails or if inversion in the field is impossible.
///
#[post("/admin/generate_user_key")]
async fn generate_user_key(
    state: web::Data<AppState>,
    req: web::Json<GenerateKeyRequest>,
) -> Result<HttpResponse, actix_web::Error> {
    let lock = state.dkg.lock().unwrap();

    // Ensure DKG has been run
    let stored = if let Some(s) = &*lock {
        s.clone()
    } else {
        return Err(actix_web::error::ErrorBadRequest("DKG state not initialized; call /admin/receive_dkg first"));
    };

    // verify proof
    let verifier = state.verifier.clone();
    let sub   = req.user_id.clone();
    let kid   = req.kid.clone();
    let proof = req.proof.clone();

    let verified = state
        .verifier
        .verify(&req.user_id, &req.kid, &req.proof)
        .await
        .map_err(|e| {
            log::warn!("proof verification failed: {e}");
            actix_web::error::ErrorUnauthorized("invalid proof")
        })?;

    if !verified {
        return Err(actix_web::error::ErrorUnauthorized("invalid proof"));
    }


    // 1) Derive s ∈ Fr from user_id
    let s: Fr = field_elem_from_try_and_incr::<Fr, Blake2b512>(req.user_id.as_bytes());

    // 2) Deserialize isk_i
    let isk_bytes = hex::decode(&stored.isk_i).expect("invalid hex for isk_i");
    let isk_i = Fr::deserialize_compressed(&mut &isk_bytes[..])
        .expect("failed to deserialize isk_i");

    // 3) Compute inverse exponent 1/(s + isk_i)
    let inv = (s + isk_i)
        .inverse()
        .expect("s + isk_i not invertible");

    // 4) Generators in G1 and G2
    let g1 = affine_group_elem_from_try_and_incr::<G1Affine, Blake2b512>(b"syra-generator");
    let g2 = affine_group_elem_from_try_and_incr::<G2Affine, Blake2b512>(b"syra-generator-2");

    // 5) usk = g1^inv
    let usk_pt = (g1 * inv).into_affine();
    let mut buf_usk = Vec::new();
    usk_pt.serialize_compressed(&mut buf_usk).unwrap();
    let usk = hex::encode(buf_usk);

    // 6) usk_hat = g2^inv
    let usk_hat_pt = (g2 * inv).into_affine();
    let mut buf_usk_hat = Vec::new();
    usk_hat_pt.serialize_compressed(&mut buf_usk_hat).unwrap();
    let usk_hat = hex::encode(buf_usk_hat);

    let resp = GenerateKeyResponse {
        ivk: stored.ivk.clone(),
        usk,
        usk_hat,
    };
    
    Ok(HttpResponse::Ok().json(resp))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let verifier = Arc::new(
        Verifier::new()
            .await
            .expect("failed to initialise Groth16 verifier"),
    );
    let state = web::Data::new(AppState {
        dkg: Mutex::new(None),
        verifier,
    });

    println!("🔧 Server listening on http://127.0.0.1:9000");
    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .service(receive_dkg)
            .service(generate_user_key)
    })
        .bind("127.0.0.1:9000")?
        .run()
        .await
}
