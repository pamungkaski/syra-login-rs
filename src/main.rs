use std::ops::{AddAssign, MulAssign};
use ark_ff::UniformRand;
mod jwt_proof_verifier;
mod proof;

use actix_cors::Cors;
use actix_web::{http::header,post, web, App, HttpServer, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use ark_std::rand::{CryptoRng, RngCore, rngs::OsRng};

use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField, Zero, One};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use unicode_normalization::UnicodeNormalization;
use blake2::{Blake2b512, Digest};
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

#[derive(Serialize)]
struct GenerateKeyResponse {
    ivk: String,
    usk: String,
    usk_hat: String,
}
/// Holds your issuer’s key material once generated.
pub struct StoredIssuerKeys {
    pub bp:       Bp,
    pub isk:      Fr,
    pub ivk_hat:  G2Affine,
    pub W:        G1Affine,
    pub W_hat:    G2Affine,
}

/// Pairing‐group description (just the two generators here).
#[derive(Clone)]
pub struct Bp {
    pub g1: G1Affine,
    pub g2: G2Affine,
}

/// What you publish as your “verification key bundle.”
#[derive(Clone)]
pub struct IvkBundle {
    pub bp:      Bp,
    pub ivk_hat: G2Affine,
    pub W:       G1Affine,
    pub W_hat:   G2Affine,
}

impl IvkBundle {
    /// Serialize the entire bundle as
    /// g1 ∥ g2 ∥ ivk_hat ∥ W ∥ W_hat
    /// where each element is in its compressed form.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.bp.g1.serialize_compressed(&mut buf).unwrap();
        self.bp.g2.serialize_compressed(&mut buf).unwrap();
        self.ivk_hat.serialize_compressed(&mut buf).unwrap();
        self.W.serialize_compressed(&mut buf).unwrap();
        self.W_hat.serialize_compressed(&mut buf).unwrap();
        buf
    }

    /// Hex-encode the above byte sequence into one big string.
    pub fn to_hex_string(&self) -> String {
        hex::encode(self.to_bytes())
    }
}

/// Shared application state — at most one generation allowed.
pub struct AppState {
    pub issuer_keys: Mutex<Option<StoredIssuerKeys>>,
    pub verifier: Arc<Verifier>,
}

/// Errors during key generation.
#[derive(thiserror::Error, Debug)]
pub enum KeygenError {
    #[error("issuer keys already generated")]
    AlreadyGenerated,
}

pub fn generate_issuer_keys(
    state: &AppState,
) -> Result<IvkBundle, KeygenError>{
    let mut guard = state.issuer_keys.lock().unwrap();
    if guard.is_some() {
        return Err(KeygenError::AlreadyGenerated);
    }

    // 1) GrGen: derive g1 ∈ G1 and g2 ∈ G2 
    let g1 = affine_group_elem_from_try_and_incr::<G1Affine, Blake2b512>(b"syra-generator-1");
    let g2 = affine_group_elem_from_try_and_incr::<G2Affine, Blake2b512>(b"syra-generator-2");
    let bp = Bp { g1, g2 };

    // Prepare a secure RNG
    let mut rng = OsRng;

    // 2) Sample isk ∈ Fr
    let isk = Fr::rand(&mut rng);
    let isk_clone =  isk.clone();

    // 3) Sample two fresh group elements W = g1^r₁, W_hat = g2^r₂
    let r1 = Fr::rand(&mut rng);
    let r2 = Fr::rand(&mut rng);
    let W     = (G1Projective::from(bp.g1) * r1).into_affine();
    let W_hat = (G2Projective::from(bp.g2) * r2).into_affine();

    // 4) Compute ivk_hat = g2^isk
    let ivk_hat = (G2Projective::from(bp.g2) * isk).into_affine();

    // 5) Bundle public IVK
    let ivk = IvkBundle { bp: bp.clone(), ivk_hat, W, W_hat };

    // 6) Store everything for future use
    *guard = Some(StoredIssuerKeys {
        bp,
        isk:     isk_clone,   // <-- clone here
        ivk_hat,
        W,
        W_hat,
    });

    println!("✔ ISK initialized in memory");
    Ok(ivk)
}

const TAG: &[u8] = b"syra-user-id";

/// Deterministic hash-to-field:  sub  →  s ∈ Fr  (never 0).
pub fn s_from_sub<S: AsRef<str>>(sub: S) -> Fr {
    let mut acc = Fr::zero();

    for &byte in sub.as_ref().as_bytes() {
        acc.mul_assign(Fr::from(256u64));      // acc *= 256
        acc.add_assign(Fr::from(byte as u64)); // acc += byte
    }

    if acc.is_zero() { Fr::one() } else { acc } // avoid 0 just like TS
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
    let lock = state.issuer_keys.lock().unwrap();

    let stored = if let Some(s) = &*lock {
        s.clone()
    } else {
        return Err(actix_web::error::ErrorBadRequest("DKG state not initialized; call /admin/receive_dkg first"));
    };

    println!("{}", req.proof);

    println!("{}", req.kid);

    println!("{}", req.user_id);

    // 1) verify proof
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

    // 2) Derive s ∈ Fr from user_id
    let s: Fr = s_from_sub(req.user_id.clone());
    let mut le32 = [0u8; 32];
    s.serialize_compressed(&mut le32[..]).unwrap();   // LE, 0-padded
    println!("s (32-byte LE) = {}", hex::encode(le32));
    let isk = stored.isk.clone();

    let inv = (s + isk)
        .inverse()
        .expect("s + isk_i not invertible");

    // 4) usk = g1^invR
    let usk_pt = (G1Projective::from(stored.bp.g1) * inv.clone()).into_affine();
    let mut buf_usk = Vec::new();
    usk_pt.serialize_compressed(&mut buf_usk).unwrap();
    let usk = hex::encode(buf_usk);

    // 5) usk_hat = g2^invR
    let usk_hat_pt = (G2Projective::from(stored.bp.g2) * inv.clone()).into_affine();
    let mut buf_usk_hat = Vec::new();
    usk_hat_pt.serialize_compressed(&mut buf_usk_hat).unwrap();
    let usk_hat = hex::encode(buf_usk_hat);

    let ivk_hex = IvkBundle {
        bp:       stored.bp.clone(),
        ivk_hat:  stored.ivk_hat,
        W:        stored.W,
        W_hat:    stored.W_hat,
    }.to_hex_string();

    let resp = GenerateKeyResponse {
        ivk: ivk_hex,
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
        issuer_keys: Mutex::new(None),
        verifier,
    });
    generate_issuer_keys(&state)
        .unwrap_or_else(|e| panic!("failed to generate issuer keys: {:?}", e));

    println!("🔧 Server listening on http://127.0.0.1:9000");
    HttpServer::new(move || {
        // configure CORS
        let cors = Cors::default()
            // allow your Next.js origin
            .allowed_origin("http://localhost:8080")
            // allow the POST and OPTIONS methods
            .allowed_methods(vec!["POST", "OPTIONS"])
            // allow Content-Type header
            .allowed_header(header::CONTENT_TYPE)
            // set how long the preflight is cached (in seconds)
            .max_age(3600);

        App::new()
            .wrap(cors)
            .app_data(state.clone())
            .service(generate_user_key)
    })
        .bind("127.0.0.1:9000")?
        .run()
        .await
}