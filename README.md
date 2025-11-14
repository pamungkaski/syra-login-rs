# SyRA Login – Issuer Service

Implementing: [SyRA: Sybil-Resilient Anonymous Signatures with Applications to Decentralized Identity](https://eprint.iacr.org/2024/379) with OAuth

**Rust/Actix-Web backend for privacy-preserving, Sybil-resilient OAuth 2.0 authentication**

This micro-service supplies the back-end endpoint required by the [SyRA Login Front-End](https://github.com/pamungkaski/syra-login-fe) to mint per-user SyRA key material after a zero-knowledge proof of Google identity.  It:

* Verifies a Groth16 proof that binds the user’s Google **ID token** (`sub`) to the selected Google **JWK** (`kid`).
* Generates the issuer’s master key once at startup and publishes an **IVK bundle** (verification key) derived from it.
* Derives user-specific secret keys `usk`/`usk_hat` and returns them along with the IVK when the proof checks out.

> **Port 9000** is hard-coded and CORS is pre-configured for `http://localhost:8080` (the default FE dev server).

---

## Quick start

```bash
# 1. Prerequisites
#    ✦ Rust ≥ 1.70  (rustup toolchain install stable)
#    ✦ `protoc`    (only if you plan to regenerate Arkworks bindings)

# 2. Clone + build
$ git clone https://github.com/pamungkaski/syra-login-rs.git
$ cd syra-login-rs
$ cargo run --release   # binary ~12 MB
```

You should see:

```
✔ ISK initialized in memory
 Server listening on http://127.0.0.1:9000
```

---

## REST API

| Method | Path                       | Body (JSON)                                                                        | Response 200 (JSON)                                      |
| ------ | -------------------------- | ---------------------------------------------------------------------------------- | -------------------------------------------------------- |
| `POST` | `/admin/generate_user_key` | `{ "user_id": "<jwt.sub>", "kid": "<jwt.header.kid>", "proof": "<base64-proof>" }` | `{ "ivk": "<hex>", "usk": "<hex>", "usk_hat": "<hex>" }` |

* **401** is returned if the Groth16 verification fails.
* **400** is returned if issuer keys are missing (should not happen unless the in-memory state was reset).

### Example

```bash
curl -X POST http://127.0.0.1:9000/admin/generate_user_key \
     -H 'Content-Type: application/json'               \
     -d '{
           "user_id": "113048723091228773641",
           "kid": "f25c5ef3e0df1c0c6e…",
           "proof": "AAEDABv9…base64…"
         }'
```

---

## How it works (high-level)

1. **Issuer key generation** – at launch the server samples an issuer secret key `isk ∈ Fr`, commits to it via `ivk_hat = g2^isk` and two random points `W`, `W_hat`, bundling everything into an *Issuer Verification Key* (`ivk`).
2. **Proof verification** – the client submits a zkSNARK proof showing it controls a Google ID token whose `sub` matches the provided `user_id`, and that the token was signed by the RSA key with modulus limbs embedded in the proof.
3. **User key derivation** – the server hashes `sub` deterministically into the field to get `s`, computes `inv = (s + isk)⁻¹`, and returns `usk = g1^inv`, `usk_hat = g2^inv`.

The resulting triple `(ivk, usk, usk_hat)` allows the user to produce SyRA signatures that any verifier can check purely from `ivk`.

---

## Dependency highlights

* **Actix-Web 4** – HTTP server & CORS
* **Arkworks** (`ark-bn254`, `ark-groth16`, `ark-ec`, `ark-ff`) – pairings & SNARK verification
* **Reqwest + rustls** – fetch Google JWKs over HTTPS
* **tokio** – async runtime (multi-thread)
* **syra** (Dock Network crypto) – SyRA primitives

See `Cargo.toml` for exact versions.

---

## Project layout

```
src/
├─ main.rs               # Actix server + issuer keygen + REST handler
├─ jwt_proof_verifier.rs # Groth16 verifier (BN254)
├─ proof.rs              # Base64 → ark-groth16 Proof utility
└─ verification_key.json # SnarkJS-exported VK (embedded at compile-time)
```

---

## Testing

Run the unit test suite (none yet) or invoke the endpoint locally with the front-end client.  Mock proofs can be generated with Circom + SnarkJS if you have the original circuit.

---

## Roadmap

* [ ] Persist issuer keys to disk instead of RAM-only storage.
* [ ] Optional **threshold DKG** so that multiple issuers can collaborate.
* [ ] Health check endpoint.
* [ ] Dockerfile & CI workflow.

PRs are very welcome!

---

## License

This repository is currently unlicensed; see `LICENSE` once added.
