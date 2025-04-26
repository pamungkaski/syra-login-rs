# Syra Issuer Service

A Rust-based Actix-Web service implementing a threshold Distributed Key Generation (DKG) protocol, user-specific key derivation, and zkSNARK proof verification for binding user identities to key shares. Includes a command-line client example to run and distribute DKG shares to peer issuers.

---

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Running the Service](#running-the-service)
    - [/admin/receive_dkg](#adminreceivedkg)
    - [/admin/generate_user_key](#admingenerate_user_key)
- [Proof Verification](#proof-verification)
- [Client Example](#client-example)
- [Logging & Errors](#logging--errors)
- [License](#license)

---

## Features

- **Threshold DKG Initialization** – receive and store your share of the joint public key.
- **User Key Generation** – derive per-user secret keys (`usk` in G1, `usk_hat` in G2) after proof-of-identity verification.
- **zkSNARK Verification** – verify Google-backed Groth16 proofs binding `sub` and `kid`.
- **Client Demo** – sample async client to perform an (n, t) DKG round and broadcast shares.

---

## Prerequisites

- Rust **1.70+**
- `cargo` toolchain
- Actix-Web
- Arkworks (`ark-ec`, `ark-snark`, `ark-ff`, etc.)
- A running Google JWK endpoint (for proof verification)

---

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/your-org/syra-threshold-dkg.git
   cd syra-threshold-dkg
