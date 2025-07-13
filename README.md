# Syra Issuer Service

A Rust-based Actix-Web service implementing SyRQ single issuer key generation.

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
   cd syra-login-rs
