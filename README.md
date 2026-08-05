# ZKP Authentication Library

Rust workspace for service authentication using non-interactive Schnorr proofs. A service proves knowledge of its secret key without sending the key to another service.

The authentication proof is bound to the HTTP request context. The library also uses timestamps and one-time nonces to prevent replay attacks.

## Workspace structure

schnorr - Schnorr protocol, Fiat–Shamir transcript, key generation, proof generation, and verification.

auth - HTTP authentication context, authentication proof API, and replay protection.

## Main features

generation and verification of non-interactive Schnorr proofs

Fiat-Shamir challenge derivation

binding proofs to HTTP request data

SHA-256 hashing of request bodies

timestamp validation

nonce-based replay protection

serializable keys, contexts, and proofs

## Tests

Run all workspace tests with: `cargo test`