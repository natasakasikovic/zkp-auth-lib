# zkp-auth-lib

A Rust library for authenticating service-to-service HTTP requests with non-interactive Zero-Knowledge Proofs, instead of API keys, bearer tokens, or mTLS client certificates.

A service proves it holds a secret key — without ever sending that key, or any other static secret, over the wire. The proof is a non-interactive **Schnorr proof** (discrete-log based, over the Ristretto255 group from [`curve25519-dalek`](https://github.com/dalek-cryptography/curve25519-dalek)), made non-interactive via the **Fiat–Shamir transform**.

Unlike a bare Schnorr proof, a proof produced by this library is bound to a *specific HTTP request*: the target service, method, path, and a hash of the body all feed into the challenge. Change any one of them after the proof is formed — swap the path, tamper with the body — and the proof no longer verifies. A timestamp window plus one-time nonces (`ReplayProtector`) additionally stop a captured, otherwise-valid proof from being replayed.

See it wired into a running system in [zkp-auth-demo](https://github.com/natasakasikovic/zkp-auth-demo) — three Axum microservices authenticating their internal calls with this library.

## Workspace layout

| Crate | Responsibility |
|---|---|
| [`schnorr`](schnorr) | Pure protocol: the Ristretto group, key types, Fiat–Shamir transcript, proof generation and verification. No HTTP, no I/O. |
| [`auth`](auth) | Everything HTTP-specific: `AuthContext`, binding a proof to a request, `ReplayProtector`, the public `create_auth_proof` / `verify_auth_proof` API. Depends on `schnorr`, re-exports its key types. |

`auth` is the crate most consumers depend on directly — `schnorr` stays usable on its own for anyone who wants the bare protocol without the HTTP-binding layer.

## Quick example

```rust
use auth::{
    AuthContext, ReplayProtector, ReplayProtectorConfig, SecretKey,
    create_auth_proof, current_unix_timestamp, verify_auth_proof,
};
use rand_core::OsRng;

let mut rng = OsRng;
let secret_key = SecretKey::random(&mut rng);
let public_key = secret_key.public_key(); // shared with whoever verifies the proof

// --- side that calls the other service ---
let body = br#"{"product_id":"laptop","quantity":1}"#;
let context = AuthContext::new(
    "order-service", "warehouse-service", "POST", "/reservations",
    body, &mut rng, current_unix_timestamp(),
);
let proof = create_auth_proof(&mut rng, &secret_key, context);
// serialize `proof` (serde) and send it as a header alongside the request

// --- side that receives the request ---
let mut replay_protector = ReplayProtector::new(ReplayProtectorConfig::default());
verify_auth_proof(
    &proof, &public_key, "warehouse-service", "POST", "/reservations",
    body, current_unix_timestamp(), &mut replay_protector,
)
.expect("proof should be valid");
```

If the receiving service used a different path, a different body, an unexpected public key, an expired timestamp, or had already seen that proof's nonce, `verify_auth_proof` returns a specific `AuthVerificationError` instead — `RequestContextMismatch`, `ExpiredTimestamp`, `ReplayDetected`, `PublicKeyMismatch`, or `InvalidProof`.

## Security properties

- **Zero-knowledge**: the prover never transmits its secret key, and the verifier learns nothing beyond "the proof is valid."
- **Request binding**: the Fiat–Shamir challenge is derived from a length-prefixed, domain-separated transcript of `service_id`, `audience`, `method`, `path`, `SHA-256(body)`, `nonce`, and `timestamp` — so a proof cannot be lifted from one request and replayed against another.
- **Replay protection**: each proof carries a fresh random nonce; `ReplayProtector` rejects a nonce it has already accepted within its configured window.
- **Bounded validity**: `verify_auth_proof` rejects proofs whose timestamp falls outside the configured clock-skew tolerance.

## Testing & benchmarks

```bash
cargo test                                              # unit + integration tests, both crates
cargo test -p auth --test auth_sizes -- --ignored --nocapture   # proof/bundle size report (JSON vs bincode)
cargo bench -p auth                                      # Criterion benchmarks for proof generation/verification
```

## Current scope

- `ReplayProtector` keeps used nonces in memory, scoped to a single process — a multi-instance deployment of a verifying service would need a shared store (e.g. Redis) instead.
- Key generation and storage are left to the caller; `SecretKey::random` is the entry point, and how a service persists or rotates that key is outside this library's scope.
- Only the Schnorr scheme is implemented today. The `schnorr` / `auth` split exists so an additional ZKP scheme could be added as its own crate without changing the `auth` API.
