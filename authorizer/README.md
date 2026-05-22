# sudp authorizer

The Authorizer side of SUDP — the party that authorizes operations by producing a
signature `σ` over `β = H(DS_BIND ‖ r ‖ H(o))`.

## Packages

- **[`ts/`](ts/)** — TypeScript SDK for browser-based Authorizers (`@sudp/authorizer`).
  Carrier-agnostic protocol primitives (canonical JSON, β computation,
  wrapping-key derivation, AEAD-as-wrap) plus an optional `./webauthn`
  subpath for the WebAuthn / PRF adapter. Cross-language β conformance
  with the Rust custodian crate is locked in CI.

Other Authorizer realizations (Swift / Kotlin / HSM-backed) may follow.
