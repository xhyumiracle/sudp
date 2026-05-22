# sudp authorizer

The Authorizer side of SUDP — the party that authorizes operations by producing a
signature `σ` over `β = H(DS_bind ‖ r ‖ H(o))`.

## Planned packages

- **`ts/`** — TypeScript SDK for browser-based Authorizers (WebAuthn passkeys, etc.).
  Carrier-agnostic protocol primitives (canonical JSON, β computation, wrapping-key
  derivation, AEAD-as-wrap) plus an optional `./webauthn` subpath for the
  WebAuthn / PRF adapter.

Other Authorizer realizations (Swift / Kotlin / HSM-backed) may follow.
