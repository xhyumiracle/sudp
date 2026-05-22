# SUDP protocol demo — three roles, talking over HTTP

A self-contained demo of the SUDP protocol where each of the three roles
is a separate process talking the same wire shapes a real deployment
would use:

- **T — Custodian**: a Rust binary built on `sudp::Custodian`, exposed
  over HTTP via `tiny_http`. Sudp-aware endpoints (`/sudp/v1/setup`,
  `/sudp/v1/use`, `/sudp/v1/use/{id}/redeem`) mirror the skeleton a real
  deployment (e.g. safeclaw) layers its product-level API on top of.
- **R — Requester**: a Node section in `runner.ts` that uses
  `@sudp/requester` to build an `Operation` and posts it to T.
- **A — Authorizer**: a Node section in `runner.ts` that uses
  `@sudp/authorizer` to compute β and mock-signs it. (Real A uses
  WebAuthn / passkey / HSM; the demo skips that ceremony with a
  deterministic SHA-256-over-secret-and-β signer the Rust side also
  knows about.)

Both R and A run inside one Node process for ergonomics; their colour-
coded log lines make the role boundary visible.

## Run it

From this directory:

```bash
./run.sh
```

The script builds `@sudp/authorizer`, `@sudp/requester`, the demo
Custodian binary, installs the runner's deps, then runs the demo. End
to end it produces output similar to:

```
═══ Phase I — Setup (Authorizer enrolls a credential at the Custodian) ═══
[A] Building setup payload with auth_secret, cred_id, prf_salt, W_c, and an initial M
[A] M[env.api_key] = "sk_live_top_secret" (lives only inside T thereafter)
[A] -> 200 sealed_state_id=… (1 cred, 51B sealed M)

═══ Phase II.1 — R proposes an operation; T issues freshness r ═══
[R] Built Operation via @sudp/requester.useOp(...)
[R]     o.act    = {"type":"use","target":"env.api_key","scope":{"endpoint":"GET /repos/me"}}
[R]     o.bind   = {"redeemer":"demo-custodian"}
[R]     o.valid  = {"iat":…,"multiplicity":"one","exp":…}
[R] -> 200 request_id=… r=<32 bytes>…

═══ Phase II.2 — A computes β and signs ═══
[A] β = SHA-256(DS_BIND ‖ r ‖ H(canonical(o)))
[A] β = <32 bytes>…
[A] (real flow: WebAuthn navigator.credentials.get({ challenge: β }))
[A] σ = mock-sign(secret, β) = <32 bytes>…

═══ Phase II.3 + III.1 — R submits grant; T verifies and uses s_o ═══
[R] Assembling Grant = { o, r, cid, W_c, σ }
[R] -> 200 ρ={"status":200,"note":"R received only this response (ρ); s_o never crossed the wire."}

✓ Demo complete. R received only ρ; s_o stayed inside T.

═══ Sanity check — a tampered Operation must fail ═══
[R] Re-running the flow, but tampering with o.act.target after A signs.
✓ T rejected the tampered grant: HTTP 400 …: AuthorizationInvalid
  (tampering changed H(o), which changed β, which broke σ verification)
```

The Custodian's own logs (`[T] …`) print on stderr alongside, so you can
see every request as T processes it.

## What's deliberately missing

This is a **demo**, not a deployment template:

- **The authenticator is a mock**: signature = SHA-256(secret ‖ β). Real
  deployments swap in `sudp::passkey::WebAuthn` (or any other impl of
  the `Authenticator` trait).
- **No persistence**: Σ is held in a `HashMap<sealed_state_id, _>` in
  the binary's memory. Restart the binary, everything's gone.
- **No TLS**: localhost only.
- **No keep-alive / `/approve` pattern**: the demo splits Phase II.1
  and II.3 into two HTTP calls. A real deployment can merge them with a
  long-poll on the first call (this is what safeclaw v1 does), but
  that's a transport optimisation, not a protocol shape change.
- **Only `use` is wired**: `export`, `write`, `rotate`, `enroll`,
  `revoke` are analogous and intentionally not duplicated here — each
  is one `Custodian::execute_*` call away on the server side.

## Mapping to the protocol

| Section in `runner.ts` / `main.rs` | Phase | What happens |
|------------------------------------|-------|--------------|
| `POST /sudp/v1/setup` (handler: `handle_setup`) | I | Authorizer enrolls a credential; `Custodian::setup` builds `Σ_0`. |
| `POST /sudp/v1/use` (handler: `handle_freshness`) | II.1 | R submits `o`; T issues `r` via `Custodian::issue_freshness`, returns it to R for forwarding to A. |
| `computeBinding(DS_BIND, r, op)` + `mockSign(secret, β)` | II.2 | A computes β and signs (real flow: WebAuthn ceremony). |
| `POST /sudp/v1/use/{id}/redeem` (handler: `handle_use_redeem`) | II.3 + III.1 | R forwards the Grant; T verifies σ (via `Custodian::redeem_grant`), unwraps K, opens M, runs the closure on `s_o` (via `Custodian::execute_use`), returns ρ. |

The tamper-detection sanity check at the end demonstrates that R cannot
substitute the operation after A signs — any change to `o` changes
H(o), changes β, breaks σ verification, T rejects.

## Where this fits in the repo

- The Custodian binary in `custodian/` is a downstream consumer of
  [`custodian/rust/`](../../custodian/rust/) (the `sudp` crate).
- The TS runner consumes [`authorizer/ts/`](../../authorizer/ts/) and
  [`requester/ts/`](../../requester/ts/) via `file:` links so a single
  `npm install` works.
- The byte-level cross-language alignment table lives in the
  [top-level README](../../README.md#cross-language-alignment).
