# sudp

> **Secret-Use Delegation Protocol** — protocol-level secret use for agentic systems.

`sudp` lets an autonomous **Requester** *propose* a secret-backed operation, an **Authorizer**
*authorize* exactly that operation, and a **Custodian** *perform* it — without the
Requester ever seeing reusable authority over the secret. The unit of delegation is one
**use**, not the secret.

```text
                  ┌─────────────────────────┐
                  │  Authorizer  A          │
                  │  (passkey on a device)  │
                  └────────────┬────────────┘
                               │  signs β over (DS ‖ r ‖ H(o))
                               ▼
   ┌──────────────┐      ┌───────────────┐       ┌──────────────┐
   │ Requester R  │ ─o─▶ │  Custodian T  │ ─s─▶  │ Environment  │
   │   (agent)    │      │               │       │      E       │
   │              │◀ρ────│ holds sealed Σ│       │              │
   └──────────────┘      └───────────────┘       └──────────────┘
```

`R` never receives the secret `s`. `T` only spends `s` on operations `A` has authorized.
Reusable authority does not cross `R`'s boundary.

## Layout

```
sudp/
  custodian/
    rust/        ← Rust implementation of the Custodian (T)
  authorizer/
    ts/          ← TypeScript SDK for the Authorizer (A) — browser/passkey/HSM
  requester/
    ts/          ← TypeScript types + op builders for the Requester (R) — agent-side
  LICENSE
  SECURITY.md
```

| Package | Role | Status |
|---------|------|--------|
| [`custodian/rust`](custodian/rust/) | Custodian Rust crate (publishes as `sudp`) | pre-1.0, working |
| [`authorizer/ts`](authorizer/ts/) | Authorizer TS SDK (publishes as `@sudp-protocol/authorizer`) | pre-1.0, cross-language β conformance locked |
| [`requester/ts`](requester/ts/) | Requester TS types + builders (publishes as `@sudp-protocol/requester`) | pre-1.0, wire-shape only — no crypto, no HTTP, no framework |

### Building an agent against SUDP

Agent authors typically need only [`@sudp-protocol/requester`](requester/ts/):
it gives you typed `Operation` builders (`useOp`, `exportOp`, etc.) and
shape validators, but **no transport** — wire it up to whatever HTTP
client your stack uses to reach the Custodian. SUDP intentionally does
not ship framework adapters; the Requester is the most replaceable layer
and every agent framework writes this glue its own way.

## See it run

Two reading paths:

- **[`examples/protocol-demo/`](examples/protocol-demo/)** — `./run.sh`
  builds the three packages, spawns the Rust Custodian, runs a Node
  script that plays the Requester and Authorizer roles, prints
  colour-coded annotated logs of every wire interaction, and finishes
  with a tampered-grant rejection sanity check.
- The per-package READMEs ([`custodian/rust`](custodian/rust/),
  [`authorizer/ts`](authorizer/ts/), [`requester/ts`](requester/ts/))
  for API-level usage.

## Cross-language alignment

Every byte string the Authorizer produces and the Custodian expects MUST
agree. The conformance suite locks each primitive at the byte level —
and the role examples above use exactly the same primitives, so any
composite shape stays aligned by construction.

| Surface | Rust anchor | TS anchor |
|---------|-------------|-----------|
| `canonical(o)` | `Operation::canonical_bytes` unit tests | `conformance.test.ts: canonical: nested ordering` |
| `β` + `DS_BIND` | `beta_matches_ts_authorizer_conformance_vector` | `conformance.test.ts: β: matches Rust...` |
| `derive_wrapping_key` | `derive_wrapping_key_matches_ts_authorizer_conformance_vector` | `conformance.test.ts: deriveWrappingKey: matches Rust...` |
| AEAD encrypt (fixed nonce) | `aead_matches_ts_authorizer_conformance_vector` | `conformance.test.ts: aeadEncrypt: matches Rust...` |
| `wrap_ad` layout | `WrapBinding::to_canonical_ad` tests | `conformance.test.ts: wrap_ad: DS_WRAP ‖ cid ‖ ver_be` |
| `seal_ad` layout | `phases::setup::seal_ad` (setup tests) | `conformance.test.ts: seal_ad: DS_SEAL ‖ ver_be` |
| `WRAP_VERSION` ↔ `CURRENT_VERSION` | `state::CURRENT_VERSION = 1` | `conformance.test.ts: WRAP_VERSION matches Rust...` |

Run both halves; CI does the same on every push:

```bash
cd custodian/rust && cargo test
cd authorizer/ts  && npm test
cd requester/ts   && npm test
```

Either side failing means the cross-language protocol invariant broke.

## Pre-1.0

Wire format and trait shapes may still move before the 1.0 cut. See each package's own
CHANGELOG for details.

## Security

See [SECURITY.md](SECURITY.md) for the responsible-disclosure process.

## License

Apache-2.0. See [LICENSE](LICENSE).
