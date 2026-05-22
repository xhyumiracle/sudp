# sudp

> **Secret-Use Delegation Protocol** — protocol-level secret use for agentic systems.

[![crates.io](https://img.shields.io/crates/v/sudp.svg?label=sudp%20%28crates.io%29)](https://crates.io/crates/sudp)
[![npm @sudp-protocol/authorizer](https://img.shields.io/npm/v/%40sudp-protocol%2Fauthorizer.svg?label=%40sudp-protocol%2Fauthorizer)](https://www.npmjs.com/package/@sudp-protocol/authorizer)
[![npm @sudp-protocol/requester](https://img.shields.io/npm/v/%40sudp-protocol%2Frequester.svg?label=%40sudp-protocol%2Frequester)](https://www.npmjs.com/package/@sudp-protocol/requester)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

This repository is the **reference implementation** of the SUDP protocol
defined in:

> Xiaohang Yu, Hejia Geng, Xinmeng Zeng, William Knottenbelt.
> *SUDP: Secret-Use Delegation Protocol for Agentic Systems.*
> [`arXiv:2604.24920`](https://arxiv.org/abs/2604.24920), 2026.

`sudp` lets an autonomous **Requester** *propose* a secret-backed operation,
an **Authorizer** *authorize* exactly that operation, and a **Custodian**
*perform* it — without the Requester ever seeing reusable authority over
the secret. The unit of delegation is one **use**, not the secret.

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

`R` never receives the secret `s`. `T` only spends `s` on operations `A`
has authorized. Reusable authority does not cross `R`'s boundary — even
if `R` is fully compromised (prompt injection, runtime shim, etc.).

## Packages

| Role | Source | Published as | Status |
|------|--------|--------------|--------|
| **Custodian** (T) | Rust crate at [`custodian/rust`](custodian/rust/) | [`sudp`](https://crates.io/crates/sudp) on crates.io | pre-1.0, working |
| **Authorizer** (A) | TypeScript SDK at [`authorizer/ts`](authorizer/ts/) | [`@sudp-protocol/authorizer`](https://www.npmjs.com/package/@sudp-protocol/authorizer) on npm | pre-1.0, cross-language β conformance locked |
| **Requester** (R) | TypeScript types + op builders at [`requester/ts`](requester/ts/) | [`@sudp-protocol/requester`](https://www.npmjs.com/package/@sudp-protocol/requester) on npm | pre-1.0, wire-shape only — no crypto, no HTTP, no framework |

```
sudp/
  custodian/rust/      ← T  (Rust)
  authorizer/ts/       ← A  (TypeScript, browser / passkey / HSM)
  requester/ts/        ← R  (TypeScript, agent-side types + builders)
  examples/            ← runnable cross-process demo
  custodian/rust/CHANGELOG.md, authorizer/ts/, requester/ts/ CHANGELOGs
  LICENSE, SECURITY.md
```

## Try it

A single command builds all three packages, spawns the Rust Custodian
binary, and runs a Node script that plays the Requester and Authorizer
roles. The output is colour-coded by role and prints every wire
interaction. The demo finishes with an adversarial sanity check —
the Requester tampers with the operation after the Authorizer signs,
and the Custodian rejects with `AuthorizationInvalid`.

```bash
git clone https://github.com/xhyumiracle/sudp
cd sudp/examples/protocol-demo
./run.sh
```

For API-level usage, see the per-package READMEs:
[`custodian/rust`](custodian/rust/) ·
[`authorizer/ts`](authorizer/ts/) ·
[`requester/ts`](requester/ts/).

## Building an agent against SUDP

Agent authors typically need only
[`@sudp-protocol/requester`](requester/ts/): typed `Operation` builders
(`useOp`, `exportOp`, etc.) and shape validators, with **no transport**
— wire it up to whatever HTTP client your stack uses to reach the
Custodian. SUDP intentionally does not ship framework adapters; the
Requester is the most replaceable layer and every agent framework writes
this glue its own way.

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

Run both halves locally; CI does the same on every push:

```bash
cd custodian/rust && cargo test
cd authorizer/ts  && npm test
cd requester/ts   && npm test
```

Either side failing means the cross-language protocol invariant broke.

## Pre-1.0

Wire format and trait shapes may still move before the 1.0 cut. See each
package's own CHANGELOG for details. Pin minor versions in production:

```toml
# Cargo.toml
sudp = "~0.1"
```

```json
// package.json
"@sudp-protocol/authorizer": "~0.1.0",
"@sudp-protocol/requester":  "~0.1.0"
```

## Citing

If you use SUDP in academic work, please cite the paper:

```bibtex
@misc{yu2026sudp,
  title         = {SUDP: Secret-Use Delegation Protocol for Agentic Systems},
  author        = {Xiaohang Yu and Hejia Geng and Xinmeng Zeng and William Knottenbelt},
  year          = {2026},
  eprint        = {2604.24920},
  archivePrefix = {arXiv},
  primaryClass  = {cs.CR},
  url           = {https://arxiv.org/abs/2604.24920}
}
```

Plain text:

> Xiaohang Yu, Hejia Geng, Xinmeng Zeng, and William Knottenbelt.
> "SUDP: Secret-Use Delegation Protocol for Agentic Systems."
> arXiv preprint arXiv:2604.24920 (2026).

## Security

See [SECURITY.md](SECURITY.md) for the responsible-disclosure process.

## License

Apache-2.0. See [LICENSE](LICENSE).
