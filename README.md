# SUDP — Secret-Use Delegation Protocol

> Protocol-level secret use for agentic systems.

[![crates.io](https://img.shields.io/crates/v/sudp.svg?label=sudp%20%28crates.io%29)](https://crates.io/crates/sudp)
[![npm @sudp-protocol/authorizer](https://img.shields.io/npm/v/%40sudp-protocol%2Fauthorizer.svg?label=%40sudp-protocol%2Fauthorizer)](https://www.npmjs.com/package/@sudp-protocol/authorizer)
[![npm @sudp-protocol/requester](https://img.shields.io/npm/v/%40sudp-protocol%2Frequester.svg?label=%40sudp-protocol%2Frequester)](https://www.npmjs.com/package/@sudp-protocol/requester)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Reference implementation of the SUDP protocol defined in:

> Xiaohang Yu, Hejia Geng, Xinmeng Zeng, William Knottenbelt.
> *SUDP: Secret-Use Delegation Protocol for Agentic Systems.*
> [`arXiv:2604.24920`](https://arxiv.org/abs/2604.24920), 2026.

sudp lets an autonomous **Requester** (R) propose a secret-backed
operation, an **Authorizer** (A) authorize exactly that operation, and a
**Custodian** (T) perform it. The unit of delegation is one **use**, not
the secret.

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

R never sees `s` and gains no reusable authority over it — even if R is
fully compromised (prompt injection, runtime shim, etc.).

## Packages

| Role | Source | Published as |
|------|--------|--------------|
| **Custodian** (T) | [`custodian/rust`](custodian/rust/) | [`sudp`](https://crates.io/crates/sudp) on crates.io |
| **Authorizer** (A) | [`authorizer/ts`](authorizer/ts/) | [`@sudp-protocol/authorizer`](https://www.npmjs.com/package/@sudp-protocol/authorizer) on npm |
| **Requester** (R) | [`requester/ts`](requester/ts/) | [`@sudp-protocol/requester`](https://www.npmjs.com/package/@sudp-protocol/requester) on npm |

## Try it

Prerequisites: Rust 1.85+ (via [rustup](https://rustup.rs)) and Node.js 20+.

```bash
git clone https://github.com/xhyumiracle/sudp
cd sudp/examples/protocol-demo
./run.sh
```

Builds all three packages, spawns the Custodian, runs R + A in a Node
script, prints every wire interaction colour-coded by role, and finishes
with an adversarial check (R tampers with `o` after A signs → T rejects).

For API-level usage: [`custodian/rust`](custodian/rust/) ·
[`authorizer/ts`](authorizer/ts/) · [`requester/ts`](requester/ts/).

## Building an agent

Agent authors typically need only
[`@sudp-protocol/requester`](requester/ts/) — typed `Operation` builders
and shape validators, no transport, no framework adapters. The Requester
is the most replaceable layer; every agent framework wires its own glue.

## Cross-language alignment

Conformance vectors lock the Authorizer's bytes against the Custodian at
the byte level — composite shapes stay aligned by construction.

| Surface | Rust anchor | TS anchor |
|---------|-------------|-----------|
| `canonical(o)` | `Operation::canonical_bytes` unit tests | `conformance.test.ts: canonical: nested ordering` |
| `β` + `DS_BIND` | `beta_matches_ts_authorizer_conformance_vector` | `conformance.test.ts: β: matches Rust...` |
| `derive_wrapping_key` | `derive_wrapping_key_matches_ts_authorizer_conformance_vector` | `conformance.test.ts: deriveWrappingKey: matches Rust...` |
| AEAD encrypt (fixed nonce) | `aead_matches_ts_authorizer_conformance_vector` | `conformance.test.ts: aeadEncrypt: matches Rust...` |
| `wrap_ad` layout | `WrapBinding::to_canonical_ad` tests | `conformance.test.ts: wrap_ad: DS_WRAP ‖ cid ‖ ver_be` |
| `seal_ad` layout | `phases::setup::seal_ad` (setup tests) | `conformance.test.ts: seal_ad: DS_SEAL ‖ ver_be` |
| `WRAP_VERSION` ↔ `CURRENT_VERSION` | `state::CURRENT_VERSION = 1` | `conformance.test.ts: WRAP_VERSION matches Rust...` |

CI runs both halves on every push:

```bash
cd custodian/rust && cargo test
cd authorizer/ts  && npm test
cd requester/ts   && npm test
```

## Pre-1.0

Wire format and trait shapes may still move before 1.0. Pin minor
versions in production:

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

> Xiaohang Yu, Hejia Geng, Xinmeng Zeng, and William Knottenbelt.
> "SUDP: Secret-Use Delegation Protocol for Agentic Systems."
> arXiv preprint arXiv:2604.24920 (2026).

## Security

See [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
