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
    rust/        ← Rust implementation of the Custodian (this is what runs T)
  authorizer/
    ts/          ← (planned) TypeScript SDK for the Authorizer (browser/passkey)
  LICENSE
  SECURITY.md
```

| Package | Role | Status |
|---------|------|--------|
| [`custodian/rust`](custodian/rust/) | Custodian-side Rust crate (publishes as `sudp` on crates.io) | pre-1.0, working |
| [`authorizer/ts`](authorizer/ts/) | Authorizer-side TypeScript SDK (publishes as `@sudp/authorizer`) | pre-1.0, scaffolded with cross-language β conformance |

## How the protocol runs end-to-end

See [**EXAMPLES.md**](EXAMPLES.md) for a per-phase walkthrough of how the
three roles cooperate, with byte-level alignment between the Rust
custodian and the TypeScript authorizer.

## Pre-1.0

Wire format and trait shapes may still move before the 1.0 cut. See each package's own
CHANGELOG for details.

## Security

See [SECURITY.md](SECURITY.md) for the responsible-disclosure process.

## License

Apache-2.0. See [LICENSE](LICENSE).
