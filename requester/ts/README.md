# @sudp/requester

> Wire-shape types and operation builders for the **SUDP** Requester role.

The Requester `R` is the autonomous agent (LLM tool runtime, automated
job) that proposes a secret-backed operation `o` to the Custodian and
relays the resulting Grant. SUDP's threat model assumes `R` can be fully
compromised — so this package ships **only** the protocol-shape glue
`R` needs and **no** security-critical code.

## Scope (this is on purpose)

What's in:

- TypeScript types for `Operation`, `Act`, `Bind`, `Valid`,
  `RecipientPk`, `Grant`, `GrantOpt`, `ActType`, `Multiplicity` —
  matching the Rust crate's wire layout one-to-one.
- Builders: `useOp`, `exportOp`, `writeOp`, `rotateOp`, `enrollOp`,
  `revokeOp`, `customOp` — each returns a plain `Operation` object with
  sensible defaults (`iat = now`, `multiplicity = "one"`, `scope = {}`).
- Structural validators: `validateOperation`, `validateGrant` — catch
  malformed shapes before they hit the wire.

What's **not** in, and why:

| Not included | Reason |
|--------------|--------|
| HTTP / RPC client | SUDP does not define an on-the-wire transport. Build your own `fetch` / gRPC / Bun.serve / etc. on top of these types. |
| Canonical JSON, β, key derivation | `R` does no crypto. That all lives on the Authorizer side — see [`@sudp/authorizer`](../../authorizer/ts/). |
| LangChain / OpenAI / Anthropic adapters | Per-framework, per-deployment. Trying to be all of them at once means being none of them well. |
| Polling helpers / status enums | A polling shape implies a wire spec. SUDP intentionally has no normative wire spec yet. |

**This is a deliberate package constitution.** If you want one of the
above, write your own package on top of `@sudp/requester` — do not grow
this one.

## Usage sketch

```ts
import { useOp, exportOp } from "@sudp/requester";

// 1) Build an operation in your tool-call adapter.
const op = useOp({
  target: "env.api_key",
  redeemer: "custodian.example.com",
  scope: { request_id: "abc-123" },
});

// 2) Submit to the Custodian over your chosen transport.
//    (This package does NOT supply `fetch` — that's deployment glue.)
const resp = await fetch("https://custodian.example.com/use", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ o: op }),
});

// 3) Authorization (β computation + signing + W_c derivation) happens
//    at the Authorizer — see @sudp/authorizer for that side.
// 4) The Grant the Authorizer produces flows back to T; R sees only the
//    final response ρ.

const result = await resp.json();
```

For an Export operation (recipient is required by the protocol):

```ts
import { exportOp } from "@sudp/requester";

const op = exportOp({
  target: "env.api_key",
  redeemer: "custodian.example.com",
  recipient: {
    alg: "hpke-p256-sha256-aes128gcm",
    bytes: bytesToB64(recipientPubKey),
  },
});
```

For a custom (profile-defined) act type:

```ts
import { customOp } from "@sudp/requester";

const op = customOp("co-sign", {
  target: "wallet.eth_main",
  redeemer: "custodian.example.com",
  scope: { tx_hash: "0x..." },
});
// The Custodian's deployment is responsible for dispatching "co-sign".
// sudp's built-in execute_use / execute_export / execute_lifecycle
// reject custom types with ActTypeMismatch.
```

## End-to-end protocol walkthrough

Runnable three-process demo over HTTP showing where the Requester sits
relative to the Authorizer and Custodian:
[`../../examples/protocol-demo/`](../../examples/protocol-demo/).

## Status

Pre-1.0, alongside [`@sudp/authorizer`](../../authorizer/ts/) and the
[Rust custodian crate](../../custodian/rust/). Wire-shape changes will
ripple to all three.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
