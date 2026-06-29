/**
 * SUDP protocol demo — runs R + A in this Node process, talks to the
 * Rust Custodian binary over HTTP. Annotated console output makes the
 * full data flow visible without reading the paper.
 *
 *   R (this script, Requester section): proposes operations, forwards grants.
 *   A (this script, Authorizer section): computes β, mock-signs.
 *   T (sudp-demo-custodian, spawned as a subprocess): HTTP server wrapping
 *      sudp::Custodian.
 *
 * Build prerequisites (the run.sh in this directory handles them):
 *   1. `cd custodian/rust && cargo build` for the Rust crate
 *   2. `cd authorizer/ts && npm install && npm run build`
 *   3. `cd requester/ts  && npm install && npm run build`
 *   4. `cd examples/protocol-demo/custodian && cargo build --release`
 *   5. `cd examples/protocol-demo/runner && npm install`
 */

import { spawn, type ChildProcess } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

import { computeBinding, DS_BIND } from "@sudp-protocol/authorizer";
import { useOp, type Operation } from "@sudp-protocol/requester";

// ─── Mock authenticator (matches the Rust binary's MockAuthenticator) ───
//
// Signature = SHA-256(secret ‖ β). This is what a real WebAuthn
// authenticator's σ would be — except cryptographically meaningful and
// extracted via a passkey ceremony. The demo skips all that.

const AUTH_SECRET = new TextEncoder().encode("would-be-WebAuthn-PRF-output");
const CREDENTIAL_ID = new TextEncoder().encode("demo-cred");
// In a real flow, W_c comes from `deriveWrappingKey(y_c, prf_salt, cid)`.
// The demo uses a fixed W_c so the binary's setup and the runner's
// sign-and-submit agree without negotiating PRF output.
const WRAPPING_KEY = new Uint8Array(32).fill(0xaa);
const PRF_SALT = new Uint8Array(32).fill(0xbb);

const BASE_URL = process.env["SUDP_DEMO_URL"] ?? "http://127.0.0.1:28789";
const CUSTODIAN_BIN =
  process.env["SUDP_DEMO_BIN"] ??
  "../custodian/target/release/sudp-demo-custodian";

// ─── Pretty-print helpers ────────────────────────────────────────────────

const reset = "\x1b[0m";
const bold = "\x1b[1m";
const dim = "\x1b[2m";
const red = "\x1b[31m";
const green = "\x1b[32m";
const yellow = "\x1b[33m";
const blue = "\x1b[34m";
const magenta = "\x1b[35m";
const cyan = "\x1b[36m";

const tag = (color: string, name: string) => `${color}[${name}]${reset}`;
const R = tag(green, "R");
const A = tag(magenta, "A");
const phase = (s: string) => `\n${bold}${cyan}═══ ${s} ═══${reset}`;

function bytesToB64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}
function b64ToBytes(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64"));
}
function bytesToHex(bytes: Uint8Array, max = 16): string {
  const hex = Array.from(bytes)
    .slice(0, max)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return bytes.length > max ? `${hex}…(${bytes.length}B total)` : hex;
}

// ─── HTTP client ─────────────────────────────────────────────────────────

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const r = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: { "content-type": "application/json" },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  if (!r.ok) {
    throw new Error(`HTTP ${r.status} ${method} ${path}: ${text}`);
  }
  return JSON.parse(text) as T;
}

async function waitForReady(): Promise<void> {
  for (let i = 0; i < 100; i++) {
    try {
      await call<{ status: string }>("GET", "/health");
      return;
    } catch {
      await sleep(100);
    }
  }
  throw new Error("custodian did not become ready");
}

// ─── Mock signer (SHA-256(secret ‖ β)) ───────────────────────────────────

async function mockSign(secret: Uint8Array, beta: Uint8Array): Promise<Uint8Array> {
  const buf = new Uint8Array(secret.byteLength + beta.byteLength);
  buf.set(secret, 0);
  buf.set(beta, secret.byteLength);
  const digest = await crypto.subtle.digest("SHA-256", buf as unknown as ArrayBuffer);
  return new Uint8Array(digest);
}

// ─── The protocol flow ───────────────────────────────────────────────────

async function runDemo(): Promise<void> {
  console.log(`${bold}SUDP protocol demo${reset}`);
  console.log(`${dim}R, A, T are colour-coded; logs from the Rust server (T) print to stderr.${reset}`);
  console.log();

  console.log(phase("Phase I — Setup (Authorizer enrolls a credential at the Custodian)"));
  console.log(`${A} ${dim}Building setup payload with auth_secret, cred_id, prf_salt, W_c, and an initial M${reset}`);
  console.log(`${A} ${dim}M[env.api_key] = "sk_live_top_secret" (lives only inside T thereafter)${reset}`);

  const setup = await call<{
    sealed_state_id: string;
    credentials: number;
    ciphertext_bytes: number;
  }>("POST", "/sudp/v1/setup", {
    credential_id_b64: bytesToB64(CREDENTIAL_ID),
    secret_b64: bytesToB64(AUTH_SECRET),
    prf_salt_b64: bytesToB64(PRF_SALT),
    wrapping_key_b64: bytesToB64(WRAPPING_KEY),
    initial_secrets: {
      "env.api_key": bytesToB64(new TextEncoder().encode("sk_live_top_secret")),
    },
  });
  console.log(
    `${A} -> ${green}200${reset} sealed_state_id=${setup.sealed_state_id} (${setup.credentials} cred, ${setup.ciphertext_bytes}B sealed M)`,
  );

  console.log(phase("Phase II.1 — R proposes an operation; T issues freshness r"));
  const op: Operation = useOp({
    target: "env.api_key",
    redeemer: "demo-custodian",
    scope: { endpoint: "GET /repos/me" },
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 600,
  });
  console.log(`${R} ${dim}Built Operation via @sudp-protocol/requester.useOp(...)${reset}`);
  console.log(`${R}     ${blue}o.act${reset}    = ${JSON.stringify(op.act)}`);
  console.log(`${R}     ${blue}o.bind${reset}   = ${JSON.stringify(op.bind)}`);
  console.log(`${R}     ${blue}o.valid${reset}  = ${JSON.stringify(op.valid)}`);

  const proposal = await call<{
    request_id: string;
    r_b64: string;
    ds_bind: string;
    op: Operation;
  }>("POST", "/sudp/v1/use", {
    sealed_state_id: setup.sealed_state_id,
    op,
  });
  console.log(
    `${R} -> ${green}200${reset} request_id=${proposal.request_id} r=${bytesToHex(b64ToBytes(proposal.r_b64))}`,
  );

  console.log(phase("Phase II.2 — A computes β and signs"));
  const rBytes = b64ToBytes(proposal.r_b64);
  const beta = await computeBinding(DS_BIND, rBytes, op);
  console.log(`${A} β = SHA-256(${blue}DS_BIND${reset} ‖ r ‖ H(canonical(o)))`);
  console.log(`${A} β = ${bytesToHex(beta, 32)}`);
  console.log(`${A} ${dim}(real flow: WebAuthn navigator.credentials.get({ challenge: β }))${reset}`);
  const tagBytes = await mockSign(AUTH_SECRET, beta);
  console.log(`${A} σ = mock-sign(secret, β) = ${bytesToHex(tagBytes, 16)}`);

  console.log(phase("Phase II.3 + III.1 — R submits grant; T verifies and uses s_o"));
  console.log(`${R} ${dim}Assembling Grant = { o, r, cid, W_c, σ }${reset}`);
  const result = await call<{ status: number; note: string }>(
    "POST",
    `/sudp/v1/use/${proposal.request_id}/redeem`,
    {
      sealed_state_id: setup.sealed_state_id,
      op,
      credential_id_b64: bytesToB64(CREDENTIAL_ID),
      wrapping_key_b64: bytesToB64(WRAPPING_KEY),
      assertion: {
        credential_id: Array.from(CREDENTIAL_ID),
        tag: Array.from(tagBytes),
      },
    },
  );
  console.log(`${R} -> ${green}200${reset} ρ=${JSON.stringify(result)}`);
  console.log();
  console.log(`${bold}${green}✓ Demo complete.${reset} R received only ρ; s_o stayed inside T.`);
}

// ─── Adversarial sanity check (optional but illuminating) ────────────────

async function runTamperCheck(): Promise<void> {
  console.log(phase("Sanity check — a tampered Operation must fail"));
  console.log(`${R} ${dim}Re-running the flow, but tampering with o.act.target after A signs.${reset}`);
  const setup = await call<{ sealed_state_id: string }>("POST", "/sudp/v1/setup", {
    credential_id_b64: bytesToB64(CREDENTIAL_ID),
    secret_b64: bytesToB64(AUTH_SECRET),
    prf_salt_b64: bytesToB64(PRF_SALT),
    wrapping_key_b64: bytesToB64(WRAPPING_KEY),
    initial_secrets: {
      "env.api_key": bytesToB64(new TextEncoder().encode("sk_live_top_secret")),
    },
  });

  const honest = useOp({
    target: "env.api_key",
    redeemer: "demo-custodian",
    iat: Math.floor(Date.now() / 1000),
  });
  const proposal = await call<{ request_id: string; r_b64: string }>(
    "POST",
    "/sudp/v1/use",
    { sealed_state_id: setup.sealed_state_id, op: honest },
  );

  const beta = await computeBinding(DS_BIND, b64ToBytes(proposal.r_b64), honest);
  const tagBytes = await mockSign(AUTH_SECRET, beta);

  // A signed `honest`, but R tampers — swaps the op for a more permissive one.
  const tampered = { ...honest, act: { ...honest.act, target: "env.different_secret" } };

  try {
    await call<unknown>("POST", `/sudp/v1/use/${proposal.request_id}/redeem`, {
      sealed_state_id: setup.sealed_state_id,
      op: tampered,
      credential_id_b64: bytesToB64(CREDENTIAL_ID),
      wrapping_key_b64: bytesToB64(WRAPPING_KEY),
      assertion: {
        credential_id: Array.from(CREDENTIAL_ID),
        tag: Array.from(tagBytes),
      },
    });
    console.log(`${red}✗ unexpected: T accepted a tampered grant${reset}`);
    process.exitCode = 1;
  } catch (e) {
    console.log(
      `${green}✓${reset} T rejected the tampered grant: ${yellow}${(e as Error).message}${reset}`,
    );
    console.log(
      `${dim}  (tampering changed H(o), which changed β, which broke σ verification)${reset}`,
    );
  }
}

// ─── Entry point ─────────────────────────────────────────────────────────

let child: ChildProcess | undefined;

async function main(): Promise<void> {
  // Spawn the custodian binary
  child = spawn(CUSTODIAN_BIN, [], {
    stdio: ["ignore", "inherit", "inherit"],
    env: { ...process.env, SUDP_DEMO_BIND: "127.0.0.1:28789" },
  });
  child.on("error", (err) => {
    console.error(`failed to spawn ${CUSTODIAN_BIN}: ${err.message}`);
    process.exit(2);
  });

  try {
    await waitForReady();
    await runDemo();
    await runTamperCheck();
  } finally {
    child?.kill();
  }
}

process.on("SIGINT", () => {
  child?.kill();
  process.exit(130);
});

main().catch((e) => {
  console.error(`${red}demo failed:${reset}`, e);
  child?.kill();
  process.exit(1);
});
