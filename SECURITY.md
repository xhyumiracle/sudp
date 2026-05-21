# Security Policy

## Reporting a Vulnerability

**Please do not file public GitHub issues for security vulnerabilities.**

Report suspected vulnerabilities by email to **[xhyumiracle@gmail.com](mailto:xhyumiracle@gmail.com)**.
A response acknowledging receipt should arrive within 7 days; full triage may take
longer (solo maintainer, best-effort).

Useful detail in your report:

- A description of the issue and its security impact.
- The affected crate version (`Cargo.toml` version field).
- Minimal reproduction steps, if you have them.
- Whether you would like credit in the fix's release notes (and how to spell your name).

## What's in scope

- Cryptographic correctness of the implemented protocol phases (setup, grant
  redemption, consumption dispatch, lifecycle).
- Issues that let an adversary recover `s_o`, forge a grant, replay a redeemed
  grant, or substitute an operation past authorization.
- Memory-safety bugs (despite `#![deny(unsafe_code)]`, transitive dependencies
  could in principle expose them).
- Cross-device envelope (`xdevice::*`) confidentiality / channel-binding gaps.
- Canonical encoding ambiguity that defeats operation binding.

## What's out of scope

- Vulnerabilities in callers' code that misuse the crate's API in ways its
  documentation explicitly warns against (e.g. handlers that leak `s_o`,
  caller-supplied `next_prf_salt` that diverges from `o.act.scope`).
- Issues that require physical access to the custodian process's memory.
- Plain DoS that's purely resource exhaustion without amplification.
- Vulnerabilities in transitively-pulled crates that don't surface through
  this crate's API (please report upstream).

## Disclosure preference

I aim to coordinate disclosure: triage privately, ship a fix, then publish a
patch release plus a brief write-up with credit. If you have a publication
deadline, say so in your initial report and we'll work backward from that.
