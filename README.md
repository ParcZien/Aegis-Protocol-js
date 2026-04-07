# Aegis Protocol

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Status: Production-Ready](https://img.shields.io/badge/Status-Production--Ready-green.svg)
![Dependencies: 0](https://img.shields.io/badge/Dependencies-0-blue.svg)

A deterministic validation gate between AI output and execution.

If an AI system in your stack can trigger real actions—payments, API calls, database writes—then you have a boundary problem. Language models are non-deterministic. Your systems are not.

Aegis enforces that boundary. Nothing executes unless it passes strict validation and is sealed into a verifiable, time-bound packet.

The AI proposes. The code decides.

---

## What it does

Aegis takes a proposed action (typically from an AI), validates it against explicit rules and live system state, and returns either:

* a VERIFIED result with a signed execution packet
* or a CRITICAL_DENIAL with a precise failure reason

There is no partial success. The system fails closed.

---

## What problem this solves

Without a hard validation layer, AI systems can:

* issue valid but incorrect API calls
* exceed business limits (for example, large refunds or transfers)
* include unexpected or injected fields
* replay previously valid but costly actions
* produce structurally correct but unsafe data

These failures come from using probabilistic outputs to control deterministic systems.

Aegis prevents them by making execution conditional on deterministic checks.

---

## Design principles

* Fail closed — any violation terminates immediately
* Deterministic — no heuristics, no inference
* Explicit policy — all allowed behavior is declared up front
* Immutable inputs — all data is copied and frozen before validation
* Verifiable output — successful results are cryptographically sealed

---

## Installation

Option 1:

npm install aegis-protocol

Option 2:

Copy aegis.js into your project. No dependencies, no build step.

Requires a runtime with the Web Crypto API (Node 20+, modern browsers, Deno, Bun).

---

## Quick start

To get started quickly, refer to the "quickstart" file in the repository.

---

## Where Aegis sits

Aegis is a gate between untrusted output and execution.

Typical flow:

1. An AI (or other untrusted system) proposes an action
2. Aegis validates it against rules and context
3. Only verified actions are executed

Everything before Aegis is untrusted. Everything after it is constrained.

---

## Validation pipeline

Each call to verify() runs four stages in order. Failure at any stage stops execution.

Stage 1 — Structural integrity

* Valid JSON or object
* All required keys present
* No undefined or extra fields

Stage 2 — Type enforcement

* Strict typeof checks
* No coercion ("100" is not 100)
* NaN, Infinity, and non-finite values rejected
* Optional safe integer enforcement

Stage 3 — Boundary constraints

* Numeric limits (min, max)
* String constraints (pattern, length, whitelist/blacklist)
* Global dangerous-character filtering

Stage 4 — Contextual verification

* Cross-checks against live system state
* Examples: amount ≤ balance, action allowed for user

---

## Verification packet

On success, Aegis returns a signed packet containing:

* nonce (one-time use value)
* timestamp and expiration
* hash of the validated intent
* cryptographic signature

This binds the approved action to a specific moment and prevents reuse.

---

## Execution requirements

Before executing any verified action, your system must check:

1. The packet has not expired
2. The nonce has not been used before

Aegis tracks nonces in-memory, but production systems should maintain a persistent nonce ledger.

---

## Packet verification

You can re-verify a packet at any time to confirm:

* it has not expired
* it has not been tampered with
* it matches the intended action

---

## Security model

Aegis addresses:

* Type confusion and coercion
* Prototype pollution (**proto**, constructor, prototype)
* Numeric edge cases (NaN, Infinity, unsafe integers)
* Injection via string payloads
* Replay attacks (nonce + expiration)
* Mutation during validation (deep copy + freeze)
* Time-of-check vs time-of-use gaps

The system does not infer intent. It strictly constrains it.

---

## API

* Aegis.verify(proposal, manifest, context)
  Runs the full validation pipeline

* Aegis.verifyPacket(packet, intent)
  Verifies packet integrity and validity

* Aegis.rotateKeys()
  Generates a new signing keypair

* Aegis.flushNonces()
  Clears the in-memory nonce registry

All methods are asynchronous. The Aegis object is immutable.

---

## Runtime

* Node.js 20+
* Modern browsers
* Deno
* Bun

Uses the Web Crypto API. Prefers Ed25519, falls back to ECDSA P-256.

---

## License

MIT
