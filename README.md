[README.md](https://github.com/user-attachments/files/26528331/README.md)
# Aegis Protocol
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Status: Production-Ready](https://img.shields.io/badge/Status-Production--Ready-green.svg)
![Dependencies: 0](https://img.shields.io/badge/Dependencies-0-blue.svg)

A deterministic validation gate between AI outputs and real-world execution. Vanilla JavaScript, zero dependencies.

The idea is simple: the AI proposes, the code disposes. Aegis sits between whatever your model spits out and whatever your system actually does with it. Nothing touches your database or API unless it passes a four-stage, fail-closed validation pipeline and gets a signed cryptographic packet.

## Why

Language models are non-deterministic. Your database is not. If you're letting an AI decide things like "transfer $500 to account X," you need a hard boundary between what the model *suggests* and what your code *permits*. Aegis is that boundary.

It's not a framework. It's one function: `Aegis.verify()`.

## Install

Copy `aegis.js` into your project. That's it. No npm, no bundler, no build step. It uses the Web Crypto API, which is built into every modern browser, Node 20+, Deno, and Bun.

## Quick Start

```js
const result = await Aegis.verify(
  // 1. The AI's proposed action (JSON string or object)
  { action: 'transfer', target: 'alice@bank.com', amount: 250 },

  // 2. Your rules (immutable for the duration of the call)
  {
    requiredKeys: ['action', 'target', 'amount'],
    ttlMs: 30000,
    safeIntegers: true,
    schema: {
      action: { type: 'string', whitelist: ['transfer', 'withdraw'] },
      target: { type: 'string', pattern: '^[a-zA-Z0-9@.]+$', maxLength: 100 },
      amount: { type: 'number', min: 0.01, max: 10000 }
    },
    contextRules: [
      { field: 'amount', operator: '<=', contextField: 'balance' },
      { field: 'action', operator: 'in', contextField: 'allowedActions' }
    ]
  },

  // 3. Live system state
  { balance: 1000, allowedActions: ['transfer', 'withdraw'] }
);

if (result.status === 'VERIFIED') {
  // result.sanitizedIntent — the cleaned, frozen proposal
  // result.packet — { nonce, timestamp, expiresAt, intentHash, signature, algorithm }
  executeTransaction(result.sanitizedIntent, result.packet);
} else {
  // result.status === 'CRITICAL_DENIAL'
  // result.stage, result.code, result.message, result.details
  log(result);
}
```

## Validation Pipeline

Every call to `verify()` runs four stages in order. Failure at any stage terminates immediately.

**Stage 1 — Structural Integrity.** Is it valid JSON? Are all required keys present? Are there any keys the manifest doesn't define? If the AI hallucinated extra fields, denied.

**Stage 2 — Type Enforcement.** Strict `typeof` checks. `"100"` is not a number. `1` is not a boolean. `NaN` and `Infinity` are rejected via `Number.isFinite`. Integers outside the safe range (`±2^53 - 1`) are rejected when `safeIntegers` is enabled.

**Stage 3 — Boundary Constraints.** Numeric `min`/`max`. String `minLength`/`maxLength`, `pattern` (regex), `whitelist`, `blacklist`. A global dangerous-characters check rejects strings containing `;`, `<`, `>`, backticks, quotes, and control characters before any field-level checks run.

**Stage 4 — Contextual Verification.** Cross-references the proposal against your live system context. Operators: `<=`, `>=`, `<`, `>`, `===`, `!==`, `in`, `not_in`. If the AI requests $500 and the user has $300, denied.

## The Verification Packet

When all four stages pass, Aegis produces a signed packet:

```js
{
  nonce: '7a3f...',           // 128-bit random, one-time use
  timestamp: 1719400000000,
  expiresAt: 1719400030000,   // timestamp + ttlMs
  intentHash: 'sha256...',    // SHA-256 of the sanitized proposal
  signature: 'ed25519...',    // Signs "nonce:timestamp:expiresAt:hash"
  algorithm: 'Ed25519'        // or 'ECDSA-P256' as fallback
}
```

Your downstream system should verify two things before execution: (1) the packet hasn't expired, and (2) the nonce hasn't been consumed before. Aegis tracks nonces in-memory for the current runtime, but your database needs its own persistent nonce ledger for cross-process protection.

You can re-verify a packet at any time:

```js
const check = await Aegis.verifyPacket(result.packet, result.sanitizedIntent);
// { valid: true } or { valid: false, reason: 'EXPIRED' | 'HASH_MISMATCH' | 'INVALID_SIGNATURE' }
```

## Manifest Reference

```js
{
  requiredKeys: ['field1', 'field2'],      // must be present in every proposal
  ttlMs: 30000,                            // packet lifetime in ms (default: 30s)
  safeIntegers: true,                      // reject integers outside ±2^53-1
  dangerousCharsPattern: '[;<>`\\\\"\\\'\\x00-\\x1f]',  // override the default trojan-char regex

  schema: {
    field1: {
      type: 'string',                      // 'string' | 'number' | 'boolean'
      pattern: '^[a-z]+$',                 // regex the value must match
      whitelist: ['a', 'b'],               // exhaustive list of allowed values
      blacklist: ['x'],                    // values that are never allowed
      minLength: 1,
      maxLength: 50
    },
    field2: {
      type: 'number',
      min: 0,
      max: 9999
    }
  },

  contextRules: [
    {
      field: 'field2',                     // key in the proposal
      operator: '<=',                      // comparison operator
      contextField: 'systemLimit'          // key in the system context
    }
  ]
}
```

## Hardening

The engine addresses eight specific attack vectors:

1. **NaN bypass** — `Number.isFinite` rejects NaN, Infinity, -Infinity at Stage 2.
2. **Type confusion** — Strict `typeof`, no coercion. `"100"` fails a `number` check.
3. **Nested trojan injection** — Global dangerous-character regex on all string fields at Stage 3.
4. **Double-spend / replay** — Cryptographic nonce per packet, in-memory consumption tracking.
5. **Prototype pollution** — `__proto__`, `constructor`, `prototype` keys are stripped and flagged. All internal objects use `Object.create(null)`.
6. **Large number precision** — `Number.isSafeInteger` enforcement when `safeIntegers` is enabled.
7. **Internal mutation** — All inputs are deep-copied and recursively `Object.freeze`'d before validation begins.
8. **TOCTOU (time-of-check/time-of-use)** — Packets expire after `ttlMs` (default 30 seconds).

## API

| Method | Description |
|---|---|
| `Aegis.verify(proposal, manifest, context)` | Run the full pipeline. Returns `VERIFIED` or `CRITICAL_DENIAL`. |
| `Aegis.verifyPacket(packet, intent)` | Re-verify a previously issued packet (hash + signature + TTL). |
| `Aegis.rotateKeys()` | Generate a new signing keypair. Invalidates all prior packets. |
| `Aegis.flushNonces()` | Clear the in-memory nonce registry. |

All methods return promises. The entire `Aegis` object is frozen.

## Runtime Requirements

Any environment with the Web Crypto API:

- Browsers (all modern)
- Node.js 20+
- Deno
- Bun

Ed25519 is preferred for signing. Falls back to ECDSA P-256 if the runtime doesn't support Ed25519 yet.

## License

MIT
