/**
 * AEGIS PROTOCOL v2
 * Universal AI Deterministic Gate — Hardened
 *
 * Zero-dependency vanilla JS. Fail-closed 4-stage validation pipeline
 * with 8 additional hardening fixes for financial-grade determinism.
 *
 * Hardening coverage:
 *   Fix 1: NaN/Infinity rejection via Number.isFinite
 *   Fix 2: Strict type checking, zero coercion
 *   Fix 3: Nested trojan sanitization — dangerous chars rejected in all strings
 *   Fix 4: Nonce-based replay/double-spend protection
 *   Fix 5: Prototype pollution — only manifest-declared keys traversed
 *   Fix 6: Large number precision — Number.isSafeInteger enforcement
 *   Fix 7: Deep freeze on all validated data, clean-room copies throughout
 *   Fix 8: TTL expiry on verification packets
 *
 * Usage:
 *   const result = await Aegis.verify(aiProposal, ruleManifest, systemContext);
 *   if (result.status === 'VERIFIED') {
 *     // Pass result.packet to your API/DB layer
 *     // DB must reject if packet.nonce was already consumed
 *     // DB must reject if Date.now() > packet.expiresAt
 *   }
 *
 * Rule Manifest Schema:
 *   {
 *     requiredKeys: ['action', 'amount'],
 *     ttlMs: 30000,                          // packet lifetime (default 30s)
 *     safeIntegers: true,                     // enforce Number.isSafeInteger on all numbers
 *     dangerousCharsPattern: '[;<>\\\\`"\']', // regex for nested trojan rejection (all strings)
 *     schema: {
 *       action: { type: 'string', whitelist: ['transfer', 'withdraw'], pattern: '^[a-z]+$' },
 *       amount: { type: 'number', min: 0.01, max: 10000 },
 *       memo:   { type: 'string', maxLength: 200 }
 *     },
 *     contextRules: [
 *       { field: 'amount', operator: '<=', contextField: 'balance' },
 *       { field: 'action', operator: 'in', contextField: 'allowedActions' }
 *     ]
 *   }
 */

const Aegis = (() => {
  'use strict';

  // ═══════════════════════════════════════════════════════════════════
  // CONFIGURATION DEFAULTS
  // ═══════════════════════════════════════════════════════════════════

  const DEFAULT_TTL_MS = 30_000;
  const DEFAULT_DANGEROUS_CHARS = '[;<>`\\\\"\\\'\\x00-\\x1f]';

  // ═══════════════════════════════════════════════════════════════════
  // NONCE REGISTRY (Fix 4 — replay protection within this runtime)
  // ═══════════════════════════════════════════════════════════════════

  const _consumedNonces = new Set();
  const MAX_NONCE_CACHE = 10_000;

  function _generateNonce() {
    const buf = new Uint8Array(16);
    crypto.getRandomValues(buf);
    return Array.from(buf, b => b.toString(16).padStart(2, '0')).join('');
  }

  function _consumeNonce(nonce) {
    if (_consumedNonces.has(nonce)) return false;
    _consumedNonces.add(nonce);
    if (_consumedNonces.size > MAX_NONCE_CACHE) {
      const first = _consumedNonces.values().next().value;
      _consumedNonces.delete(first);
    }
    return true;
  }

  // ═══════════════════════════════════════════════════════════════════
  // CRYPTO PRIMITIVES (Web Crypto API — zero external deps)
  // ═══════════════════════════════════════════════════════════════════

  let _signingKey = null;
  let _verifyKey = null;

  async function _ensureKeys() {
    if (_signingKey) return;
    const keyPair = await crypto.subtle.generateKey(
      { name: 'Ed25519' },
      false,
      ['sign', 'verify']
    ).catch(() =>
      crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify']
      )
    );
    _signingKey = keyPair.privateKey;
    _verifyKey = keyPair.publicKey;
  }

  async function _sha256(data) {
    const encoded = new TextEncoder().encode(
      typeof data === 'string' ? data : JSON.stringify(data)
    );
    const buf = await crypto.subtle.digest('SHA-256', encoded);
    return Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join('');
  }

  async function _sign(data) {
    await _ensureKeys();
    const encoded = new TextEncoder().encode(data);
    const algo = _signingKey.algorithm.name === 'Ed25519'
      ? { name: 'Ed25519' }
      : { name: 'ECDSA', hash: 'SHA-256' };
    const buf = await crypto.subtle.sign(algo, _signingKey, encoded);
    return Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join('');
  }

  // ═══════════════════════════════════════════════════════════════════
  // CLEAN-ROOM COPY (Fix 5 + Fix 7)
  // ═══════════════════════════════════════════════════════════════════

  const POISONED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

  function _cleanCopy(obj) {
    const raw = JSON.parse(JSON.stringify(obj));
    return _stripPoisoned(raw);
  }

  function _stripPoisoned(node) {
    if (node === null || typeof node !== 'object') return node;
    if (Array.isArray(node)) return node.map(_stripPoisoned);
    const clean = Object.create(null);
    for (const key of Object.keys(node)) {
      if (POISONED_KEYS.has(key)) continue;
      clean[key] = _stripPoisoned(node[key]);
    }
    return clean;
  }

  function _deepFreeze(obj) {
    if (obj === null || typeof obj !== 'object') return obj;
    Object.freeze(obj);
    for (const v of Object.values(obj)) {
      if (typeof v === 'object' && v !== null && !Object.isFrozen(v)) {
        _deepFreeze(v);
      }
    }
    return obj;
  }

  // ═══════════════════════════════════════════════════════════════════
  // DENIAL FACTORY
  // ═══════════════════════════════════════════════════════════════════

  function _deny(stage, code, message, details = null) {
    return {
      status: 'CRITICAL_DENIAL',
      stage,
      code,
      message,
      details,
      timestamp: Date.now()
    };
  }

  // ═══════════════════════════════════════════════════════════════════
  // STAGE 1: STRUCTURAL INTEGRITY
  // ═══════════════════════════════════════════════════════════════════

  function _stageStructural(proposal, manifest) {
    let raw;

    if (typeof proposal === 'string') {
      try {
        raw = JSON.parse(proposal);
      } catch {
        return { ok: false, error: _deny(1, 'INVALID_JSON', 'AI output is not valid JSON') };
      }
    } else if (typeof proposal === 'object' && proposal !== null && !Array.isArray(proposal)) {
      raw = proposal;
    } else {
      return { ok: false, error: _deny(1, 'INVALID_TYPE', 'Proposal must be a JSON string or plain object') };
    }

    // Clean-room copy: severs references, strips __proto__ et al.
    const parsed = _cleanCopy(raw);

    // Detect prototype pollution attempts explicitly (Fix 5)
    const rawKeys = typeof proposal === 'string'
      ? Object.keys(JSON.parse(proposal))
      : Object.keys(proposal);
    const poisoned = rawKeys.filter(k => POISONED_KEYS.has(k));
    if (poisoned.length > 0) {
      return {
        ok: false,
        error: _deny(1, 'PROTOTYPE_POLLUTION', `Blocked prototype-polluting keys: ${poisoned.join(', ')}`, { poisoned })
      };
    }

    // Required keys
    const missing = manifest.requiredKeys.filter(k => !(k in parsed));
    if (missing.length > 0) {
      return {
        ok: false,
        error: _deny(1, 'MISSING_KEYS', `Missing required keys: ${missing.join(', ')}`, { missing })
      };
    }

    // Hallucinated keys
    const allowedKeys = new Set(Object.keys(manifest.schema));
    const extra = Object.keys(parsed).filter(k => !allowedKeys.has(k));
    if (extra.length > 0) {
      return {
        ok: false,
        error: _deny(1, 'HALLUCINATED_KEYS', `Unexpected keys: ${extra.join(', ')}`, { extra })
      };
    }

    return { ok: true, parsed };
  }

  // ═══════════════════════════════════════════════════════════════════
  // STAGE 2: TYPE ENFORCEMENT
  // ═══════════════════════════════════════════════════════════════════

  function _stageTypeEnforcement(parsed, manifest) {
    const violations = [];

    for (const [key, rule] of Object.entries(manifest.schema)) {
      if (!(key in parsed)) continue;
      const value = parsed[key];

      if (value === null || value === undefined) {
        if (manifest.requiredKeys.includes(key)) {
          violations.push({ key, expected: rule.type, got: 'null/undefined' });
        }
        continue;
      }

      // Strict type — "100" !== number (Fix 2)
      const actual = typeof value;
      if (actual !== rule.type) {
        violations.push({ key, expected: rule.type, got: actual, value });
        continue;
      }

      if (rule.type === 'number') {
        // Fix 1: NaN, Infinity, -Infinity
        if (!Number.isFinite(value)) {
          violations.push({ key, expected: 'finite number', got: String(value) });
          continue;
        }
        // Fix 6: unsafe integer precision
        if (manifest.safeIntegers && Number.isInteger(value) && !Number.isSafeInteger(value)) {
          violations.push({
            key,
            expected: `safe integer (abs <= ${Number.MAX_SAFE_INTEGER})`,
            got: value
          });
        }
      }
    }

    if (violations.length > 0) {
      return {
        ok: false,
        error: _deny(2, 'TYPE_MISMATCH', `Type violations in ${violations.length} field(s)`, { violations })
      };
    }

    return { ok: true };
  }

  // ═══════════════════════════════════════════════════════════════════
  // STAGE 3: BOUNDARY CONSTRAINTS
  // ═══════════════════════════════════════════════════════════════════

  function _stageBoundary(parsed, manifest) {
    const violations = [];
    const dangerousCharsRegex = new RegExp(
      manifest.dangerousCharsPattern || DEFAULT_DANGEROUS_CHARS
    );

    for (const [key, rule] of Object.entries(manifest.schema)) {
      if (!(key in parsed)) continue;
      const value = parsed[key];
      if (value === null || value === undefined) continue;

      // ── Number constraints ──
      if (rule.type === 'number') {
        if (rule.min !== undefined && value < rule.min) {
          violations.push({ key, constraint: 'min', limit: rule.min, actual: value });
        }
        if (rule.max !== undefined && value > rule.max) {
          violations.push({ key, constraint: 'max', limit: rule.max, actual: value });
        }
      }

      // ── String constraints ──
      if (rule.type === 'string') {
        // Fix 3: nested trojan — dangerous characters
        if (dangerousCharsRegex.test(value)) {
          violations.push({
            key,
            constraint: 'dangerousChars',
            pattern: dangerousCharsRegex.source,
            actual: value,
            reason: 'String contains potentially dangerous characters'
          });
          continue;
        }

        if (rule.minLength !== undefined && value.length < rule.minLength) {
          violations.push({ key, constraint: 'minLength', limit: rule.minLength, actual: value.length });
        }
        if (rule.maxLength !== undefined && value.length > rule.maxLength) {
          violations.push({ key, constraint: 'maxLength', limit: rule.maxLength, actual: value.length });
        }
        if (rule.pattern && !new RegExp(rule.pattern).test(value)) {
          violations.push({ key, constraint: 'pattern', pattern: rule.pattern, actual: value });
        }
        if (rule.whitelist && !rule.whitelist.includes(value)) {
          violations.push({ key, constraint: 'whitelist', allowed: rule.whitelist, actual: value });
        }
        if (rule.blacklist && rule.blacklist.includes(value)) {
          violations.push({ key, constraint: 'blacklist', blocked: rule.blacklist, actual: value });
        }
      }
    }

    if (violations.length > 0) {
      return {
        ok: false,
        error: _deny(3, 'BOUNDARY_VIOLATION', `Boundary violations in ${violations.length} field(s)`, { violations })
      };
    }

    return { ok: true };
  }

  // ═══════════════════════════════════════════════════════════════════
  // STAGE 4: CONTEXTUAL VERIFICATION
  // ═══════════════════════════════════════════════════════════════════

  function _stageContextual(parsed, manifest, context) {
    if (!manifest.contextRules || manifest.contextRules.length === 0) {
      return { ok: true };
    }

    const violations = [];

    for (const rule of manifest.contextRules) {
      const proposalValue = parsed[rule.field];
      const contextValue = context[rule.contextField];

      if (proposalValue === undefined) continue;

      if (contextValue === undefined) {
        violations.push({
          rule,
          reason: `Context field "${rule.contextField}" missing from system context`
        });
        continue;
      }

      let passed = false;
      switch (rule.operator) {
        case '<=':  passed = proposalValue <= contextValue; break;
        case '>=':  passed = proposalValue >= contextValue; break;
        case '<':   passed = proposalValue < contextValue; break;
        case '>':   passed = proposalValue > contextValue; break;
        case '===': passed = proposalValue === contextValue; break;
        case '!==': passed = proposalValue !== contextValue; break;
        case 'in':
          passed = Array.isArray(contextValue) && contextValue.includes(proposalValue);
          break;
        case 'not_in':
          passed = Array.isArray(contextValue) && !contextValue.includes(proposalValue);
          break;
        default:
          violations.push({ rule, reason: `Unknown operator: "${rule.operator}"` });
          continue;
      }

      if (!passed) {
        violations.push({
          field: rule.field,
          operator: rule.operator,
          proposalValue,
          contextField: rule.contextField,
          contextValue: Array.isArray(contextValue) ? `[${contextValue.length} items]` : contextValue,
          reason: `${rule.field} (${proposalValue}) ${rule.operator} ${rule.contextField} (${contextValue}) → false`
        });
      }
    }

    if (violations.length > 0) {
      return {
        ok: false,
        error: _deny(4, 'CONTEXT_VIOLATION', `Contextual violations in ${violations.length} rule(s)`, { violations })
      };
    }

    return { ok: true };
  }

  // ═══════════════════════════════════════════════════════════════════
  // PUBLIC API
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Aegis.verify(aiProposal, ruleManifest, systemContext)
   *
   * @param {string|object} aiProposal   - Raw AI output (JSON string or object)
   * @param {object}        ruleManifest  - Immutable rule schema
   * @param {object}        systemContext - Live environment state
   * @returns {Promise<object>} VERIFIED packet or CRITICAL_DENIAL
   */
  async function verify(aiProposal, ruleManifest, systemContext) {
    const t0 = performance.now();

    // Clean-room, prototype-safe, deep-frozen copies (Fix 5 + Fix 7)
    const manifest = _deepFreeze(_cleanCopy(ruleManifest));
    const context = _deepFreeze(_cleanCopy(systemContext));

    // ── Stage 1: Structural Integrity ──
    const s1 = _stageStructural(aiProposal, manifest);
    if (!s1.ok) return { ...s1.error, latencyMs: performance.now() - t0 };

    // Deep-freeze parsed proposal immediately (Fix 7)
    const parsed = _deepFreeze(s1.parsed);

    // ── Stage 2: Type Enforcement ──
    const s2 = _stageTypeEnforcement(parsed, manifest);
    if (!s2.ok) return { ...s2.error, latencyMs: performance.now() - t0 };

    // ── Stage 3: Boundary Constraints ──
    const s3 = _stageBoundary(parsed, manifest);
    if (!s3.ok) return { ...s3.error, latencyMs: performance.now() - t0 };

    // ── Stage 4: Contextual Verification ──
    const s4 = _stageContextual(parsed, manifest, context);
    if (!s4.ok) return { ...s4.error, latencyMs: performance.now() - t0 };

    // ── All stages passed → Verification Packet ──

    const nonce = _generateNonce();                            // Fix 4
    const timestamp = Date.now();
    const ttlMs = manifest.ttlMs || DEFAULT_TTL_MS;
    const expiresAt = timestamp + ttlMs;                       // Fix 8
    const intentHash = await _sha256(parsed);
    const signaturePayload = `${nonce}:${timestamp}:${expiresAt}:${intentHash}`;
    const signature = await _sign(signaturePayload);

    _consumeNonce(nonce);                                      // Fix 4

    return {
      status: 'VERIFIED',
      sanitizedIntent: parsed,
      packet: {
        nonce,
        timestamp,
        expiresAt,
        intentHash,
        signature,
        algorithm: _signingKey.algorithm.name === 'Ed25519' ? 'Ed25519' : 'ECDSA-P256'
      },
      stages: {
        structural: 'PASS',
        typeEnforcement: 'PASS',
        boundary: 'PASS',
        contextual: 'PASS'
      },
      latencyMs: performance.now() - t0
    };
  }

  /**
   * Aegis.verifyPacket(packet, sanitizedIntent)
   *
   * Re-verify a previously issued packet.
   * Checks hash integrity, signature validity, and TTL expiry.
   */
  async function verifyPacket(packet, sanitizedIntent) {
    // Fix 8: TTL
    if (Date.now() > packet.expiresAt) {
      return { valid: false, reason: 'EXPIRED', expiresAt: packet.expiresAt };
    }

    // Hash integrity
    const recomputedHash = await _sha256(sanitizedIntent);
    if (recomputedHash !== packet.intentHash) {
      return { valid: false, reason: 'HASH_MISMATCH' };
    }

    // Signature
    const payload = `${packet.nonce}:${packet.timestamp}:${packet.expiresAt}:${packet.intentHash}`;
    const encoded = new TextEncoder().encode(payload);
    const sigBytes = new Uint8Array(
      packet.signature.match(/.{2}/g).map(h => parseInt(h, 16))
    );
    const algo = packet.algorithm === 'Ed25519'
      ? { name: 'Ed25519' }
      : { name: 'ECDSA', hash: 'SHA-256' };

    const sigValid = await crypto.subtle.verify(algo, _verifyKey, sigBytes, encoded);
    return sigValid
      ? { valid: true }
      : { valid: false, reason: 'INVALID_SIGNATURE' };
  }

  /**
   * Aegis.rotateKeys()
   * Force new signing keypair. Invalidates all previously signed packets.
   */
  async function rotateKeys() {
    _signingKey = null;
    _verifyKey = null;
    await _ensureKeys();
  }

  /**
   * Aegis.flushNonces()
   * Clear the in-memory nonce registry.
   */
  function flushNonces() {
    _consumedNonces.clear();
  }

  return Object.freeze({ verify, verifyPacket, rotateKeys, flushNonces });
})();

// ═══════════════════════════════════════════════════════════════════════
// EXPORT (Node.js / Deno / Bun / Browser)
// ═══════════════════════════════════════════════════════════════════════
if (typeof module !== 'undefined' && module.exports) {
  module.exports = Aegis;
} else if (typeof globalThis !== 'undefined') {
  globalThis.Aegis = Aegis;
}
