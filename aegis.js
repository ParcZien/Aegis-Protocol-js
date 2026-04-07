'use strict';

const { createHash, sign, verify, randomBytes } = require('node:crypto');
const { z } = require('zod');

// ─── Constants ──────────────────────────────────────────────────────

const ALLOWED_TYPES = new Set(['string', 'number', 'boolean', 'object']);
const POISONED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const MAX_DEPTH_DEFAULT = 16;
const MAX_PAYLOAD_BYTES_DEFAULT = 1_048_576;

// ─── AegisError ─────────────────────────────────────────────────────

class AegisError extends Error {
  constructor(stage, code, message, details = null) {
    super(message);
    this.name = 'AegisError';
    this.stage = stage;
    this.code = code;
    this.details = details;
  }
}

// ─── Audit Logger ───────────────────────────────────────────────────

class AuditLogger {
  constructor(sink) {
    this._sink = sink || AuditLogger._defaultSink;
  }

  static _defaultSink(entry) {
    process.stderr.write(JSON.stringify(entry) + '\n');
  }

  denial(stage, code, message, meta = {}) {
    this._emit('DENIAL', stage, code, message, meta);
  }

  error(stage, code, message, meta = {}) {
    this._emit('ERROR', stage, code, message, meta);
  }

  success(keyId, nonce, intentHash, meta = {}) {
    this._emit('VERIFIED', 'COMPLETE', 'OK', 'Proposal verified', {
      keyId, nonce, intentHash, ...meta,
    });
  }

  _emit(level, stage, code, message, meta) {
    const entry = {
      ts: new Date().toISOString(),
      level,
      stage,
      code,
      message,
      ...meta,
    };
    try {
      this._sink(entry);
    } catch {
      // Audit sink failure must not break the pipeline
    }
  }
}

// ─── Pre-Canonicalization Validation ────────────────────────────────
// All structural checks run before any serialization or cloning occurs.

function assertNoPoisonedKeys(val, path, depth, maxDepth) {
  if (depth > maxDepth) {
    throw new AegisError('STRUCTURAL', 'MAX_DEPTH_EXCEEDED', `Exceeds max depth of ${maxDepth} at ${path}`);
  }
  if (val === null || typeof val !== 'object') return;
  if (Array.isArray(val)) {
    for (let i = 0; i < val.length; i++) {
      assertNoPoisonedKeys(val[i], `${path}[${i}]`, depth + 1, maxDepth);
    }
    return;
  }
  for (const key of Object.keys(val)) {
    if (POISONED_KEYS.has(key)) {
      throw new AegisError(
        'STRUCTURAL', 'PROTOTYPE_POLLUTION',
        `Poisoned key "${key}" at ${path}`,
        { key, path }
      );
    }
    assertNoPoisonedKeys(val[key], `${path}.${key}`, depth + 1, maxDepth);
  }
}

function assertAllowedTypes(val, path, depth, maxDepth) {
  if (depth > maxDepth) {
    throw new AegisError('STRUCTURAL', 'MAX_DEPTH_EXCEEDED', `Exceeds max depth at ${path}`);
  }
  if (val === null) return;
  if (val === undefined) {
    throw new AegisError('TYPE', 'DISALLOWED_TYPE', `undefined not allowed at ${path}`, { path });
  }
  const t = typeof val;
  if (!ALLOWED_TYPES.has(t)) {
    throw new AegisError('TYPE', 'DISALLOWED_TYPE', `Type "${t}" not allowed at ${path}`, { path, type: t });
  }
  if (t === 'number') {
    if (!Number.isFinite(val)) {
      throw new AegisError('TYPE', 'NON_FINITE_NUMBER', `Non-finite number at ${path}: ${val}`, { path, value: String(val) });
    }
  }
  if (t === 'object') {
    if (Array.isArray(val)) {
      for (let i = 0; i < val.length; i++) {
        assertAllowedTypes(val[i], `${path}[${i}]`, depth + 1, maxDepth);
      }
    } else {
      for (const k of Object.keys(val)) {
        assertAllowedTypes(val[k], `${path}.${k}`, depth + 1, maxDepth);
      }
    }
  }
}

function assertPayloadSize(raw, maxBytes) {
  const bytes = typeof raw === 'string'
    ? Buffer.byteLength(raw, 'utf8')
    : Buffer.byteLength(canonicalize(raw), 'utf8');
  if (bytes > maxBytes) {
    throw new AegisError('STRUCTURAL', 'PAYLOAD_TOO_LARGE', `Payload ${bytes} bytes exceeds limit ${maxBytes}`, { bytes, limit: maxBytes });
  }
}

// ─── Structural Clone (null-prototype, no JSON round-trip) ──────────

function structuralClone(val, depth, maxDepth) {
  if (depth > maxDepth) {
    throw new AegisError('STRUCTURAL', 'MAX_DEPTH_EXCEEDED', 'Clone exceeds max depth');
  }
  if (val === null || typeof val !== 'object') return val;
  if (Array.isArray(val)) {
    const arr = new Array(val.length);
    for (let i = 0; i < val.length; i++) {
      arr[i] = structuralClone(val[i], depth + 1, maxDepth);
    }
    return arr;
  }
  const out = Object.create(null);
  for (const k of Object.keys(val)) {
    out[k] = structuralClone(val[k], depth + 1, maxDepth);
  }
  return out;
}

// ─── Canonical JSON ─────────────────────────────────────────────────

function canonicalize(val) {
  if (val === null) return 'null';
  const t = typeof val;
  if (t === 'boolean') return val ? 'true' : 'false';
  if (t === 'number') return Object.is(val, -0) ? '0' : String(val);
  if (t === 'string') return JSON.stringify(val);
  if (Array.isArray(val)) return '[' + val.map(canonicalize).join(',') + ']';
  const keys = Object.keys(val).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(val[k])).join(',') + '}';
}

// ─── Deep Freeze ────────────────────────────────────────────────────

function deepFreeze(obj) {
  if (obj === null || typeof obj !== 'object') return obj;
  Object.freeze(obj);
  const vals = Array.isArray(obj) ? obj : Object.values(obj);
  for (const v of vals) {
    if (typeof v === 'object' && v !== null && !Object.isFrozen(v)) {
      deepFreeze(v);
    }
  }
  return obj;
}

// ─── Nonce Stores ───────────────────────────────────────────────────

class MemoryNonceStore {
  constructor() {
    this._map = new Map();
  }
  async has(nonce) {
    const exp = this._map.get(nonce);
    if (exp === undefined) return false;
    if (Date.now() > exp) {
      this._map.delete(nonce);
      return false;
    }
    return true;
  }
  async set(nonce, ttlMs) {
    if (this._map.has(nonce)) {
      throw new AegisError('NONCE', 'REPLAY_DETECTED', `Nonce ${nonce} already consumed`);
    }
    this._map.set(nonce, Date.now() + ttlMs);
  }
}

class RedisNonceStore {
  constructor(redisClient) {
    if (!redisClient) throw new Error('RedisNonceStore requires a redis client');
    this._redis = redisClient;
    this._prefix = 'aegis:nonce:';
  }
  async has(nonce) {
    const val = await this._redis.get(this._prefix + nonce);
    return val !== null;
  }
  async set(nonce, ttlMs) {
    const result = await this._redis.set(this._prefix + nonce, '1', { NX: true, PX: ttlMs });
    if (result === null) {
      throw new AegisError('NONCE', 'REPLAY_DETECTED', `Nonce ${nonce} already consumed`);
    }
  }
}

// ─── Key Ring ───────────────────────────────────────────────────────

class KeyRing {
  constructor() {
    this._keys = new Map();       // keyId -> { privateKey, publicKey, createdAt }
    this._activeKeyId = null;
  }

  addKey(keyId, privateKey, publicKey) {
    if (this._keys.has(keyId)) {
      throw new Error(`Key ID "${keyId}" already exists`);
    }
    this._keys.set(keyId, { privateKey, publicKey, createdAt: Date.now() });
    if (!this._activeKeyId) {
      this._activeKeyId = keyId;
    }
  }

  setActiveKey(keyId) {
    if (!this._keys.has(keyId)) {
      throw new Error(`Key ID "${keyId}" not found`);
    }
    this._activeKeyId = keyId;
  }

  removeKey(keyId) {
    if (keyId === this._activeKeyId) {
      throw new Error('Cannot remove the active signing key');
    }
    this._keys.delete(keyId);
  }

  getSigningKey() {
    if (!this._activeKeyId) {
      throw new AegisError('CONFIG', 'NO_ACTIVE_KEY', 'No active signing key configured');
    }
    const entry = this._keys.get(this._activeKeyId);
    return { keyId: this._activeKeyId, privateKey: entry.privateKey };
  }

  getPublicKey(keyId) {
    const entry = this._keys.get(keyId);
    if (!entry) {
      throw new AegisError('SIGNATURE', 'UNKNOWN_KEY_ID', `Key ID "${keyId}" not found`);
    }
    return entry.publicKey;
  }

  listKeys() {
    return Array.from(this._keys.entries()).map(([id, entry]) => ({
      keyId: id,
      active: id === this._activeKeyId,
      createdAt: entry.createdAt,
    }));
  }
}

// ─── AegisValidator ─────────────────────────────────────────────────

class AegisValidator {
  /**
   * @param {Object} opts
   * @param {KeyRing} opts.keyRing
   * @param {Object}  [opts.nonceStore]      - { has(nonce), set(nonce, ttlMs) }
   * @param {number}  [opts.ttlMs=30000]
   * @param {boolean} [opts.freeze=false]
   * @param {number}  [opts.maxPayloadBytes=1048576]
   * @param {number}  [opts.maxDepth=16]
   * @param {Function} [opts.auditSink]      - (entry: object) => void
   */
  constructor(opts) {
    if (!opts.keyRing || !(opts.keyRing instanceof KeyRing)) {
      throw new Error('AegisValidator requires a KeyRing instance');
    }
    this._keyRing = opts.keyRing;
    this._nonceStore = opts.nonceStore || new MemoryNonceStore();
    this._ttlMs = opts.ttlMs ?? 30_000;
    this._freeze = opts.freeze ?? false;
    this._maxPayloadBytes = opts.maxPayloadBytes ?? MAX_PAYLOAD_BYTES_DEFAULT;
    this._maxDepth = opts.maxDepth ?? MAX_DEPTH_DEFAULT;
    this._audit = new AuditLogger(opts.auditSink || undefined);
  }

  async verify(rawProposal, manifest, context) {
    const t0 = performance.now();
    try {
      // ── 1. Parse raw input ──
      let proposal;
      if (typeof rawProposal === 'string') {
        try {
          proposal = JSON.parse(rawProposal);
        } catch {
          throw new AegisError('STRUCTURAL', 'INVALID_JSON', 'Proposal is not valid JSON');
        }
      } else if (typeof rawProposal === 'object' && rawProposal !== null && !Array.isArray(rawProposal)) {
        proposal = rawProposal;
      } else {
        throw new AegisError('STRUCTURAL', 'INVALID_TYPE', 'Proposal must be a JSON string or plain object');
      }

      // ── 2. All validation BEFORE any serialization/cloning ──

      // 2a. Payload size
      assertPayloadSize(rawProposal, this._maxPayloadBytes);

      // 2b. Recursive prototype pollution scan on raw input
      assertNoPoisonedKeys(proposal, '$', 0, this._maxDepth);

      // 2c. Type restriction scan on raw input
      assertAllowedTypes(proposal, '$', 0, this._maxDepth);

      // ── 3. Clone into null-prototype objects (safe after validation) ──
      const cloned = structuralClone(proposal, 0, this._maxDepth);

      // ── 4. Zod schema validation ──
      if (!manifest.schema || typeof manifest.schema.safeParse !== 'function') {
        throw new AegisError('CONFIG', 'INVALID_MANIFEST', 'manifest.schema must be a Zod schema');
      }

      const schemaToUse = manifest.stripUnknown
        ? manifest.schema
        : (manifest.schema instanceof z.ZodObject ? manifest.schema.strict() : manifest.schema);

      const parsed = schemaToUse.safeParse(cloned);
      if (!parsed.success) {
        throw new AegisError('SCHEMA', 'VALIDATION_FAILED', 'Schema validation failed', {
          issues: parsed.error.issues.map(i => ({
            path: i.path.join('.'),
            code: i.code,
            message: i.message,
          })),
        });
      }

      const validated = parsed.data;

      // ── 5. Post-schema poisoned key re-check (defense in depth) ──
      assertNoPoisonedKeys(validated, '$', 0, this._maxDepth);
      assertAllowedTypes(validated, '$', 0, this._maxDepth);

      // ── 6. Context rules ──
      const ctx = structuralClone(context, 0, this._maxDepth);
      if (manifest.rules && Array.isArray(manifest.rules)) {
        for (let i = 0; i < manifest.rules.length; i++) {
          const rule = manifest.rules[i];
          if (typeof rule !== 'function') {
            throw new AegisError('CONFIG', 'INVALID_RULE', `Rule at index ${i} is not a function`, { ruleIndex: i });
          }
          try {
            rule(validated, ctx);
          } catch (err) {
            if (err instanceof AegisError) throw err;
            throw new AegisError('CONTEXT', 'RULE_FAILED', err.message || `Context rule ${i} failed`, { ruleIndex: i });
          }
        }
      }

      // ── 7. Freeze if configured (only the validated payload) ──
      const intent = this._freeze ? deepFreeze(validated) : validated;

      // ── 8. Canonicalize, hash, sign ──
      const canonical = canonicalize(intent);
      const intentHash = createHash('sha256').update(canonical).digest('hex');

      const { keyId, privateKey } = this._keyRing.getSigningKey();

      const nonce = randomBytes(16).toString('hex');
      const issuedAt = Date.now();
      const expiresAt = issuedAt + this._ttlMs;

      try {
        await this._nonceStore.set(nonce, this._ttlMs);
      } catch (err) {
        if (err instanceof AegisError) throw err;
        throw new AegisError('NONCE', 'STORE_UNAVAILABLE', `Nonce store failed: ${err.message}`);
      }

      const signaturePayload = `${keyId}:${nonce}:${issuedAt}:${expiresAt}:${intentHash}`;
      const signature = sign(null, Buffer.from(signaturePayload), privateKey).toString('hex');

      const packet = {
        keyId,
        nonce,
        issuedAt,
        expiresAt,
        intentHash,
        signature,
        algorithm: 'Ed25519',
      };

      this._audit.success(keyId, nonce, intentHash, { latencyMs: performance.now() - t0 });

      return {
        status: 'VERIFIED',
        sanitizedIntent: intent,
        packet,
        latencyMs: performance.now() - t0,
      };
    } catch (err) {
      const latencyMs = performance.now() - t0;
      if (err instanceof AegisError) {
        this._audit.denial(err.stage, err.code, err.message, { details: err.details, latencyMs });
        return {
          status: 'CRITICAL_DENIAL',
          stage: err.stage,
          code: err.code,
          message: err.message,
          details: err.details,
          timestamp: Date.now(),
          latencyMs,
        };
      }
      this._audit.error('INTERNAL', 'UNEXPECTED_ERROR', err.message, { latencyMs });
      return {
        status: 'CRITICAL_DENIAL',
        stage: 'INTERNAL',
        code: 'UNEXPECTED_ERROR',
        message: err.message || 'Unknown error',
        details: null,
        timestamp: Date.now(),
        latencyMs,
      };
    }
  }

  async verifyPacket(packet, sanitizedIntent) {
    try {
      if (!packet || typeof packet !== 'object') {
        this._audit.denial('PACKET', 'INVALID_PACKET', 'Packet is not an object');
        return { valid: false, reason: 'INVALID_PACKET' };
      }

      // TTL
      if (Date.now() > packet.expiresAt) {
        this._audit.denial('PACKET', 'EXPIRED', 'Packet TTL expired', {
          keyId: packet.keyId, nonce: packet.nonce, expiresAt: packet.expiresAt,
        });
        return { valid: false, reason: 'EXPIRED' };
      }

      // Nonce existence
      let nonceKnown;
      try {
        nonceKnown = await this._nonceStore.has(packet.nonce);
      } catch {
        this._audit.error('PACKET', 'NONCE_STORE_UNAVAILABLE', 'Could not reach nonce store during verification');
        return { valid: false, reason: 'NONCE_STORE_UNAVAILABLE' };
      }
      if (!nonceKnown) {
        this._audit.denial('PACKET', 'NONCE_UNKNOWN', 'Nonce not found in store', {
          keyId: packet.keyId, nonce: packet.nonce,
        });
        return { valid: false, reason: 'NONCE_UNKNOWN' };
      }

      // Hash
      assertNoPoisonedKeys(sanitizedIntent, '$', 0, this._maxDepth);
      assertAllowedTypes(sanitizedIntent, '$', 0, this._maxDepth);
      const canonical = canonicalize(sanitizedIntent);
      const recomputed = createHash('sha256').update(canonical).digest('hex');
      if (recomputed !== packet.intentHash) {
        this._audit.denial('PACKET', 'HASH_MISMATCH', 'Intent hash does not match', {
          keyId: packet.keyId, nonce: packet.nonce,
        });
        return { valid: false, reason: 'HASH_MISMATCH' };
      }

      // Signature with keyId lookup
      let publicKey;
      try {
        publicKey = this._keyRing.getPublicKey(packet.keyId);
      } catch {
        this._audit.denial('PACKET', 'UNKNOWN_KEY_ID', `Key "${packet.keyId}" not in ring`, {
          keyId: packet.keyId, nonce: packet.nonce,
        });
        return { valid: false, reason: 'UNKNOWN_KEY_ID' };
      }

      const payload = `${packet.keyId}:${packet.nonce}:${packet.issuedAt}:${packet.expiresAt}:${packet.intentHash}`;
      const sigBuffer = Buffer.from(packet.signature, 'hex');
      const ok = verify(null, Buffer.from(payload), publicKey, sigBuffer);

      if (!ok) {
        this._audit.denial('PACKET', 'INVALID_SIGNATURE', 'Signature verification failed', {
          keyId: packet.keyId, nonce: packet.nonce,
        });
        return { valid: false, reason: 'INVALID_SIGNATURE' };
      }

      return { valid: true };
    } catch (err) {
      this._audit.error('PACKET', 'VERIFICATION_ERROR', err.message);
      return { valid: false, reason: 'VERIFICATION_ERROR' };
    }
  }
}

// ─── Exports ────────────────────────────────────────────────────────

module.exports = {
  AegisValidator,
  AegisError,
  AuditLogger,
  KeyRing,
  MemoryNonceStore,
  RedisNonceStore,
  canonicalize,
};

// ─── Example Usage ──────────────────────────────────────────────────

/*
const { generateKeyPairSync } = require('node:crypto');
const { z } = require('zod');

// --- Key rotation setup ---

const keyRing = new KeyRing();

// Initial key
const k1 = generateKeyPairSync('ed25519');
keyRing.addKey('key-2025-01', k1.privateKey, k1.publicKey);

// Rotate: generate a new key, add it, switch active
const k2 = generateKeyPairSync('ed25519');
keyRing.addKey('key-2025-07', k2.privateKey, k2.publicKey);
keyRing.setActiveKey('key-2025-07');

// Old key stays in ring for verifying old packets
// keyRing.removeKey('key-2025-01');  // only after all old packets have expired

// --- Audit sink ---

const auditLog = [];
function auditSink(entry) {
  auditLog.push(entry);
  // In production: send to structured logging (ELK, Datadog, etc.)
}

// --- Validator ---

const aegis = new AegisValidator({
  keyRing,
  ttlMs: 30_000,
  freeze: true,
  maxDepth: 10,
  auditSink,
  // nonceStore: new RedisNonceStore(redisClient),
});

const manifest = {
  schema: z.object({
    action: z.enum(['transfer', 'withdraw']),
    target: z.string().regex(/^[a-zA-Z0-9@.]+$/).max(100),
    amount: z.number().positive().max(10000),
  }),
  rules: [
    (data, ctx) => {
      if (data.amount > ctx.balance) {
        throw new Error(`Insufficient balance: ${data.amount} > ${ctx.balance}`);
      }
    },
    (data, ctx) => {
      if (!ctx.allowedActions.includes(data.action)) {
        throw new Error(`Action "${data.action}" not permitted`);
      }
    },
  ],
};

const context = {
  balance: 1000,
  allowedActions: ['transfer', 'withdraw'],
};

(async () => {
  // Valid proposal
  const result = await aegis.verify(
    { action: 'transfer', target: 'alice@bank.com', amount: 250 },
    manifest,
    context,
  );
  console.log('Result:', result.status);

  if (result.status === 'VERIFIED') {
    // Packet contains keyId — verifyPacket looks up the right public key
    const check = await aegis.verifyPacket(result.packet, result.sanitizedIntent);
    console.log('Packet valid:', check.valid);
  }

  // Prototype pollution attempt
  const attack = await aegis.verify(
    '{"action":"transfer","target":"x","amount":1,"__proto__":{"admin":true}}',
    manifest,
    context,
  );
  console.log('Attack result:', attack.status, attack.code);

  // Overdraft attempt
  const overdraft = await aegis.verify(
    { action: 'withdraw', target: 'me@bank.com', amount: 5000 },
    manifest,
    context,
  );
  console.log('Overdraft result:', overdraft.status, overdraft.code);

  console.log('Audit log entries:', auditLog.length);
  auditLog.forEach(e => console.log(`  [${e.level}] ${e.stage}/${e.code}: ${e.message}`));
})();
*/
