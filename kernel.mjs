// FallForge Catalogue — the marketplace kernel. Layer 4 of the sovereign-node factory: a
// listing binds a MINTED node (its signed manifest + gate receipts) to a use-case and an
// own-vs-rent savings calculator whose numbers come from the buyer's OWN rates — never a
// fabricated price. Savings can be negative, and the kernel says so (cheaper-to-rent is a
// first-class verdict, like the gate's LOSES). The catalogue is a content-addressed, tamper-
// evident index over verified listings. No money moves here — this is a shelf, not a till.
// No I/O. Pure and total: garbage in → { ok:false, why }, never a throw.

export const USE_CASES = Object.freeze([
  'support-triage', 'code-review', 'legal-review', 'finance-extract', 'doc-classify',
  'health-triage', 'sales-crm', 'education', 'security-scan', 'content-draft', 'data-extract',
]);

const isStr = (v) => typeof v === 'string';
const isNum = (v) => typeof v === 'number' && Number.isFinite(v);
const isInt = (v) => Number.isInteger(v);
const isObj = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const HEX = /^[0-9a-f]+$/;

// ── SHA-256 + canonical JSON (the estate's proven pair) ─────────────────────────────────────────
const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

export function sha256(text) {
  if (!isStr(text)) return { ok: false, why: 'sha256 takes a string' };
  const data = new TextEncoder().encode(text);
  const len = data.length;
  const padded = new Uint8Array((((len + 8) >> 6) << 6) + 64);
  padded.set(data);
  padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  const bitLen = len * 8;
  dv.setUint32(padded.length - 8, Math.floor(bitLen / 4294967296));
  dv.setUint32(padded.length - 4, bitLen >>> 0);
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const w = new Uint32Array(64);
  for (let i = 0; i < padded.length; i += 64) {
    for (let t = 0; t < 16; t++) w[t] = dv.getUint32(i + t * 4);
    for (let t = 16; t < 64; t++) {
      const x = w[t - 15], y = w[t - 2];
      const s0 = (((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3)) >>> 0;
      const s1 = (((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10)) >>> 0;
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, hh = h7;
    for (let t = 0; t < 64; t++) {
      const S1 = (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const t1 = (hh + S1 + ch + K256[t] + w[t]) >>> 0;
      const S0 = (((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + hh) >>> 0;
  }
  const hex = (n) => n.toString(16).padStart(8, '0');
  return { ok: true, hash: hex(h0) + hex(h1) + hex(h2) + hex(h3) + hex(h4) + hex(h5) + hex(h6) + hex(h7) };
}

export function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (typeof v === 'object') return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  return '"?"';
}

// ── own-vs-rent savings: the buyer's OWN rates, integer cents, drift-free, can go negative ──────
export function validRates(r) {
  if (!isObj(r)) return 'rates is an object';
  if (!isInt(r.asksPerMonth) || r.asksPerMonth <= 0) return 'asksPerMonth must be a positive integer';
  if (!isInt(r.tokensPerAsk) || r.tokensPerAsk <= 0) return 'tokensPerAsk must be a positive integer';
  if (!isNum(r.cloudUsdPerMtok) || r.cloudUsdPerMtok < 0) return 'cloudUsdPerMtok must be a non-negative number';
  if (!isNum(r.localKwhPerMtok) || r.localKwhPerMtok < 0) return 'localKwhPerMtok must be a non-negative number';
  if (!isNum(r.electricUsdPerKwh) || r.electricUsdPerKwh < 0) return 'electricUsdPerKwh must be a non-negative number';
  return null;
}

/** savings(rates) — deterministic own-vs-rent, in integer cents. Never invents a price; the
 *  caller supplies every rate. verdict CHEAPER-TO-OWN / SAME / CHEAPER-TO-RENT is honest. */
export function savings(rates) {
  const bad = validRates(rates);
  if (bad) return { ok: false, why: bad };
  const monthlyTokens = rates.asksPerMonth * rates.tokensPerAsk;              // integer
  const mtok = monthlyTokens / 1000000;
  const cloudCents = Math.round(mtok * rates.cloudUsdPerMtok * 100);
  const localCents = Math.round(mtok * rates.localKwhPerMtok * rates.electricUsdPerKwh * 100);
  const savedCents = cloudCents - localCents;
  const verdict = savedCents > 0 ? 'CHEAPER-TO-OWN' : savedCents < 0 ? 'CHEAPER-TO-RENT' : 'SAME';
  return {
    ok: true, monthlyTokens, cloudCents, localCents, savedCents, verdict,
    why: verdict === 'CHEAPER-TO-OWN' ? 'owning saves money at these rates'
      : verdict === 'CHEAPER-TO-RENT' ? 'at these rates renting is cheaper — the honest answer'
      : 'the two cost the same at these rates',
  };
}

// ── a listing: a minted node bound to a use-case, its manifest and receipt hashes, savings ──────
function validReceiptRef(r) {
  if (!isObj(r)) return 'a receipt reference is an object';
  if (!isStr(r.vs) || r.vs.length === 0) return 'receipt ref needs a vs model name';
  if (!isStr(r.hash) || r.hash.length !== 64 || !HEX.test(r.hash)) return 'receipt ref needs a 64-hex hash';
  if (!isStr(r.verdict) || r.verdict.length === 0) return 'receipt ref needs a verdict';
  if (typeof r.certified !== 'boolean') return 'receipt ref needs a boolean certified flag';
  return null;
}

export function validListing(l) {
  if (!isObj(l)) return { ok: false, why: 'a listing is an object' };
  if (!isStr(l.node) || l.node.length === 0) return { ok: false, why: 'a listing needs a node name' };
  if (!isStr(l.useCase) || !USE_CASES.includes(l.useCase)) return { ok: false, why: 'useCase must be one of the known kinds' };
  if (!isStr(l.base) || l.base.length === 0) return { ok: false, why: 'a listing needs a base model' };
  if (!isStr(l.summary) || l.summary.trim().length === 0) return { ok: false, why: 'a listing needs a summary' };
  if (!isStr(l.manifestHash) || l.manifestHash.length !== 64 || !HEX.test(l.manifestHash)) return { ok: false, why: 'a listing needs a 64-hex manifest hash' };
  if (!Array.isArray(l.receipts) || l.receipts.length === 0) return { ok: false, why: 'a listing carries at least one receipt reference' };
  for (const [i, r] of l.receipts.entries()) { const bad = validReceiptRef(r); if (bad) return { ok: false, why: 'receipt ' + i + ': ' + bad }; }
  // a listing may only be shelved if it BEATS its base, certified — the shelf sells proof, not hope
  const base = l.receipts.find((r) => r.vs === l.base);
  if (!base) return { ok: false, why: 'a listing must carry the receipt against its own base model' };
  if (base.verdict !== 'BEATS' || base.certified !== true) return { ok: false, why: 'a node that does not certifiably beat its base cannot be shelved' };
  return { ok: true };
}

export function makeListing(l) {
  const v = validListing(l);
  if (!v.ok) return v;
  const body = {
    v: 1, kind: 'fallforge-listing',
    node: l.node, useCase: l.useCase, base: l.base, summary: l.summary,
    manifestHash: l.manifestHash,
    receipts: l.receipts.map((r) => ({ vs: r.vs, hash: r.hash, verdict: r.verdict, certified: r.certified })),
    scope: 'proof is scoped to each receipt’s probe set; savings use the buyer’s own rates',
  };
  const h = sha256(canon(body));
  if (!h.ok) return { ok: false, why: h.why };
  return { ok: true, listing: { ...body, hash: h.hash } };
}

export function verifyListing(l) {
  if (!isObj(l) || l.kind !== 'fallforge-listing' || !isStr(l.hash)) return { ok: false, why: 'not a fallforge listing' };
  const body = { ...l };
  delete body.hash;
  const h = sha256(canon(body));
  if (!h.ok) return { ok: false, why: h.why };
  if (h.hash !== l.hash) return { ok: true, valid: false, why: 'hash mismatch — the listing does not match its own facts' };
  return { ok: true, valid: true, why: 'listing intact' };
}

// ── the catalogue: a content-addressed index over verified listings ─────────────────────────────
export function buildCatalogue(listings) {
  if (!Array.isArray(listings)) return { ok: false, why: 'the catalogue takes an array of listings' };
  const seen = new Set();
  const entries = [];
  for (const [i, l] of listings.entries()) {
    const v = verifyListing(l);
    if (!v.ok) return { ok: false, why: 'listing ' + i + ': ' + v.why };
    if (v.valid !== true) return { ok: false, why: 'listing ' + i + ' (' + l.node + '): ' + v.why };
    if (seen.has(l.node)) return { ok: false, why: 'duplicate node in the catalogue: ' + l.node };
    seen.add(l.node);
    entries.push({ node: l.node, useCase: l.useCase, base: l.base, summary: l.summary, hash: l.hash });
  }
  entries.sort((a, b) => a.node.localeCompare(b.node));   // no comparison operators to mutate; nodes are unique (deduped above)
  const index = { v: 1, kind: 'fallforge-catalogue', count: entries.length, nodes: entries };
  const h = sha256(canon(index));
  if (!h.ok) return { ok: false, why: h.why };
  return { ok: true, catalogue: { ...index, hash: h.hash } };
}

export function verifyCatalogue(cat) {
  if (!isObj(cat) || cat.kind !== 'fallforge-catalogue' || !isStr(cat.hash)) return { ok: false, why: 'not a fallforge catalogue' };
  const body = { ...cat };
  delete body.hash;
  const h = sha256(canon(body));
  if (!h.ok) return { ok: false, why: h.why };
  if (h.hash !== cat.hash) return { ok: true, valid: false, why: 'hash mismatch — the catalogue does not match its own entries' };
  if (!Array.isArray(cat.nodes) || cat.nodes.length !== cat.count) return { ok: true, valid: false, why: 'count does not match the entries' };
  return { ok: true, valid: true, why: 'catalogue intact' };
}

/** filterByUseCase(catalogue, useCase) — a pure view; the index is never mutated. */
export function filterByUseCase(cat, useCase) {
  const v = verifyCatalogue(cat);
  if (!v.ok) return v;
  if (v.valid !== true) return { ok: false, why: v.why };
  if (!isStr(useCase) || !USE_CASES.includes(useCase)) return { ok: false, why: 'unknown use-case' };
  return { ok: true, nodes: cat.nodes.filter((n) => n.useCase === useCase) };
}
