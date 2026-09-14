import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  USE_CASES, sha256, canon, validRates, savings,
  validListing, makeListing, verifyListing, buildCatalogue, verifyCatalogue, filterByUseCase,
} from './kernel.mjs';

test('sha256 + canon: FIPS-pinned, order-blind, primitive-distinct', () => {
  assert.equal(sha256('abc').hash, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(sha256('').hash, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(sha256(9).ok, false);
  assert.equal(canon({ b: 1, a: 2 }), canon({ a: 2, b: 1 }));
  assert.notEqual(canon({ x: 5 }), canon({ x: '5' }));
  assert.notEqual(canon({ x: null }), canon({ x: 0 }));
  assert.notEqual(canon({ x: true }), canon({ x: false }));
  assert.deepEqual([...USE_CASES].slice(0, 3), ['support-triage', 'code-review', 'legal-review']);
  assert.equal(USE_CASES.length, 11);
});

// ── savings: the buyer's own rates, integer cents, honest verdicts
test('savings: own-vs-rent is deterministic, drift-free, and can say CHEAPER-TO-RENT', () => {
  // 100k asks/mo × 500 tok = 50M tok. cloud $0.50/Mtok = $25.00 = 2500c. local 300 kWh/Mtok × $0.10 = $1.50 = 150c.
  const s = savings({ asksPerMonth: 100000, tokensPerAsk: 500, cloudUsdPerMtok: 0.5, localKwhPerMtok: 3, electricUsdPerKwh: 0.10 });
  assert.equal(s.ok, true);
  assert.equal(s.monthlyTokens, 50000000);
  assert.equal(s.cloudCents, 2500);
  assert.equal(s.localCents, 1500);
  assert.equal(s.savedCents, 1000);
  assert.equal(s.verdict, 'CHEAPER-TO-OWN');
  // flip the rates so renting wins — the kernel says so plainly
  const r = savings({ asksPerMonth: 100, tokensPerAsk: 100, cloudUsdPerMtok: 0.01, localKwhPerMtok: 50, electricUsdPerKwh: 0.30 });
  assert.equal(r.verdict, 'CHEAPER-TO-RENT');
  assert.match(r.why, /renting is cheaper/);
  // exact equality is SAME, not a win (kills > vs >=)
  const eq = savings({ asksPerMonth: 1000000, tokensPerAsk: 1, cloudUsdPerMtok: 1, localKwhPerMtok: 10, electricUsdPerKwh: 0.1 });
  assert.equal(eq.cloudCents, eq.localCents);
  assert.equal(eq.verdict, 'SAME');
  // zero cloud price at real volume → renting free is cheaper; never a divide, never NaN
  const z = savings({ asksPerMonth: 100000, tokensPerAsk: 500, cloudUsdPerMtok: 0, localKwhPerMtok: 5, electricUsdPerKwh: 0.2 });
  assert.equal(z.cloudCents, 0);
  assert.equal(z.localCents, 5000);
  assert.equal(z.verdict, 'CHEAPER-TO-RENT');
});

test('validRates: every guard, boundaries exact', () => {
  const R = { asksPerMonth: 10, tokensPerAsk: 10, cloudUsdPerMtok: 0.5, localKwhPerMtok: 3, electricUsdPerKwh: 0.1 };
  assert.equal(savings(R).ok, true);
  assert.equal(savings({ ...R, asksPerMonth: 0 }).ok, false);       // must be positive
  assert.equal(savings({ ...R, asksPerMonth: 1.5 }).ok, false);
  assert.equal(savings({ ...R, tokensPerAsk: 0 }).ok, false);
  assert.equal(savings({ ...R, cloudUsdPerMtok: -0.01 }).ok, false);
  assert.equal(savings({ ...R, cloudUsdPerMtok: 0 }).ok, true);      // zero is allowed
  assert.equal(savings({ ...R, localKwhPerMtok: -1 }).ok, false);
  assert.equal(savings({ ...R, electricUsdPerKwh: -1 }).ok, false);
  assert.equal(savings({ ...R, cloudUsdPerMtok: NaN }).ok, false);
  assert.equal(savings({ ...R, cloudUsdPerMtok: Infinity }).ok, false);
  assert.equal(savings(null).ok, false);
});

// ── listings
const goodReceipts = [
  { vs: 'llama3.2:1b', hash: 'a'.repeat(64), verdict: 'BEATS', certified: true },
  { vs: 'qwen2.5:7b', hash: 'b'.repeat(64), verdict: 'LOSES', certified: false },
];
const L = {
  node: 'triage-1b', useCase: 'support-triage', base: 'llama3.2:1b',
  summary: 'Routes support tickets to category + urgency + order number.',
  manifestHash: 'c'.repeat(64), receipts: goodReceipts,
};

test('validListing: a proven node shelves; an unproven one cannot', () => {
  assert.equal(validListing(L).ok, true);
  // the base receipt must be a certified BEATS — the shelf sells proof
  assert.equal(validListing({ ...L, receipts: [{ vs: 'llama3.2:1b', hash: 'a'.repeat(64), verdict: 'LOSES', certified: false }] }).ok, false);
  assert.equal(validListing({ ...L, receipts: [{ vs: 'llama3.2:1b', hash: 'a'.repeat(64), verdict: 'BEATS', certified: false }] }).ok, false);   // uncertified win
  assert.match(validListing({ ...L, receipts: [goodReceipts[1]] }).why, /against its own base/);   // no base receipt
  assert.equal(validListing({ ...L, useCase: 'vibes' }).ok, false);
  assert.equal(validListing({ ...L, node: '' }).ok, false);
  assert.equal(validListing({ ...L, summary: '   ' }).ok, false);
  assert.equal(validListing({ ...L, manifestHash: 'a'.repeat(63) }).ok, false);
  assert.equal(validListing({ ...L, manifestHash: 'z'.repeat(64) }).ok, false);
  assert.equal(validListing({ ...L, receipts: [] }).ok, false);
  assert.equal(validListing(null).ok, false);
});

test('kill: receipt-ref guards — each clause isolated, forged array refused', () => {
  const R = (rr) => validListing({ ...L, receipts: [{ vs: 'llama3.2:1b', hash: 'a'.repeat(64), verdict: 'BEATS', certified: true }, rr] });
  assert.equal(R({ vs: 'x', hash: 'b'.repeat(64), verdict: 'LOSES', certified: false }).ok, true);
  assert.equal(R({ vs: '', hash: 'b'.repeat(64), verdict: 'L', certified: false }).ok, false);
  assert.equal(R({ vs: 7, hash: 'b'.repeat(64), verdict: 'L', certified: false }).ok, false);
  assert.equal(R({ vs: 'x', hash: 'b'.repeat(63), verdict: 'L', certified: false }).ok, false);
  assert.equal(R({ vs: 'x', hash: 'b'.repeat(64), verdict: '', certified: false }).ok, false);
  assert.equal(R({ vs: 'x', hash: 'b'.repeat(64), verdict: 'L' }).ok, false);          // no certified flag
  const arr = []; Object.assign(arr, { vs: 'x', hash: 'b'.repeat(64), verdict: 'L', certified: false });
  assert.equal(R(arr).ok, false);                                                       // array with honest fields
});

test('makeListing + verifyListing: sealed, tamper shows', () => {
  const r = makeListing(L);
  assert.equal(r.ok, true);
  assert.equal(r.listing.kind, 'fallforge-listing');
  assert.match(r.listing.scope, /buyer/);
  assert.equal(verifyListing(r.listing).valid, true);
  assert.equal(verifyListing({ ...r.listing, node: 'other' }).valid, false);
  assert.equal(verifyListing({ ...r.listing, useCase: 'code-review' }).valid, false);
  assert.equal(verifyListing({ ...r.listing, manifestHash: 'd'.repeat(64) }).valid, false);
  assert.equal(verifyListing({ ...r.listing, hash: 'f'.repeat(64) }).valid, false);
  assert.equal(verifyListing({ kind: 'fallforge-listing' }).ok, false);
  assert.equal(verifyListing('x').ok, false);
  assert.equal(makeListing({ ...L, useCase: 'nope' }).ok, false);
});

// ── the catalogue
function mk(node, useCase, base) {
  return makeListing({ node, useCase, base, summary: node + ' summary here', manifestHash: 'c'.repeat(64),
    receipts: [{ vs: base, hash: 'a'.repeat(64), verdict: 'BEATS', certified: true }] }).listing;
}

test('buildCatalogue + verifyCatalogue: sorted, deduped, tamper shows', () => {
  const cat = buildCatalogue([mk('triage-1b', 'support-triage', 'llama3.2:1b'), mk('review-1b', 'code-review', 'llama3.2:1b')]);
  assert.equal(cat.ok, true);
  assert.equal(cat.catalogue.count, 2);
  assert.deepEqual(cat.catalogue.nodes.map((n) => n.node), ['review-1b', 'triage-1b']);   // sorted
  assert.equal(verifyCatalogue(cat.catalogue).valid, true);
  assert.equal(verifyCatalogue({ ...cat.catalogue, count: 3 }).valid, false);              // count lie
  const tamperedNodes = { ...cat.catalogue, nodes: [...cat.catalogue.nodes, { node: 'ghost', useCase: 'x', base: 'y', summary: 'z', hash: '0'.repeat(64) }] };
  assert.equal(verifyCatalogue(tamperedNodes).valid, false);                               // added entry breaks hash
  assert.equal(verifyCatalogue({ kind: 'fallforge-catalogue' }).ok, false);
  assert.equal(buildCatalogue([mk('dup', 'support-triage', 'b'), mk('dup', 'code-review', 'b')]).ok, false);   // dup node
  assert.equal(buildCatalogue([{ kind: 'fallforge-listing', hash: 'f'.repeat(64) }]).ok, false);              // unverifiable listing
  assert.equal(buildCatalogue('x').ok, false);
  assert.equal(buildCatalogue([]).ok, true);                                               // an empty shelf is valid
});

// ═══ kill probes ════════════════════════════════════════════════════════════════════════════════

test('kill: local and electric rate zero-boundaries are valid (kills < vs <=)', () => {
  const R = { asksPerMonth: 10, tokensPerAsk: 10, cloudUsdPerMtok: 0.5, localKwhPerMtok: 3, electricUsdPerKwh: 0.1 };
  assert.equal(savings({ ...R, localKwhPerMtok: 0 }).ok, true);
  assert.equal(savings({ ...R, localKwhPerMtok: 0 }).localCents, 0);
  assert.equal(savings({ ...R, electricUsdPerKwh: 0 }).ok, true);
  assert.equal(savings({ ...R, electricUsdPerKwh: 0 }).localCents, 0);
});

test('kill: validListing clauses isolated — a bad base with a matching receipt is still refused', () => {
  // base '' passes the &&-mutant of clause 123, and an empty-vs receipt would satisfy the downstream
  // base-receipt check — so only the correct || catches it. Mutant lets it through; this pins it.
  const emptyBase = { node: 'n', useCase: 'support-triage', base: '', summary: 's here',
    manifestHash: 'c'.repeat(64), receipts: [{ vs: '', hash: 'a'.repeat(64), verdict: 'BEATS', certified: true }] };
  assert.equal(validListing(emptyBase).ok, false);
  assert.match(validListing(emptyBase).why, /base/);
  // receipts as a non-array object: correct || returns cleanly; the &&-mutant would fall through and throw
  assert.equal(validListing({ ...L, receipts: {} }).ok, false);
  assert.equal(validListing({ ...L, base: 7 }).ok, false);
});

test('kill: verifyListing / verifyCatalogue type-guards — forged arrays with kind+hash refused', () => {
  const fakeListing = Object.assign([], { kind: 'fallforge-listing', hash: 'a'.repeat(64) });
  assert.equal(verifyListing(fakeListing).ok, false);              // isObj excludes arrays — kills the isObj clause
  const fakeCat = Object.assign([], { kind: 'fallforge-catalogue', hash: 'a'.repeat(64) });
  assert.equal(verifyCatalogue(fakeCat).ok, false);
});

test('kill: verifyCatalogue count-vs-length guard fires even when the hash matches', () => {
  const cat = buildCatalogue([mk('a-node', 'support-triage', 'llama3.2:1b'), mk('b-node', 'code-review', 'llama3.2:1b')]).catalogue;
  // forge an inconsistent body (count says 5) and RECOMPUTE its hash so the hash check passes —
  // now only the count!==nodes.length clause stands between the forgery and a valid verdict
  const body = { v: cat.v, kind: cat.kind, count: 5, nodes: cat.nodes };
  const forged = { ...body, hash: sha256(canon(body)).hash };
  const v = verifyCatalogue(forged);
  assert.equal(v.ok, true);
  assert.equal(v.valid, false);
  assert.match(v.why, /count/);
  // and a body whose nodes is a non-array, hash recomputed to match
  const body2 = { v: cat.v, kind: cat.kind, count: 0, nodes: {} };
  const forged2 = { ...body2, hash: sha256(canon(body2)).hash };
  assert.equal(verifyCatalogue(forged2).valid, false);
});

test('filterByUseCase: a pure view over a verified catalogue', () => {
  const cat = buildCatalogue([mk('triage-1b', 'support-triage', 'llama3.2:1b'), mk('review-1b', 'code-review', 'llama3.2:1b'), mk('triage-7b', 'support-triage', 'qwen2.5:7b')]).catalogue;
  assert.deepEqual(filterByUseCase(cat, 'support-triage').nodes.map((n) => n.node), ['triage-1b', 'triage-7b']);
  assert.deepEqual(filterByUseCase(cat, 'code-review').nodes.map((n) => n.node), ['review-1b']);
  assert.deepEqual(filterByUseCase(cat, 'legal-review').nodes, []);
  assert.equal(filterByUseCase(cat, 'vibes').ok, false);
  assert.equal(filterByUseCase({ ...cat, hash: 'f'.repeat(64) }, 'support-triage').ok, false);   // won't filter a broken catalogue
});
