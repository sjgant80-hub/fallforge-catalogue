#!/usr/bin/env node
// build-catalogue.mjs — assemble the shipped catalogue from real minted manifests. Each node's
// signed manifest (from fallforge-mint) and its gate receipts become a verified listing; the
// listings are sealed into a content-addressed catalogue. No network, no LLM — pure assembly
// over artifacts that were already gated and signed.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { makeListing, buildCatalogue, verifyCatalogue } from './kernel.mjs';
import { verifyManifest } from './vendor/mint-kernel.mjs';

// each source: a minted node's manifest + a human summary + its use-case
const SOURCES = [
  { manifest: 'C:/Users/sjgan/fallforge-mint/out/triage-1b.manifest.json', node: 'triage-1b', useCase: 'support-triage',
    summary: 'Routes a support message to {category, urgency, order} as strict JSON. A 1B model that beats its own base, ~3x faster than the 7B.' },
  { manifest: 'C:/Users/sjgan/fallforge-mint/out/review-1b.manifest.json', node: 'review-1b', useCase: 'code-review',
    summary: 'Classifies a code snippet to {severity, category} as strict JSON — blocker/warning/nit/ok across bug/security/style/perf.' },
];

const listings = [];
for (const src of SOURCES) {
  if (!existsSync(src.manifest)) { console.log('skip ' + src.node + ' — no manifest at ' + src.manifest); continue; }
  const m = JSON.parse(readFileSync(src.manifest, 'utf8'));
  const vm = verifyManifest(m);
  if (!vm.ok || vm.valid !== true) { console.error('manifest for ' + src.node + ' does not verify: ' + vm.why); process.exit(1); }
  const l = makeListing({
    node: m.node, useCase: src.useCase, base: m.base, summary: src.summary,
    manifestHash: m.hash,
    receipts: m.receipts.map((r) => ({ vs: r.vs, hash: r.hash, verdict: r.verdict, certified: r.certified })),
  });
  if (!l.ok) { console.error('listing for ' + src.node + ' refused: ' + l.why); process.exit(1); }
  listings.push(l.listing);
  console.log('listed ' + src.node + ' (' + src.useCase + ') — ' + m.receipts.map((r) => r.vs + ':' + r.verdict).join(', '));
}

const cat = buildCatalogue(listings);
if (!cat.ok) { console.error('catalogue refused: ' + cat.why); process.exit(1); }
const v = verifyCatalogue(cat.catalogue);
if (!v.ok || v.valid !== true) { console.error('catalogue failed self-verification'); process.exit(1); }
writeFileSync('catalogue/catalogue.json', JSON.stringify(cat.catalogue, null, 2) + '\n');
writeFileSync('catalogue/listings.json', JSON.stringify(listings, null, 2) + '\n');
console.log('catalogue sealed: ' + cat.catalogue.count + ' nodes, hash ' + cat.catalogue.hash.slice(0, 16) + '\u2026');
