# FallForge Catalogue

**LIVE: https://sjgant80-hub.github.io/fallforge-catalogue/**

The shelf of sovereign nodes — layer 4 of the sovereign-node factory. Pre-minted, **owned** SLM
nodes, one per use-case, each carrying a tamper-evident proof-of-play receipt and a signed mint
manifest. Buy the node, own it, [run it private](https://github.com/sjgant80-hub/fallnode).

## On the shelf (real, minted today)

| Node | Use-case | vs its base | Own it |
|---|---|---|---|
| **triage-1b** | support-triage | BEATS `llama3.2:1b` 14/16 ✓ | support tickets → `{category, urgency, order}` |
| **review-1b** | code-review | BEATS `llama3.2:1b` 9/16 ✓ (+31%) | code snippet → `{severity, category}` |

Both are `llama3.2:1b` prompt-tuned by a limb, gated against their raw base, signed. A node
**cannot be shelved unless it certifiably beats its base** — the kernel refuses a listing whose
base receipt isn't a certified BEATS. The shelf sells proof, not hope. Each listing and the whole
index are content-addressed; the live page recomputes the hashes in your browser.

## Own vs rent — your numbers

The live calculator takes **your** rates (asks/month, tokens/ask, cloud $/Mtok, local kWh/Mtok,
electricity $/kWh), computes in integer cents, and returns **CHEAPER-TO-OWN**, **SAME**, or
**CHEAPER-TO-RENT**. No fabricated vendor prices; a calculator that can only say "buy" is a
brochure. Nothing here bills anyone — the payment rail is a separate, gated decision behind
legal counsel.

## The estate as use-cases

A deterministic crawl of ~1,510 active estate repos, bucketed into node use-cases (finance 347,
code-review 115, legal 39, …). The two on the shelf are minted; the rest are the roadmap — each a
use-case FallForge can mint a node for. The crawl runs locally on your electric, zero cloud cost.

## Run it

```bash
node --test kernel.test.mjs
node tools/witness.mjs mutate kernel.mjs --timeout 20000 --cap 500 --test node --test kernel.test.mjs
node build-catalogue.mjs      # seal listings from real minted manifests
node make-page.mjs
```

Kernel mutation-witnessed in CI (71/72, one argued equivalent); the shipped catalogue and every
listing are re-verified against the shipped kernel on every push. MIT.
