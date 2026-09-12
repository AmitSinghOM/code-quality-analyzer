# ADR 003: Scoring policy 2.1.0 — locking, concurrency, hardening, scheduling; labuladong gaps

**Status:** Accepted (2.44.0)

## Context

Two reviews of the 56-pattern catalog (policy 2.0.0) found gaps of a
different kind from ADR 002's.

1. **The maintainer's own backends were under-measured again.** cloudscale
   (lease-fenced consumers, expected-version event appends, HMAC request
   verification), fastapi-microservices-platform (`SKIP LOCKED` work
   claiming, Standard-Webhooks signing, SSRF-isolated egress, a scheduler)
   and wallet-transfer-service (optimistic get-or-create) lead their READMEs
   with exactly these mechanisms, and the catalog had no ID for any of
   them. The 2.0.0 additions covered *failure handling* (retries, DLQ,
   idempotency); these are *coordination and safety*: distributed locking,
   optimistic concurrency, security hardening beyond authentication, and
   scheduling.
2. **labuladong's framework (fucking-algorithm, the maintainer's DSA study
   path) named techniques the catalog recognised only under a narrower
   vocabulary.** Ring buffers and weighted-random / reservoir sampling had
   no ID; monotonic queues, difference arrays, two-heap medians, ordered
   maps (TreeMap/SortedDict/BTreeMap/skip lists), Floyd-Warshall, bipartite
   and cycle checks, sweep-line scheduling and Rabin-Karp were all
   labuladong chapters that mapped to an existing ID but not to any anchor
   in it.

Adding IDs changes the score for every project (the curves map total
matched weight to 1–10) and the maturity component measures breadth
against a fixed target.

## Decision

1. **Catalog 2.1**: add 4 design IDs (`distributed_locking`,
   `optimistic_concurrency`, `security_hardening`, `scheduling`; weights
   2.5 / 2.5 / 2.5 / 1.5) and 2 DSA IDs (`ring_buffer`,
   `randomized_sampling`; 2.0 each). 62 total. The specs live once in
   `production_patterns.py` and every language catalog inherits them, so
   the fairness gate (every language reaches every ID) holds by
   construction.
2. **Anchor extensions, not more IDs, for the labuladong gaps.**
   `SHARED_ANCHOR_EXTENSIONS` adds the missing vocabulary to eight existing
   DSA IDs; every catalog applies it through `extend_shared_anchors`. A
   technique that is a *variant* of an existing pattern (monotonic queue ⊂
   monotonic stack, difference array ⊂ prefix sum) does not earn separate
   weight.
3. **Maturity target 28 → 31**, keeping it at half the vocabulary as ADR 002
   set it. This is the only component that can *lower* a score (−0.1 on
   hiredis, ioredis, nest in calibration): a project with the same breadth
   is now measured against a larger catalog.
4. **Curves unchanged.** ADR 002 scaled the ceilings for the rarity of the
   2.0.0 additions; the 2.1.0 patterns are rarer still (the corpus median is
   one new pattern per project, maximum five on redis-py), so the added
   weight is left to lift only the projects that genuinely have them.
5. **Detection stays conservative and was calibrated before release.**
   `scheduling` and `ring_buffer` require two signals (`schedule` and
   `deque` are common words). Calibration on the 24-project corpus removed
   anchors that fired on HTTP constant tables (`IF_MATCH`,
   `PRECONDITION_FAILED`, `CONTENT_SECURITY_POLICY` on javalin), generic
   allow/deny lists (fzf's keybinding denylist), a bare `import secrets`
   (wallet's load script), and an atomic `CompareAndSwap` (HUMM's circuit
   breaker), which is memory-level, not record versioning.

## Consequences

- Scores are **not comparable across policy versions**; reports carry
  `scoring_policy_version`, and baselines keyed on 2.0.0 should be
  regenerated.
- Corpus movement (24 projects): 17 moved, all within −0.1 … +0.5;
  median +0.1. Every increase traces to a verified new-pattern hit
  (`docs/CALIBRATION.md`, "Scoring policy 2.1.0"). The maintainer's own
  repositories, which motivated the design IDs, moved fastapi 8.1 → 8.6,
  cloudscale 7.3 → 8.0, HUMM 7.4 → 7.5; wallet stayed at 6.0 after the
  `secrets` fix.
- Rank order across languages within each domain is unchanged; Rust's
  lead in web frameworks and CLI tools is the same size as before.
- Anything labuladong covers that is *not* detectable as a code idiom
  (greedy as a strategy, divide and conquer, Euler paths, Huffman coding,
  prime sieves) is deliberately not a pattern; ADR 002's "not scored is not
  penalised" stance applies.
