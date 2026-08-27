# Actor identity and profile standard

Reviewed: 2026-08-19

ExtortSignal treats a threat-actor name as an analytic identity, not merely a
display string. The canonical registry is applied to claims, DLS catalogue
entries, retained OSINT, saved actor profiles, and actor AI analyses.

## Identity resolution rules

Labels are merged only when at least one of these conditions is met:

1. The difference is capitalization, spacing, punctuation, or an unambiguous
   rendering error.
2. A well-established equivalent name is documented in retained CTI.
3. Passive sources use an obvious site or brand suffix for the same operation,
   such as `Abyss` / `abyss-data`, `Arkana` / `arkana security`, or `Skira` /
   `skira team`.
4. Catalogue evidence explicitly identifies the leak-site name with the actor,
   such as `Dunghill Leak` with `Dark Angels`.

Version labels, successors, rebrands, affiliates, source-code relationships,
and infrastructure-sharing are not sufficient for identity deduplication.
Examples intentionally kept separate include Royal / BlackSuit, INC Ransom /
Lynx, Hive / Hunters International, Hunters International / World Leaks,
LockBit 3 / LockBit 5, and Qilin / Securotrop.

Unknown labels remain distinct. This biases the system against false merges;
an analyst can add a later mapping after corroboration.

## Passive-source audit result

The 2026-08-19 audit read the original actor field from every retained passive
source archive. It did not contact a DLS.

| Measure | Result |
| --- | ---: |
| Archived source records inspected | 128,744 |
| Archive read errors | 0 |
| Empty actor labels | 0 |
| Distinct original labels | 421 |
| Canonical labels before this review | 384 |
| Canonical labels after this review | 340 |
| Additional duplicate labels consolidated | 44 |
| Remaining case/spacing identity collisions | 0 |

Run the read-only audit again with:

```bash
PYTHONPATH=backend .venv/bin/python scripts/audit-actor-normalization.py \
  --database data/ransom-monitor.sqlite3
```

## Professional profile contract

Profiles follow `ExtortSignal CTI Profile 1.0` and keep external CTI separate
from local victim-list observations. A profile exposes:

- canonical identity, aliases, resolution basis, and related-but-distinct labels;
- actor class, TLP marking, profile status, review date, and confidence;
- sourced summary, motivation, targeting, capabilities, and campaign history;
- source references and retained field-level evidence for AI overlays;
- ATT&CK techniques, software, and campaigns where a sourced match exists;
- defensive priority actions, bounded hunt hypotheses, and detection-coverage status;
- explicit caveats for attribution, affiliate variation, reporting bias, and
  unverified victim claims.

An AI refresh is an analyst-reviewable overlay. It is applied only when it cites
retained evidence and passes the minimum evidence and confidence checks. It
cannot convert a public victim claim into confirmation of compromise.
