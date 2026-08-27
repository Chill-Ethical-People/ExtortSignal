#!/usr/bin/env python3
"""Audit original passive-feed actor labels against ExtortSignal normalization.

The report reads immutable gzip archives referenced by source_observations. It does
not contact a source or mutate the database. Original spellings stay visible even
when the canonical claim table has already been migrated.
"""

from __future__ import annotations

import argparse
import gzip
import json
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from ransom_monitor.actor_names import (  # noqa: E402
    actor_identity_key,
    actor_name_key,
    canonical_actor_name,
    known_actor_aliases,
)
from ransom_monitor.actor_profiles_static import lookup_static_profile  # noqa: E402


ACTOR_FIELDS = {
    "ransomlook": ("group_name", "group"),
    "ransomfeed": ("gang", "group_name"),
    "ransomware_live": ("group", "group_name"),
}


def original_actor(source: str, archived_record: dict) -> str:
    raw = archived_record.get("raw")
    if not isinstance(raw, dict):
        raw = {}
    for field in ACTOR_FIELDS.get(source, ()):
        value = str(raw.get(field) or "").strip()
        if value:
            return value
    return str(archived_record.get("threat_actor") or "").strip()


def audit(database_path: Path) -> dict:
    connection = sqlite3.connect(database_path)
    rows = connection.execute(
        """SELECT source, raw_path FROM source_observations
           WHERE raw_path <> '' ORDER BY source, raw_path"""
    ).fetchall()
    connection.close()

    source_labels: dict[str, Counter[str]] = defaultdict(Counter)
    archive_errors = 0
    empty_labels = 0
    seen_paths: set[str] = set()
    for source, raw_path in rows:
        if raw_path in seen_paths:
            continue
        seen_paths.add(raw_path)
        try:
            with gzip.open(raw_path, "rt", encoding="utf-8") as handle:
                payload = json.load(handle)
            record = payload.get("record", {})
            if not isinstance(record, dict):
                raise ValueError("archive record is not an object")
            actor = original_actor(source, record)
            if actor:
                source_labels[source][actor] += 1
            else:
                empty_labels += 1
        except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
            archive_errors += 1

    variants: dict[str, Counter[str]] = defaultdict(Counter)
    identity_labels: dict[str, set[str]] = defaultdict(set)
    raw_key_labels: dict[str, set[str]] = defaultdict(set)
    source_presence: dict[str, set[str]] = defaultdict(set)
    all_labels = Counter()
    for source, labels in source_labels.items():
        for label, count in labels.items():
            canonical = canonical_actor_name(label)
            variants[canonical][label] += count
            identity_labels[actor_identity_key(label)].add(canonical)
            raw_key_labels[actor_name_key(label)].add(label)
            source_presence[canonical].add(source)
            all_labels[label] += count

    unmapped = []
    for label, count in all_labels.most_common():
        canonical = canonical_actor_name(label)
        if known_actor_aliases(label) == (canonical,):
            unmapped.append(
                {
                    "label": label,
                    "count": count,
                    "canonical_display": canonical,
                    "has_curated_profile": bool(lookup_static_profile(canonical)),
                    "sources": sorted(source_presence[canonical]),
                }
            )

    return {
        "database": str(database_path),
        "archived_files_scanned": len(seen_paths),
        "archive_errors": archive_errors,
        "empty_actor_labels": empty_labels,
        "distinct_original_labels": len(all_labels),
        "distinct_canonical_labels": len(variants),
        "sources": {
            source: {
                "records": sum(labels.values()),
                "distinct_original_labels": len(labels),
                "labels": dict(labels.most_common()),
            }
            for source, labels in sorted(source_labels.items())
        },
        "canonical_variant_groups": {
            canonical: dict(labels.most_common())
            for canonical, labels in sorted(
                variants.items(), key=lambda item: item[0].casefold()
            )
            if len(labels) > 1
        },
        "unresolved_identity_collisions": {
            key: sorted(labels, key=str.casefold)
            for key, labels in identity_labels.items()
            if len(labels) > 1
        },
        "format_only_collisions": {
            key: sorted(labels, key=str.casefold)
            for key, labels in raw_key_labels.items()
            if len(labels) > 1
        },
        "unmapped_original_labels": unmapped,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--database",
        type=Path,
        default=ROOT / "data" / "ransom-monitor.sqlite3",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = audit(args.database.resolve())
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(f"{rendered}\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
