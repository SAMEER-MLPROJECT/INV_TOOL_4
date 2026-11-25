from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from sakshya.adapters import ADAPTERS, AdapterContext
from sakshya.core.config import colmap
from sakshya.evaluation.fixtures import build_all

TIME_TOLERANCE_S = 1.0
SCALAR_FIELDS = ("kind", "direction", "duration_s", "text")


def _fields(record: Any) -> set[tuple]:
    items: set[tuple] = {("kind", record.kind)}
    items |= {("id", role, kind, value) for role, kind, value in record.ids}
    return items


def _expected_fields(label: dict[str, Any]) -> set[tuple]:
    items: set[tuple] = {("kind", label["kind"])}
    items |= {("id", *identifier) for identifier in label["ids"]}
    return items


def _scalar_checks(record: Any, label: dict[str, Any]) -> tuple[int, int]:
    checked = passed = 0
    if "t" in label:
        checked += 1
        if label["t"] is None:
            passed += record.t_raw is None
        else:
            passed += record.t_raw is not None and abs(record.t_raw - label["t"]) <= TIME_TOLERANCE_S
    for name in ("direction", "duration_s", "text", "amount"):
        if name in label:
            checked += 1
            passed += getattr(record, name) == label[name]
    if "text_contains" in label:
        checked += 1
        passed += label["text_contains"] in (record.text or "")
    for key, value in (label.get("attrs") or {}).items():
        checked += 1
        passed += record.attrs.get(key) == value
    return checked, passed


def evaluate_fixture(directory: Path, spec: dict[str, Any]) -> dict[str, Any]:
    settings = colmap(spec["source"], spec["entry"].get("colmap"))
    ctx = AdapterContext(directory / spec["file"], "E1", spec["entry"], settings)
    try:
        result = ADAPTERS[spec["source"]](ctx)
    except Exception as exc:
        return {
            "file": spec["file"],
            "source": spec["source"],
            "error": f"{type(exc).__name__}: {exc}",
            "precision": 0.0,
            "recall": 0.0,
        }
    records = result.records
    by_key: dict[tuple[int, str], Any] = {(r.row, r.kind): r for r in records}
    true_pos = predicted = expected = 0
    checked = passed = 0
    missing = []
    matched = set()
    for label in spec["expected"]:
        want = _expected_fields(label)
        expected += len(want)
        record = by_key.get((label["row"], label["kind"]))
        if record is None:
            missing.append(label["row"])
            continue
        matched.add((record.row, record.kind))
        got = _fields(record)
        predicted += len(got)
        true_pos += len(got & want)
        c, p = _scalar_checks(record, label)
        checked += c
        passed += p
    labelled_kinds = {label["kind"] for label in spec["expected"]}
    unexpected = [r for r in records if (r.row, r.kind) not in matched and r.kind in labelled_kinds]
    for record in unexpected:
        predicted += len(_fields(record))
    precision = true_pos / predicted if predicted else 0.0
    recall = true_pos / expected if expected else 0.0
    return {
        "file": spec["file"],
        "source": spec["source"],
        "records": len(records),
        "expected_records": len(spec["expected"]),
        "missing_rows": missing,
        "unexpected_records": len(unexpected),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "value_checks": checked,
        "value_checks_passed": passed,
        "warnings": (ctx.warnings + result.warnings)[:5],
        "quarantined": ctx.quarantined,
    }


def validate(directory: Path) -> dict[str, Any]:
    labels = build_all(directory)
    rows = [evaluate_fixture(directory, spec) for spec in labels["fixtures"]]
    return {
        "note": labels["note"],
        "fixtures": rows,
        "min_precision": min(r["precision"] for r in rows),
        "min_recall": min(r["recall"] for r in rows),
        "value_checks": sum(r.get("value_checks", 0) for r in rows),
        "value_checks_passed": sum(r.get("value_checks_passed", 0) for r in rows),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m sakshya.evaluation.parsers")
    parser.add_argument("--dir", default="workspace/parser_fixtures")
    parser.add_argument("--out", default=None)
    args = parser.parse_args(argv)
    report = validate(Path(args.dir))
    text = json.dumps(report, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    print(text)
    ok = report["min_precision"] >= 0.95 and report["min_recall"] >= 0.95
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
