from __future__ import annotations

import math
import statistics
from collections import defaultdict
from itertools import pairwise
from pathlib import Path
from typing import Any

import numpy as np

from sakshya.core.config import settings, templates
from sakshya.core.hashing import load_json
from sakshya.pipeline import analyse
from sakshya.predict.hmm import baseline, predict

CRIME_CLASSES = {"upi_investment_fraud", "sextortion", "sim_swap_takeover"}
MODELS = ("hsmm", "hmm")
WINDOW_MIN = 60.0
CUTOFF_OFFSETS_MIN = (10.0, 40.0)


def phase_starts(truth: dict[str, Any]) -> dict[str, float]:
    starts: dict[str, float] = {}
    for event in truth.get("events", []):
        phase = event.get("phase")
        if phase and event.get("time") is not None:
            starts[phase] = min(starts.get(phase, math.inf), float(event["time"]))
    cash = truth.get("money", {}).get("first_cash_time")
    if cash:
        starts["cash_out"] = min(starts.get("cash_out", math.inf), float(cash))
    return starts


def fit_durations(case_dirs: list[Path]) -> dict[str, Any]:
    samples: dict[str, list[float]] = defaultdict(list)
    order = {t["class"]: [p["name"] for p in t["phases"] if not p.get("optional")] for t in templates()}
    for case_dir in case_dirs:
        truth = load_json(case_dir / "truth.json")
        names = order.get(truth["class"])
        if not names:
            continue
        starts = phase_starts(truth)
        for current, following in pairwise(names):
            if current in starts and following in starts and starts[following] > starts[current]:
                samples[f"{truth['class']}:{current}"].append((starts[following] - starts[current]) / 60.0)
    fitted = {}
    for key, values in sorted(samples.items()):
        logs = np.log(np.maximum(values, 0.5))
        fitted[key] = {
            "n": len(values),
            "median_min": round(float(math.exp(np.mean(logs))), 2),
            "sigma": round(max(float(np.std(logs, ddof=1)) if len(values) > 1 else 1.0, 0.3), 3),
        }
    return fitted


def _cutoffs(truth: dict[str, Any]) -> list[float]:
    money = truth.get("money", {})
    layering, cash = money.get("layering_time"), money.get("first_cash_time")
    if not layering or not cash:
        return []
    return [layering + m * 60 for m in CUTOFF_OFFSETS_MIN if layering + m * 60 < cash]


def forecast_case(case_dir: Path, base_rate: float) -> list[dict[str, Any]]:
    truth = load_json(case_dir / "truth.json")
    if truth["class"] not in CRIME_CLASSES:
        return []
    latency = float(settings()["predict"]["freeze_latency_min"])
    rows = []
    cash = float(truth["money"]["first_cash_time"])
    for cutoff in _cutoffs(truth):
        snapshot = analyse(case_dir, as_of=cutoff)
        decision = snapshot.explained["decision"]
        hypothesis = snapshot.crime_hypothesis() if decision.get("outcome") == "OFFENCE_SUPPORTED" else None
        actual = (cash - cutoff) / 60.0
        row: dict[str, Any] = {
            "case_id": snapshot.case_id,
            "class": truth["class"],
            "cutoff": cutoff,
            "actual_min": round(actual, 1),
            "outcome_at_cutoff": decision.get("outcome"),
            "class_at_cutoff": decision["label"],
            "records_at_cutoff": len(snapshot.obs),
            "models": {},
        }
        for model in MODELS:
            result = predict(hypothesis, cutoff, model) if hypothesis else {"available": False}
            if not result.get("available") or result.get("next") != "cash_out":
                row["models"][model] = {"available": False, "phase": result.get("current")}
                continue
            h60 = next((h["p"] for h in result["horizons"] if h["minutes"] == WINDOW_MIN), None)
            moved = float(result.get("p_already_moved", 0.0))
            p60 = moved + (1 - moved) * (h60 or 0.0)
            median = result.get("median_remaining_min")
            if median is None:
                interval = result.get("interval_min") or [0.0, 0.0]
                median = round((interval[0] + interval[1]) / 2, 1)
            low, high = result.get("interval_min") or [None, None]
            row["models"][model] = {
                "available": True,
                "phase": result.get("current"),
                "phase_correct": result.get("last_observed") == "layering",
                "predicted_min": median,
                "abs_error_min": round(abs(median - actual), 1),
                "p_within_60": round(p60, 4),
                "brier_60": round((p60 - (1.0 if actual <= WINDOW_MIN else 0.0)) ** 2, 4),
                "covered": low is not None and low <= actual <= high,
                "alert": result.get("p_before_freeze", 0) > 0.5,
                "false_alert": result.get("p_before_freeze", 0) > 0.5 and actual > latency,
            }
        naive = baseline(hypothesis, cutoff) if hypothesis else None
        if naive and naive["next"] == "cash_out":
            p60 = 1.0 if naive["remaining_min"] <= WINDOW_MIN else 0.0
            row["models"]["baseline_median"] = {
                "available": True,
                "predicted_min": round(naive["remaining_min"], 1),
                "abs_error_min": round(abs(naive["remaining_min"] - actual), 1),
                "p_within_60": p60,
                "brier_60": round((p60 - (1.0 if actual <= WINDOW_MIN else 0.0)) ** 2, 4),
            }
        row["models"]["base_rate"] = {
            "available": True,
            "p_within_60": round(base_rate, 4),
            "brier_60": round((base_rate - (1.0 if actual <= WINDOW_MIN else 0.0)) ** 2, 4),
        }
        rows.append(row)
    return rows


def base_rate(case_dirs: list[Path]) -> float:
    hits = total = 0
    for case_dir in case_dirs:
        truth = load_json(case_dir / "truth.json")
        for cutoff in _cutoffs(truth) if truth["class"] in CRIME_CLASSES else []:
            total += 1
            hits += int((truth["money"]["first_cash_time"] - cutoff) / 60.0 <= WINDOW_MIN)
    return hits / total if total else 0.5


def summarise(rows: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "cutoffs": len(rows),
        "cases": len({r["case_id"] for r in rows}),
        "split": "case-level holdout: training and held-out cases use different seeds; each cutoff re-runs the whole "
        "analysis on records time-stamped up to the cutoff",
        "class_at_cutoff_correct": round(sum(1 for r in rows if r["class_at_cutoff"] == r["class"]) / len(rows), 4)
        if rows
        else None,
        "models": {},
    }
    names = sorted({m for r in rows for m in r["models"]})
    for name in names:
        items = [r["models"][name] for r in rows if r["models"].get(name, {}).get("available")]
        if not items:
            continue
        errors = [i["abs_error_min"] for i in items if "abs_error_min" in i]
        summary = {
            "forecasts": len(items),
            "brier_60": round(statistics.fmean(i["brier_60"] for i in items), 4),
        }
        if errors:
            summary["mae_min"] = round(statistics.fmean(errors), 1)
            summary["median_abs_error_min"] = round(statistics.median(errors), 1)
        if any("covered" in i for i in items):
            summary["interval_coverage_80"] = round(sum(1 for i in items if i.get("covered")) / len(items), 3)
        if any("phase_correct" in i for i in items):
            summary["phase_accuracy"] = round(sum(1 for i in items if i.get("phase_correct")) / len(items), 3)
        if any("alert" in i for i in items):
            alerts = [i for i in items if i.get("alert")]
            summary["false_alert_share"] = round(sum(1 for i in alerts if i["false_alert"]) / len(alerts), 3) if alerts else 0.0
        by_class: dict[str, list[float]] = defaultdict(list)
        for row in rows:
            entry = row["models"].get(name, {})
            if entry.get("available"):
                by_class[row["class"]].append(entry["brier_60"])
        summary["brier_by_class"] = {k: round(statistics.fmean(v), 4) for k, v in sorted(by_class.items())}
        out["models"][name] = summary
    return out
