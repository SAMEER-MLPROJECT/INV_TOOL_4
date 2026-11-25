from __future__ import annotations

import argparse
import json
import math
import statistics
import tempfile
import time
import tracemalloc
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from sakshya import __version__
from sakshya.core.config import CONFIG_DIR, reload_calibration
from sakshya.core.hashing import dump_json as _dump
from sakshya.evaluation.calibration import calibrate, reliability
from sakshya.evaluation.forecast import base_rate, fit_durations, forecast_case, summarise
from sakshya.evaluation.metrics import evaluate_case, summarise_bands
from sakshya.evaluation.parsers import validate as validate_parsers
from sakshya.generator import CaseSpec, generate_case, heldout_specs, training_specs
from sakshya.pipeline import analyse, bundle
from sakshya.predict.hmm import PARAMS_FILE, reload_parameters


def dump_json(path: Path, data: Any) -> None:
    _dump(path, data)
    path.chmod(0o644)


RESULTS_PATH = Path(__file__).resolve().parent.parent / "data" / "evaluation" / "results.json"


def _mean(values: list[float]) -> float | None:
    clean = [v for v in values if v is not None and not (isinstance(v, float) and math.isnan(v))]
    return round(statistics.fmean(clean), 4) if clean else None


def run_suite(specs: list[CaseSpec], work: Path, dirs: list[Path] | None = None) -> list[dict[str, Any]]:
    results = []
    for spec in specs:
        case_dir = generate_case(spec, work)
        if dirs is not None:
            dirs.append(case_dir)
        started = time.perf_counter()
        analysis = analyse(case_dir)
        elapsed = time.perf_counter() - started
        result = evaluate_case(analysis)
        result["analysis_s"] = round(elapsed, 3)
        results.append(result)
    return results


def aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
    by_source: dict[str, list[float]] = defaultdict(list)
    for r in results:
        for source, data in r["extraction"].items():
            if data["coverage"] is not None:
                by_source[source].append(data["coverage"])
    clock = [c for r in results for c in r["clock"]]
    confusion: dict[str, Counter] = defaultdict(Counter)
    for r in results:
        confusion[r["roles"]["class_truth"]][r["roles"]["class_found"]] += 1
    crime = [r for r in results if r["roles"].get("mule_l1_correct") is not None]
    presence_post = [p for r in results for p in r["presence"]["posteriors"]]
    return {
        "cases": len(results),
        "extraction": {s: {"mean_coverage": _mean(v), "files": len(v)} for s, v in sorted(by_source.items())},
        "clock": {
            "files": len(clock),
            "median_error_s": statistics.median([c["error_s"] for c in clock]) if clock else None,
            "max_error_s": max([c["error_s"] for c in clock], default=None),
            "timezone_detected": sum(1 for c in clock if c["kind"] == "timezone" and c["detected_timezone"]),
            "timezone_cases": sum(1 for c in clock if c["kind"] == "timezone"),
        },
        "same_event": {
            "precision": _mean([r["same_event"]["precision"] for r in results]),
            "recall": _mean([r["same_event"]["recall"] for r in results]),
        },
        "presence": {
            "link_precision": _mean([r["presence"]["links"] for r in results]),
            "entity_recall": _mean([r["presence"]["entity_recall"] for r in results]),
            "impossibility_recall": _mean([r["presence"]["impossibility_recall"] for r in results]),
            "median_posterior": statistics.median(presence_post) if presence_post else None,
        },
        "resolution": {
            "precision": _mean([r["resolution"]["precision"] for r in results]),
            "recall": _mean([r["resolution"]["recall"] for r in results]),
            "f1": _mean([r["resolution"]["f1"] for r in results]),
            "decoy_merges": sum(r["resolution"]["decoy_merges"] for r in results),
            "decoy_pairs": sum(r["resolution"]["decoy_pairs"] for r in results),
        },
        "timeline": {
            "kendall_tau_before": _mean([r["timeline"].get("kendall_tau_before") for r in results]),
            "kendall_tau_after": _mean([r["timeline"].get("kendall_tau_after") for r in results]),
            "median_error_s": _mean([r["timeline"].get("median_error_s") for r in results]),
        },
        "money": {
            "precision": _mean([r["money"]["precision"] for r in results]),
            "recall": _mean([r["money"]["recall"] for r in results]),
            "cash_error_share": _mean([r["money"]["cash_error_share"] for r in results]),
        },
        "classification": {
            "accuracy": round(sum(1 for r in results if r["roles"]["class_correct"]) / len(results), 4),
            "confusion": {k: dict(v) for k, v in confusion.items()},
        },
        "roles": {
            "mule_l1_accuracy": _mean([1.0 if r["roles"]["mule_l1_correct"] else 0.0 for r in crime]),
            "cashout_accuracy": _mean(
                [1.0 if r["roles"].get("cashout_correct") else 0.0 for r in crime if "cashout_correct" in r["roles"]]
            ),
            "variant_accuracy": _mean(
                [1.0 if r["roles"].get("variant_correct") else 0.0 for r in crime if "variant_correct" in r["roles"]]
            ),
        },
        "traceability": {
            "share": _mean([r["traceability"]["share"] for r in results]),
            "pointers": sum(r["traceability"]["pointers"] for r in results),
        },
        "tamper": {
            "expected": sum(r["tamper"]["expected"] for r in results),
            "caught": sum(r["tamper"]["caught"] for r in results),
            "false_alarms": sum(r["tamper"]["false_alarms"] for r in results),
        },
        "analysis_time_s": {
            "median": statistics.median([r["analysis_s"] for r in results]),
            "max": max(r["analysis_s"] for r in results),
        },
        "calibration": summarise_bands([row for r in results for row in r["_calibration"]]),
        "calibration_by_type": reliability_by_type([row for r in results for row in r["_calibration"]]),
    }


def determinism(work: Path) -> dict[str, Any]:
    case_dir = generate_case(CaseSpec("DET-UPI", "upi_investment_fraud", 7, fixed=True), work)
    first = bundle(analyse(case_dir))["digest"]
    second = bundle(analyse(case_dir))["digest"]
    return {"identical": first == second, "digest": first}


def scaling(work: Path, scales: list[float]) -> list[dict[str, Any]]:
    rows = []
    for scale in scales:
        case_dir = generate_case(CaseSpec(f"SCALE-{scale:g}", "upi_investment_fraud", 7, scale=scale, fixed=True), work)
        tracemalloc.start()
        started = time.perf_counter()
        analysis = analyse(case_dir)
        data = bundle(analysis)
        elapsed = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        rows.append(
            {
                "scale": scale,
                "observations": data["counts"]["observations"],
                "entities": data["counts"]["entities"],
                "seconds": round(elapsed, 3),
                "peak_memory_mb": round(peak / 1e6, 1),
                "blocking": analysis.blocking,
                "decision": data["decision"]["label"],
            }
        )
    return rows


def reliability_by_type(rows: list[tuple[str, float, bool, float | None]]) -> dict[str, Any]:
    return {t: reliability([r for r in rows if r[0] == t]) for t in sorted({r[0] for r in rows})}


def parser_validation(directory: Path) -> dict[str, Any]:
    report = validate_parsers(directory)
    rows = [
        {k: r.get(k) for k in ("file", "source", "records", "precision", "recall", "value_checks", "value_checks_passed")}
        for r in report["fixtures"]
    ]
    return {**{k: v for k, v in report.items() if k != "fixtures"}, "fixtures": rows}


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate the engine on generated cases with answer keys")
    parser.add_argument("--per-kind", type=int, default=6)
    parser.add_argument("--training", type=int, default=18)
    parser.add_argument("--scales", default="1,5,10,20")
    parser.add_argument("--fit", action="store_true", help="write fitted calibration and duration parameters")
    parser.add_argument("--out", type=Path, default=RESULTS_PATH)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="sakshya-eval-") as tmp:
        work = Path(tmp)
        train_dirs: list[Path] = []
        training = run_suite(training_specs(args.training), work / "train", train_dirs)
        provenance = f"{args.training} synthetic training cases (seeds 500 to {499 + args.training})"
        calibration = calibrate([row for r in training for row in r["_calibration"]], provenance)
        durations = fit_durations(train_dirs)
        if args.fit:
            scales = {t: rep["scale"] for t, rep in calibration["types"].items() if rep.get("scale")}
            dump_json(
                CONFIG_DIR / "calibration.json",
                {"scales": scales, "fitted_on": provenance, "engine": __version__, "report": calibration["types"]},
            )
            reload_calibration()
            dump_json(PARAMS_FILE, {"transitions": durations, "fitted_on": provenance, "validation": {}})
            reload_parameters()
        held_dirs: list[Path] = []
        heldout = run_suite(heldout_specs(args.per_kind), work / "heldout", held_dirs)
        summary = aggregate(heldout)
        rate = base_rate(train_dirs)
        forecast_rows = [row for case_dir in held_dirs for row in forecast_case(case_dir, rate)]
        forecasts = summarise(forecast_rows)
        if args.fit:
            validation = {
                name: {"cases": forecasts["cases"], "brier_60": data["brier_60"], "mae_min": data.get("mae_min")}
                for name, data in forecasts["models"].items()
                if name in {"hsmm", "hmm"}
            }
            dump_json(PARAMS_FILE, {"transitions": durations, "fitted_on": provenance, "validation": validation})
            reload_parameters()
        payload = {
            "engine": __version__,
            "generated": time.strftime("%Y-%m-%d"),
            "synthetic": True,
            "heldout": summary,
            "calibration_fit": calibration,
            "durations": durations,
            "forecast": forecasts,
            "forecast_rows": forecast_rows,
            "determinism": determinism(work / "det"),
            "scaling": scaling(work / "scale", [float(s) for s in args.scales.split(",")]),
            "parsers": parser_validation(work / "parsers"),
            "cases": [{k: v for k, v in r.items() if k != "_calibration"} for r in heldout],
            "note": (
                "All cases are synthetic and generated with answer keys. The engine never reads the answer keys. "
                "Held-out cases use seeds not used while building the engine. These figures are not evidence of "
                "accuracy on real case files and are not a substitute for an independent blind evaluation."
            ),
        }
    dump_json(args.out, payload)
    print(json.dumps({k: v for k, v in payload.items() if k not in {"cases", "forecast_rows"}}, indent=2, default=str))


if __name__ == "__main__":
    main()
