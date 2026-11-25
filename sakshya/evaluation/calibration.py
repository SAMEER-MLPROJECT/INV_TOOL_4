from __future__ import annotations

import math
from typing import Any

from scipy.optimize import minimize

MIN_LINKS = 50
BANDS = [
    (-math.inf, 0, "W below 0"),
    (0, 1, "W 0 to 1"),
    (1, 2, "W 1 to 2"),
    (2, 3, "W 2 to 3"),
    (3, 4, "W 3 to 4"),
    (4, math.inf, "W 4 and above"),
]


def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    if total == 0:
        return (0.0, 1.0)
    p = successes / total
    centre = (p + z * z / (2 * total)) / (1 + z * z / total)
    spread = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / (1 + z * z / total)
    return (round(max(0.0, centre - spread), 4), round(min(1.0, centre + spread), 4))


def _probability(k: float, b: float, w: float, prior: float | None) -> float:
    logit = k * w * math.log(10) + (math.log(prior) if prior else b)
    logit = max(min(logit, 40.0), -40.0)
    return min(max(1 / (1 + math.exp(-logit)), 1e-9), 1 - 1e-9)


def _loss(rows: list[tuple[float, bool, float | None]], k: float, b: float) -> float:
    total = 0.0
    for w, y, prior in rows:
        p = _probability(k, b, w, prior)
        total -= math.log(p) if y else math.log(1 - p)
    return total / len(rows)


def _brier(rows: list[tuple[float, bool, float | None]], k: float, b: float) -> float:
    return sum((_probability(k, b, w, prior) - (1.0 if y else 0.0)) ** 2 for w, y, prior in rows) / len(rows)


def fit_type(link_type: str, rows: list[tuple[float, bool, float | None]], provenance: str) -> dict[str, Any]:
    report: dict[str, Any] = {
        "type": link_type,
        "links": len(rows),
        "positives": sum(1 for _, y, _ in rows if y),
        "provenance": provenance,
    }
    if len(rows) < MIN_LINKS or report["positives"] == 0 or report["positives"] == len(rows):
        report["status"] = "insufficient data; reported weights are not calibrated"
        report["scale"] = None
        return report
    uses_prior = all(prior for _, _, prior in rows)
    start = [1.0, 0.0]
    if uses_prior:
        result = minimize(lambda x: _loss(rows, x[0], 0.0), [1.0], bounds=[(0.2, 2.0)], method="L-BFGS-B")
        k, b = float(result.x[0]), 0.0
    else:
        result = minimize(lambda x: _loss(rows, x[0], x[1]), start, bounds=[(0.2, 2.0), (-30.0, 30.0)], method="L-BFGS-B")
        k, b = float(result.x[0]), float(result.x[1])
    report.update(
        {
            "status": "fitted",
            "scale": round(k, 3),
            "intercept": None if uses_prior else round(b, 3),
            "prior": "per-link prior odds" if uses_prior else "intercept fitted from the candidate base rate",
            "log_loss": round(_loss(rows, k, b), 4),
            "log_loss_unscaled": round(_loss(rows, 1.0, b), 4),
            "brier": round(_brier(rows, k, b), 4),
            "brier_unscaled": round(_brier(rows, 1.0, b), 4),
        }
    )
    return report


def reliability(rows: list[tuple[str, float, bool, float | None]]) -> list[dict[str, Any]]:
    out = []
    for low, high, label in BANDS:
        members = [r for r in rows if low <= r[1] < high]
        if not members:
            continue
        hits = sum(1 for r in members if r[2])
        out.append(
            {
                "band": label,
                "links": len(members),
                "true_share": round(hits / len(members), 4),
                "ci95": wilson(hits, len(members)),
                "by_type": {t: sum(1 for r in members if r[0] == t) for t in sorted({r[0] for r in members})},
            }
        )
    return out


def calibrate(rows: list[tuple[str, float, bool, float | None]], provenance: str) -> dict[str, Any]:
    types = sorted({r[0] for r in rows})
    reports = {t: fit_type(t, [(w, y, p) for kind, w, y, p in rows if kind == t], provenance) for t in types}
    return {
        "types": reports,
        "reliability": {t: reliability([r for r in rows if r[0] == t]) for t in types},
    }
