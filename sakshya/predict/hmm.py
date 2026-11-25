from __future__ import annotations

import json
import math
from functools import lru_cache
from typing import Any

import numpy as np
from scipy.stats import norm

from sakshya.core.config import CONFIG_DIR, settings, templates

STAY, ADVANCE, SKIP = 0.55, 0.40, 0.05
HIT, MISS = 0.85, 0.15
MODEL_VERSION = "2.0"
MIN_HISTORY = 5
PARAMS_FILE = CONFIG_DIR / "predict_params.json"


def _template(name: str) -> dict[str, Any] | None:
    return next((t for t in templates() if t["class"] == name), None)


@lru_cache(maxsize=1)
def fitted_parameters() -> dict[str, Any]:
    if not PARAMS_FILE.exists():
        return {"transitions": {}, "validation": {}}
    return json.loads(PARAMS_FILE.read_text(encoding="utf-8"))


def reload_parameters() -> None:
    fitted_parameters.cache_clear()


def duration_model(template: dict[str, Any], phase: str) -> dict[str, Any] | None:
    fitted = fitted_parameters().get("transitions", {}).get(f"{template['class']}:{phase}")
    if fitted and fitted.get("n", 0) >= MIN_HISTORY:
        return {
            "median_min": float(fitted["median_min"]),
            "sigma": float(fitted["sigma"]),
            "source": f"fitted on {fitted['n']} synthetic training cases",
            "n": int(fitted["n"]),
            "sufficient": True,
        }
    spec = template.get("transitions", {}).get(phase)
    if spec is None:
        return None
    return {
        "median_min": float(spec["median_min"]),
        "sigma": float(spec["sigma"]),
        "source": "elicited in the crime template; not fitted to data",
        "n": int(fitted["n"]) if fitted else 0,
        "sufficient": False,
    }


def _transition_matrix(size: int) -> np.ndarray:
    matrix = np.zeros((size, size))
    for i in range(size):
        matrix[i, i] = STAY
        if i + 1 < size:
            matrix[i, i + 1] = ADVANCE
        if i + 2 < size:
            matrix[i, i + 2] = SKIP
        matrix[i] /= matrix[i].sum()
    return matrix


def lognormal_cdf(minutes: float, median_min: float, sigma: float) -> float:
    if minutes <= 0:
        return 0.0
    return float(norm.cdf((math.log(minutes) - math.log(median_min)) / sigma))


def lognormal_quantile(q: float, median_min: float, sigma: float) -> float:
    return math.exp(math.log(median_min) + sigma * norm.ppf(min(max(q, 1e-9), 1 - 1e-9)))


def hmm_posterior(events: list[tuple[float, int]], size: int) -> np.ndarray:
    belief = np.zeros(size)
    belief[0] = 1.0
    matrix = _transition_matrix(size)
    for _, label in events:
        belief = belief @ matrix
        emission = np.full(size, MISS / max(size - 1, 1))
        emission[label] = HIT
        belief = belief * emission
        belief /= belief.sum()
    return belief


def hsmm_posterior(
    events: list[tuple[float, int]], size: int, as_of: float, durations: list[dict[str, Any] | None], detect: list[float]
) -> np.ndarray:
    belief = np.zeros(size)
    if not events:
        belief[0] = 1.0
        return belief
    current = max(label for _, label in events)
    start = min(t for t, label in events if label == current)
    model = durations[current] if current < len(durations) else None
    if model is None or current >= size - 1:
        belief[current] = 1.0
        return belief
    elapsed = max(0.0, (as_of - start) / 60.0)
    moved = lognormal_cdf(elapsed, model["median_min"], model["sigma"])
    unseen = 1.0 - detect[current + 1] if current + 1 < len(detect) else 1.0
    stay = 1.0 - moved
    advance = moved * unseen
    total = stay + advance
    belief[current] = stay / total if total > 0 else 1.0
    belief[current + 1] = advance / total if total > 0 else 0.0
    return belief


def predict(hypothesis: dict[str, Any] | None, as_of: float, model: str | None = None) -> dict[str, Any]:
    cfg = settings()["predict"]
    model = model or cfg.get("model", "hsmm")
    if not hypothesis or hypothesis.get("template") == "no_offence":
        return {"available": False, "reason": "No offence pattern to track"}
    template = _template(hypothesis["template"])
    if template is None:
        return {"available": False, "reason": "Template not found"}
    phases = [p for p in hypothesis["phases"] if not p.get("optional")]
    names = ["not_started"] + [p["name"] for p in phases]
    labels = ["Not started"] + [p["label"] for p in phases]
    events: list[tuple[float, int]] = []
    for index, phase in enumerate(phases, start=1):
        for t in phase.get("times", []):
            if t <= as_of:
                events.append((t, index))
    events.sort()
    size = len(names)
    durations = [None] + [duration_model(template, name) for name in names[1:]]
    detect = [0.0] + [float(p.get("observability", 0.0)) for p in phases]
    hsmm = model != "hmm"
    belief = hsmm_posterior(events, size, as_of, durations, detect) if hsmm else hmm_posterior(events, size)
    observed = max((label for _, label in events), default=0)
    current = int(np.argmax(belief))
    posterior = [{"phase": names[i], "label": labels[i], "p": round(float(belief[i]), 4)} for i in range(size)]
    validation = fitted_parameters().get("validation", {}).get(model)
    result: dict[str, Any] = {
        "available": True,
        "model": model,
        "model_version": MODEL_VERSION,
        "template": hypothesis["template"],
        "as_of": as_of,
        "posterior": posterior,
        "current": names[current],
        "current_label": labels[current],
        "last_observed": names[observed],
        "events_seen": len(events),
        "calibration_status": (
            f"validated on {validation['cases']} synthetic held-out cases, Brier {validation['brier_60']}"
            if validation
            else "not validated"
        ),
    }
    if observed == 0 or observed >= size - 1:
        result["next"] = None
        result["message"] = (
            "No offence phase observed yet"
            if observed == 0
            else f"Final phase ({labels[observed]}) reached; nothing further to predict"
        )
        return result
    phase_start = min(t for t, label in events if label == observed)
    elapsed_min = max(0.0, (as_of - phase_start) / 60.0)
    spec = durations[observed]
    if spec is None:
        result["next"] = None
        result["message"] = "No timing model for this transition"
        return result
    median, sigma = spec["median_min"], spec["sigma"]
    done = lognormal_cdf(elapsed_min, median, sigma)
    survival = max(1e-9, 1.0 - done)
    horizons = []
    for horizon in cfg["horizons_min"]:
        p = (lognormal_cdf(elapsed_min + horizon, median, sigma) - done) / survival
        horizons.append({"minutes": horizon, "p": round(min(max(p, 0.0), 1.0), 4)})

    def remaining(q: float) -> float:
        return max(0.0, lognormal_quantile(done + q * survival, median, sigma) - elapsed_min)

    latency = cfg["freeze_latency_min"]
    within_latency = (lognormal_cdf(elapsed_min + latency, median, sigma) - done) / survival
    interval = [round(remaining(0.1), 1), round(remaining(0.9), 1)]
    result.update(
        {
            "next": names[observed + 1],
            "next_label": labels[observed + 1],
            "elapsed_min": round(elapsed_min, 1),
            "typical_min": median,
            "duration_source": spec["source"],
            "sufficient_history": spec["sufficient"],
            "horizons": horizons,
            "median_remaining_min": round(remaining(0.5), 1) if spec["sufficient"] else None,
            "interval_min": interval,
            "freeze_latency_min": latency,
            "p_before_freeze": round(min(max(within_latency, 0.0), 1.0), 4),
            "p_already_moved": round(float(belief[observed + 1]) if model != "hmm" else 0.0, 4),
            "message": (
                f"{labels[observed]} started {elapsed_min:.0f} min ago. {labels[observed + 1]} usually follows within "
                f"about {median:.0f} min; it is 80% likely within {interval[0]:.0f} to {interval[1]:.0f} min from now."
            ),
        }
    )
    if not spec["sufficient"]:
        result["message"] += " The timing comes from the template, not from enough past cases, so treat it as a rough guide."
    return result


def baseline(hypothesis: dict[str, Any] | None, as_of: float) -> dict[str, Any] | None:
    if not hypothesis:
        return None
    template = _template(hypothesis["template"])
    phases = [p for p in hypothesis["phases"] if not p.get("optional")]
    observed = None
    start = None
    for index, phase in enumerate(phases):
        stamps = [t for t in phase.get("times", []) if t <= as_of]
        if stamps:
            observed, start = index, min(stamps)
    if template is None or observed is None or observed >= len(phases) - 1:
        return None
    spec = duration_model(template, phases[observed]["name"])
    if spec is None:
        return None
    predicted = start + spec["median_min"] * 60.0
    return {"next": phases[observed + 1]["name"], "predicted_t": predicted, "remaining_min": max(0.0, (predicted - as_of) / 60)}
