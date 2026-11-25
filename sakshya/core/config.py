from __future__ import annotations

import copy
import hashlib
import json
from functools import cache, lru_cache
from pathlib import Path
from typing import Any

import yaml

CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"


@cache
def _load_yaml(path: str) -> Any:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def settings() -> dict[str, Any]:
    return copy.deepcopy(_load_yaml(str(CONFIG_DIR / "settings.yaml")))


def config_file(name: str) -> Any:
    return copy.deepcopy(_load_yaml(str(CONFIG_DIR / name)))


def source_types() -> list[str]:
    return sorted(p.stem for p in (CONFIG_DIR / "colmaps").glob("*.yaml"))


def colmap(source: str, override: dict[str, Any] | None = None) -> dict[str, Any]:
    path = CONFIG_DIR / "colmaps" / f"{source}.yaml"
    if not path.exists():
        raise ValueError(f"No column map for source type '{source}'")
    merged = copy.deepcopy(_load_yaml(str(path)))
    for key, value in (override or {}).items():
        if key == "columns" and isinstance(value, dict):
            merged.setdefault("columns", {}).update(value)
        else:
            merged[key] = value
    return merged


def channel_of(source: str) -> str:
    try:
        return str(colmap(source).get("observes_as") or source)
    except ValueError:
        return source


def templates() -> list[dict[str, Any]]:
    items = []
    for path in sorted((CONFIG_DIR / "templates").glob("*.yaml")):
        items.append(copy.deepcopy(_load_yaml(str(path))))
    return items


@lru_cache(maxsize=1)
def calibration() -> dict[str, Any]:
    path = CONFIG_DIR / "calibration.json"
    if not path.exists():
        return {"scales": {}, "fitted_on": None}
    return json.loads(path.read_text(encoding="utf-8"))


def calibration_scale(link_type: str) -> float:
    return float(calibration().get("scales", {}).get(link_type, 1.0))


def reload_calibration() -> None:
    calibration.cache_clear()


def config_digest() -> str:
    digest = hashlib.sha256()
    for path in sorted(CONFIG_DIR.rglob("*")):
        if path.is_file() and path.suffix in {".yaml", ".json"}:
            digest.update(path.relative_to(CONFIG_DIR).as_posix().encode("utf-8"))
            digest.update(path.read_bytes())
    return digest.hexdigest()


class ConfigError(ValueError):
    pass


FINDERS = {
    "seed",
    "contacted_seed",
    "first_hop_accounts",
    "onward_accounts",
    "present_at_cash",
    "device_operators",
    "sim_controller",
}
PHASE_EVENTS = {"contact", "lure", "threat", "payment", "layering", "cash_out", "control", "sim_change", "otp"}
SETTINGS_SECTIONS = {"clock", "links", "money", "explain", "predict", "decide"}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ConfigError(message)


def validate_template(template: Any, indicator_names: set[str], sources: set[str]) -> None:
    _require(isinstance(template, dict), "A crime template must be a mapping")
    name = template.get("class", "?")
    for key in ("class", "label", "prior_log10", "roles", "phases", "version"):
        _require(key in template, f"Template {name} has no '{key}'")
    _require(
        isinstance(template["prior_log10"], (int, float)) and template["prior_log10"] <= 0, f"{name}: prior_log10 must be <= 0"
    )
    roles = template["roles"]
    _require(isinstance(roles, list) and roles, f"{name}: roles must be a non-empty list")
    role_names = set()
    for role in roles:
        _require(isinstance(role, dict) and isinstance(role.get("name"), str), f"{name}: each role needs a name")
        _require(role["name"] not in role_names, f"{name}: role {role['name']} is defined twice")
        role_names.add(role["name"])
        _require(role.get("find") in FINDERS, f"{name}: role {role['name']} has unknown finder {role.get('find')}")
        for key in ("supports", "contradicts"):
            for indicator in role.get(key, []):
                _require(indicator in indicator_names, f"{name}: role {role['name']} uses unknown indicator {indicator}")
        for variant, spec in (role.get("variants") or {}).items():
            for key in ("supports", "contradicts"):
                for indicator in spec.get(key, []):
                    _require(indicator in indicator_names, f"{name}: variant {variant} uses unknown indicator {indicator}")
    seen = []
    for phase in template["phases"]:
        _require(isinstance(phase, dict) and isinstance(phase.get("name"), str), f"{name}: each phase needs a name")
        _require(phase.get("role") in role_names, f"{name}: phase {phase['name']} names unknown role {phase.get('role')}")
        _require(phase.get("events") in PHASE_EVENTS, f"{name}: phase {phase['name']} has unknown events {phase.get('events')}")
        if phase.get("after") is not None:
            _require(phase["after"] in seen, f"{name}: phase {phase['name']} follows {phase['after']}, which is not earlier")
        for rule in phase.get("observability", []):
            _require(rule.get("source") in sources, f"{name}: phase {phase['name']} uses unknown source {rule.get('source')}")
            _require(0.0 <= float(rule.get("o", -1)) < 1.0, f"{name}: observability must be in [0, 1)")
            if rule.get("of") is not None:
                _require(rule["of"] in role_names, f"{name}: observability names unknown role {rule['of']}")
        for key in ("min_lag_h", "max_lag_h"):
            if key in phase:
                _require(isinstance(phase[key], (int, float)) and phase[key] >= 0, f"{name}: {key} must be a positive number")
        seen.append(phase["name"])
    for phase_name, spec in (template.get("transitions") or {}).items():
        _require(phase_name in seen, f"{name}: transition for unknown phase {phase_name}")
        _require(float(spec.get("median_min", 0)) > 0 and float(spec.get("sigma", 0)) > 0, f"{name}: bad transition {phase_name}")
    for relation in template.get("relationships", []):
        _require(
            relation.get("type") in {"co_presence", "same_actor", "sequence", "impossibility", "contact_payment"},
            f"{name}: unknown relationship type {relation.get('type')}",
        )
        _require(
            relation.get("between") and all(r in role_names for r in relation["between"]),
            f"{name}: relationship names unknown roles",
        )


def validate_configuration() -> None:
    _load_yaml.cache_clear()
    cfg = settings()
    _require(isinstance(cfg, dict) and set(cfg) >= SETTINGS_SECTIONS, "settings.yaml is missing sections")
    sources = set(source_types())
    for source in sources:
        spec = colmap(source)
        for key in ("source", "label", "family", "dependence"):
            _require(key in spec, f"Column map {source} has no '{key}'")
        _require(isinstance(spec.get("columns", {}), dict), f"Column map {source}: columns must be a mapping")
    indicators = config_file("indicators.yaml")
    names = set(indicators["weights"])
    classes = set()
    for template in templates():
        validate_template(template, names, sources)
        _require(template["class"] not in classes, f"Template class {template['class']} is defined twice")
        classes.add(template["class"])
