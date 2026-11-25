from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pandas as pd

from sakshya.core.hashing import atomic_write_bytes, sha256_file

if TYPE_CHECKING:
    from sakshya.pipeline import Analysis

ARTIFACT_SCHEMA = 1

PARQUET = importlib.util.find_spec("pyarrow") is not None


def _frame(rows: list[dict[str, Any]]) -> pd.DataFrame:
    frame = pd.DataFrame(rows)
    for column in frame.columns:
        if frame[column].map(lambda v: isinstance(v, (dict, list, tuple, set))).any():
            frame[column] = frame[column].map(lambda v: json.dumps(v, sort_keys=True, default=str))
    return frame


def _write(directory: Path, name: str, frame: pd.DataFrame) -> dict[str, Any]:
    directory.mkdir(parents=True, exist_ok=True)
    if PARQUET:
        path = directory / f"{name}.parquet"
        temp = directory / f".{name}.parquet.tmp"
        frame.to_parquet(temp, index=False)
        temp.replace(path)
    else:
        path = directory / f"{name}.jsonl"
        text = "\n".join(json.dumps(row, sort_keys=True, default=str) for row in frame.to_dict(orient="records"))
        atomic_write_bytes(path, text.encode("utf-8"))
    return {"name": name, "file": path.name, "rows": len(frame), "sha256": sha256_file(path)}


def write_artifacts(directory: Path, analysis: Analysis, data: dict[str, Any]) -> list[dict[str, Any]]:
    obs = analysis.obs.reset_index(drop=True).copy()
    tables = {
        "observations": _frame(obs.to_dict(orient="records")),
        "identifiers": _frame(
            [
                {"entity": entity, "kind": entity.split(":", 1)[0], "person": analysis.view.entity_person.get(entity)}
                for entity in sorted(analysis.facts.entities)
            ]
        ),
        "links_observed": _frame([l.to_dict() for l in analysis.links if l.status == "observed"]),
        "links_inferred": _frame([l.to_dict() for l in analysis.links if l.status != "observed"]),
        "indicators": _frame([i.to_dict() for i in analysis.view.indicators.all()]),
        "hypotheses": _frame(data["hypotheses"]),
        "financial_flows": _frame(analysis.taint.flows),
        "phase_predictions": _frame([data["reach"]["prediction"]]),
        "investigator_actions": _frame(analysis.actions),
    }
    manifest = [_write(directory, name, frame) for name, frame in tables.items()]
    atomic_write_bytes(
        directory / "manifest.json",
        json.dumps(
            {"schema": ARTIFACT_SCHEMA, "format": "parquet" if PARQUET else "jsonl", "tables": manifest}, indent=2
        ).encode(),
    )
    return manifest
