from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from sakshya.core.hashing import load_json
from sakshya.core.timeutil import fmt_ist
from sakshya.evaluation.metrics import clock_errors, money_scores, role_scores, tamper_scores, traceability
from sakshya.pipeline import Analysis, analyse, bundle

from .conftest import DEMO, DEMO_IDS

EXPECTED_OUTCOMES = {
    "CASE-2611-0147": "OFFENCE_SUPPORTED",
    "CASE-2611-0152": "OFFENCE_SUPPORTED",
    "CASE-2611-0158": "OFFENCE_SUPPORTED",
    "CASE-2611-0163": "NO_OFFENCE_INDICATED",
    "CASE-2611-0171": "UNKNOWN_PATTERN",
}


def _truth(analysis: Analysis) -> dict:
    return load_json(analysis.case_dir / "truth.json")


@pytest.mark.parametrize("case_id", DEMO_IDS)
def test_outcome_and_offence_type_match_the_answer_key(analyses: dict[str, Analysis], case_id: str) -> None:
    decision = analyses[case_id].explained["decision"]
    assert decision["outcome"] == EXPECTED_OUTCOMES[case_id]
    assert decision["label"] == _truth(analyses[case_id])["class"]


@pytest.mark.parametrize("case_id", DEMO_IDS)
def test_clock_offsets_are_recovered(analyses: dict[str, Analysis], case_id: str) -> None:
    for row in clock_errors(analyses[case_id], _truth(analyses[case_id])):
        assert row["error_s"] < 60, row
        if row["kind"] == "timezone":
            assert row["detected_timezone"], row


@pytest.mark.parametrize("case_id", DEMO_IDS)
def test_money_trail_and_roles(analyses: dict[str, Analysis], case_id: str) -> None:
    analysis = analyses[case_id]
    truth = _truth(analysis)
    money = money_scores(analysis, truth)
    if truth["money"].get("tainted_accounts"):
        assert money["precision"] == 1.0 and money["recall"] == 1.0
    if money["cash_error_share"] is not None:
        assert money["cash_error_share"] < 0.05
    roles = role_scores(analysis, truth)
    if "mule_l1_correct" in roles:
        assert roles["mule_l1_correct"]


@pytest.mark.parametrize("case_id", DEMO_IDS)
def test_every_finding_points_to_hashed_evidence(analyses: dict[str, Analysis], case_id: str) -> None:
    analysis = analyses[case_id]
    assert traceability(analysis, bundle(analysis))["share"] == 1.0
    assert tamper_scores(analysis, _truth(analysis))["false_alarms"] == 0


def test_tampered_frame_is_flagged(analyses: dict[str, Analysis]) -> None:
    caught = sum(tamper_scores(a, _truth(a))["caught"] for a in analyses.values())
    expected = sum(tamper_scores(a, _truth(a))["expected"] for a in analyses.values())
    assert expected > 0 and caught == expected


def test_decoys_with_common_names_are_never_merged(analyses: dict[str, Analysis]) -> None:
    for analysis in analyses.values():
        for pair in _truth(analysis).get("decoy_pairs", []):
            people = {analysis.view.entity_person.get(entity) for entity in pair}
            assert len(people) == 2 or None in people, pair


def test_same_input_gives_identical_output(demo_copy: Path, analyses: dict[str, Analysis]) -> None:
    case_id = DEMO_IDS[0]
    assert bundle(analyses[case_id])["digest"] == bundle(analyse(demo_copy / case_id))["digest"]


def test_bundle_is_complete(analyses: dict[str, Analysis]) -> None:
    data = bundle(analyses[DEMO_IDS[0]])
    for key in (
        "case",
        "decision",
        "hypotheses",
        "people",
        "links",
        "timeline",
        "graph",
        "map",
        "reach",
        "leads",
        "evidence",
        "coverage",
        "fragility",
        "inputs",
        "cache_key",
        "digest",
        "schema",
    ):
        assert key in data, key
    assert data["inputs"]["parsers"] and data["inputs"]["configuration"]
    hypothesis = data["hypotheses"][0]
    for key in ("supporting", "contradicting", "questions", "phases", "links_used", "gaps", "binding"):
        assert key in hypothesis, key


def test_observations_carry_full_provenance(analyses: dict[str, Analysis]) -> None:
    obs = analyses[DEMO_IDS[0]].obs
    for column in ("family", "dependence_group", "tz", "coord_basis", "sha256", "parser", "parser_version"):
        assert obs[column].notna().all(), column
    assert obs["sha256"].str.len().eq(64).all()


def test_output_does_not_depend_on_hash_seed(demo_copy: Path) -> None:
    script = (
        "import sys; from pathlib import Path; from sakshya.pipeline import analyse, bundle; "
        "print(bundle(analyse(Path(sys.argv[1])))['digest'])"
    )
    root = Path(__file__).resolve().parent.parent
    digests = set()
    for seed in ("1", "2"):
        env = {**os.environ, "PYTHONHASHSEED": seed, "PYTHONPATH": str(root)}
        result = subprocess.run(
            [sys.executable, "-c", script, str(demo_copy / DEMO_IDS[0])], env=env, capture_output=True, text=True, check=True
        )
        digests.add(result.stdout.strip())
    assert len(digests) == 1


def test_adding_future_evidence_does_not_change_a_past_forecast(tmp_path: Path) -> None:
    case_id = "CASE-2611-0147"
    case = tmp_path / case_id
    shutil.copytree(DEMO / case_id, case)
    truth = load_json(case / "truth.json")
    cutoff = float(truth["money"]["first_cash_time"]) - 20 * 60
    before = analyse(case, as_of=cutoff)
    statement = case / "evidence" / "bank" / "statement_169849.csv"
    statement.chmod(0o644)
    later = fmt_ist(cutoff + 3600).replace("-", " ").split(" ")
    stamp = f"{later[2]}-{later[1]}-{later[0]} {later[3]}"
    statement.write_text(
        statement.read_text(encoding="utf-8")
        + f"T999901,{stamp},IVBK0120429:5372509169849,DR,4000.00,1.00,ATM,,,,,ATM-NCBK-NOI-01,ATM WDL\n",
        encoding="utf-8",
    )
    full = analyse(case)
    assert any(full.obs["raw"].str.contains("T999901", regex=False))
    after = analyse(case, as_of=cutoff)
    assert len(after.obs) == len(before.obs)
    assert after.forecast()["prediction"] == before.forecast()["prediction"]
    assert after.explained["decision"] == before.explained["decision"]
    assert (after.obs["t"].dropna() <= cutoff).all()


def test_evidence_acquired_after_the_cutoff_is_excluded(tmp_path: Path) -> None:
    case_id = "CASE-2611-0147"
    case = tmp_path / case_id
    shutil.copytree(DEMO / case_id, case)
    truth = load_json(case / "truth.json")
    cutoff = float(truth["money"]["first_cash_time"]) + 3600
    manifest = (case / "case.yaml").read_text(encoding="utf-8")
    manifest = manifest.replace("source: atm_journal\n", f"source: atm_journal\n  acquired: '{fmt_ist(cutoff + 86400)}'\n", 1)
    (case / "case.yaml").write_text(manifest, encoding="utf-8")
    snapshot = analyse(case, as_of=cutoff)
    assert not (snapshot.obs["source"] == "atm_journal").any()
    assert (analyse(case).obs["source"] == "atm_journal").any()


def test_versioned_artifacts_are_written(tmp_path: Path, analyses: dict[str, Analysis]) -> None:
    from sakshya.storage.artifacts import write_artifacts

    analysis = analyses[DEMO_IDS[0]]
    tables = write_artifacts(tmp_path, analysis, bundle(analysis))
    names = {table["name"] for table in tables}
    assert {"observations", "links_inferred", "hypotheses", "financial_flows"} <= names
    for table in tables:
        assert len(table["sha256"]) == 64 and (tmp_path / table["file"]).exists()
    assert (tmp_path / "manifest.json").exists()
