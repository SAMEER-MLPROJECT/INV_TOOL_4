from __future__ import annotations

import math
from pathlib import Path

import pytest

from sakshya.decide.leads import _eig, _entropy
from sakshya.evaluation.calibration import fit_type, wilson
from sakshya.evaluation.fixtures import build_bank
from sakshya.links.terms import finalize, smoothed
from sakshya.model import Link, Term
from sakshya.money.flows import Statement, Transfer, reconcile, trace
from sakshya.normalise.facts import EntityInfo
from sakshya.people.cluster import cluster
from sakshya.pipeline import Analysis, analyse
from sakshya.predict.hmm import baseline, hsmm_posterior, predict
from sakshya.reach.freeze import freeze_list

from .conftest import DEMO_IDS

DAY = 86400.0


def _link(link_id: str, a: str, b: str, w: float, terms: list[Term] | None = None, sources=None, kind="same_actor") -> Link:
    link = Link(link_id, kind, a, b, "entity", "entity", "test", terms=terms or [], sources=sources or [], status="inferred")
    link.w = w
    return link


def test_smoothed_rates_are_never_zero_or_one() -> None:
    assert smoothed(0, 0) == pytest.approx(0.5)
    assert 0 < smoothed(0, 50) < 0.05
    assert 0.95 < smoothed(50, 50) < 1


def test_sources_sharing_an_origin_count_once() -> None:
    groups = {"sms": "bank_core:IVBK", "bank_statement": "bank_core:IVBK"}
    shared = finalize(
        _link(
            "L1", "a", "b", 0, [Term("amount", 3.0, "sms", ""), Term("ref", 3.0, "bank_statement", "")], ["sms", "bank_statement"]
        ),
        4.0,
        2.0,
        2,
        1.0,
        groups=groups,
    )
    assert shared.w == pytest.approx(4.0)
    assert shared.extra["independent_groups"] == 1
    assert shared.status == "candidate"
    independent = finalize(
        _link("L2", "a", "b", 0, [Term("amount", 3.0, "sms", ""), Term("ref", 3.0, "cdr", "")], ["sms", "cdr"]),
        4.0,
        2.0,
        2,
        1.0,
        groups={"sms": "bank_core:IVBK", "cdr": "operator"},
    )
    assert independent.w == pytest.approx(6.0)
    assert independent.status == "inferred"


def _entities(names: dict[str, str]) -> dict[str, EntityInfo]:
    return {
        entity: EntityInfo(
            entity, entity.split(":")[0], entity.split(":", 1)[1], entity, names=[name] if name else [], case_relevant=True
        )
        for entity, name in names.items()
    }


def test_merges_with_conflicting_names_are_blocked() -> None:
    entities = _entities({"phone:+919800000001": "Ravi Kumar", "phone:+919800000002": "Sunita Devi"})
    _, mapping, blocked = cluster(entities, [_link("S1", *entities, 3.0)], [], 2.0, set())
    assert mapping["phone:+919800000001"] != mapping["phone:+919800000002"]
    assert "names differ" in blocked[0]["reason"]


def test_merges_of_people_in_two_places_at_once_are_blocked() -> None:
    a, b = "phone:+919800000001", "phone:+919800000002"
    entities = _entities({a: "", b: ""})
    positions = {a: [(1000.0, 28.61, 77.20, 500.0)], b: [(1200.0, 19.07, 72.87, 500.0)]}
    _, mapping, blocked = cluster(entities, [_link("S1", a, b, 3.0)], [], 2.0, set(), positions=positions)
    assert mapping[a] != mapping[b]
    assert "km apart" in blocked[0]["reason"]


def test_hub_identifiers_cannot_join_people() -> None:
    hub = "imei:356938035643809"
    phones = [f"phone:+91980000000{i}" for i in range(1, 5)]
    entities = _entities({hub: "", **dict.fromkeys(phones, "")})
    entities[hub].kind = "imei"
    links = [_link(f"S{i}", hub, phone, 3.0) for i, phone in enumerate(phones)]
    _, mapping, blocked = cluster(entities, links, [], 2.0, set())
    assert len({mapping[p] for p in phones}) == len(phones)
    assert blocked and "shared with several" in blocked[0]["reason"]


def test_forbidden_pairs_stay_apart_even_when_strong() -> None:
    a, b = "phone:+919800000001", "phone:+919800000002"
    entities = _entities({a: "Ravi", b: "Ravi"})
    _, mapping, _ = cluster(entities, [_link("S1", a, b, 9.0)], [], 2.0, {frozenset({a, b})})
    assert mapping[a] != mapping[b]


def test_reconciliation_reports_discrepancies_gaps_and_totals() -> None:
    rows = [
        (0.0, "CR", 100.0, 100.0, "E01", "E01:2"),
        (DAY, "DR", 40.0, 60.0, "E01", "E01:3"),
        (40 * DAY, "DR", 10.0, 20.0, "E01", "E01:4"),
    ]
    book = reconcile("account:X:1", rows)
    assert book.opening == pytest.approx(0.0)
    assert book.discrepancies[0]["difference"] == pytest.approx(-30.0)
    assert book.gaps and not book.complete
    assert book.totals["credits"] == 100.0 and book.totals["debits"] == 50.0
    clean = reconcile("account:X:1", rows[:2])
    assert clean.complete and clean.totals["unexplained"] == pytest.approx(0.0)


def test_reversals_failures_and_fees_are_handled(tmp_path: Path) -> None:
    case = tmp_path / "CASE-REV-0001"
    (case / "evidence").mkdir(parents=True)
    build_bank(case / "evidence" / "statement.csv")
    (case / "case.yaml").write_text(
        "id: CASE-REV-0001\ntitle: Reversal check\nseed:\n  kind: complaint\n  identifiers:\n"
        "  - type: account\n    value: IVBK0120429:5372509169849\n"
        "evidence:\n- file: evidence/statement.csv\n  source: bank_statement\n  account: IVBK0120429:5372509169849\n",
        encoding="utf-8",
    )
    analysis = analyse(case)
    kinds = {t.kind for t in analysis.transfers}
    assert "reversed" in kinds and "fee" in kinds
    assert not any(t.amount == 24000.0 and t.kind == "transfer" and t.dst == "upi:mule3@okaxis" for t in analysis.transfers)
    assert analysis.taint.victim_out == pytest.approx(0.0)
    assert analysis.parse_status["E01"]["quarantined"] == 1


def _books() -> dict[str, Statement]:
    return {
        "account:V:1": Statement("account:V:1", "E01", [(4 * DAY, "CR", 0.0, 500000.0)], 500000.0, 0.0, 10 * DAY),
        "account:M:2": Statement("account:M:2", "E02", [(4 * DAY, "CR", 0.0, 10000.0)], 10000.0, 0.0, 10 * DAY),
    }


def test_freeze_list_has_no_arbitrary_default_and_explains_itself() -> None:
    transfers = [Transfer("t1", 5 * DAY, "account:V:1", "account:M:2", 100000.0, "UPI", "transfer")]
    taint = trace(transfers, _books(), ["account:V:1"], reference_t=6 * DAY)
    rows = freeze_list(taint, {"available": False}, None, _books())
    assert len(rows) == 1
    row = rows[0]
    assert row["p_move"] is None and row["expected_recoverable"] is None
    assert row["priority_basis"] == "heuristic"
    assert row["recoverable_upper"] <= row["held"] + 0.01
    assert any("convention" in line for line in row["reasoning"])
    modelled = freeze_list(
        taint,
        {"next": "cash_out", "p_before_freeze": 0.3, "calibration_status": "validated"},
        {"binding": {"mule_l1": ["account:M:2"]}},
        _books(),
    )[0]
    assert modelled["priority_basis"] == "model estimate"
    assert modelled["expected_recoverable"] == pytest.approx(modelled["recoverable_upper"] * 0.7, rel=1e-3)


def test_hsmm_moves_belief_forward_as_time_passes() -> None:
    durations = [None, {"median_min": 30.0, "sigma": 0.5}, {"median_min": 30.0, "sigma": 0.5}, None]
    detect = [0.0, 1.0, 0.5, 1.0]
    events = [(0.0, 1)]
    early = hsmm_posterior(events, 4, 60.0, durations, detect)
    late = hsmm_posterior(events, 4, 3 * 3600.0, durations, detect)
    assert early[1] > 0.9
    assert late[2] > early[2]
    assert math.isclose(sum(late), 1.0)


def test_predictions_need_a_supported_offence(analyses: dict[str, Analysis]) -> None:
    supported = analyses["CASE-2611-0147"]
    result = supported.predict()
    assert result.get("available") is not False
    for case_id in ("CASE-2611-0163", "CASE-2611-0171"):
        assert analyses[case_id].predict()["available"] is False
    hypothesis = supported.crime_hypothesis()
    moment = min(t for p in hypothesis["phases"] for t in p.get("times", []))
    for model in ("hmm", "hsmm"):
        assert predict(hypothesis, moment + 60, model)["model"] == model
    assert baseline(hypothesis, moment + 60) is None or "predicted_t" in baseline(hypothesis, moment + 60)


def test_expected_information_gain_behaves() -> None:
    prior = [0.5, 0.5]
    assert _eig(prior, [0.5, 0.5], 0.0) == pytest.approx(0.0, abs=1e-9)
    perfect = _eig(prior, [1.0, 0.0], 0.0)
    assert perfect == pytest.approx(_entropy(prior))
    assert _eig(prior, [1.0, 0.0], 0.5) == pytest.approx(perfect * 0.5)
    assert 0 < _eig(prior, [0.9, 0.2], 0.1) < perfect


def test_fragility_is_recomputed_not_estimated(analyses: dict[str, Analysis]) -> None:
    fragility = analyses[DEMO_IDS[0]].fragility
    assert fragility["available"] and fragility["method"] == "recomputed"
    assert fragility["experiments"]
    for experiment in fragility["experiments"]:
        assert "score_after" in experiment and "changes_conclusion" in experiment


def test_calibration_reports_brier_and_intervals() -> None:
    rows = [(w / 10.0, w > 20, None) for w in range(0, 40)] * 2
    report = fit_type("co_presence", rows, "synthetic")
    assert report["status"] == "fitted"
    assert report["brier"] <= report["brier_unscaled"] + 1e-9
    assert fit_type("co_presence", rows[:10], "synthetic")["scale"] is None
    low, high = wilson(8, 10)
    assert low < 0.8 < high


def test_scaling_keeps_blocking_bounded(analyses: dict[str, Analysis]) -> None:
    for analysis in analyses.values():
        for link_type, stats in analysis.blocking.items():
            if "candidate_pairs" in stats and "blocks" in stats:
                assert stats["candidate_pairs"] >= 0, link_type
