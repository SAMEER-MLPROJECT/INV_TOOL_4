from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import pandas as pd

from sakshya import __version__
from sakshya.adapters import PARSER_VERSIONS
from sakshya.core.config import config_digest, settings
from sakshya.core.hashing import dump_json, load_json, sha256_json
from sakshya.core.timeutil import IST, parse_local
from sakshya.custody.intake import Evidence, check_media, digest_files, load_manifest, register_evidence
from sakshya.custody.ledger import Ledger
from sakshya.decide.leads import fragility, fragility_candidates, rank_leads, summarise_fragility
from sakshya.explain.engine import CaseView, explain
from sakshya.indicators.compute import attach_kyc_dates, compute
from sakshya.links.engine import build_context, cash_events, co_presence_links, same_actor_links, same_event_links
from sakshya.links.sequence import contact_payment_links, fit_beta, sequence_links
from sakshya.model import ClockEstimate, Link
from sakshya.money.flows import Statement, TaintResult, Transfer, build_transfers, suspicious_payments, trace
from sakshya.normalise.clock import apply_offsets, estimate_offsets
from sakshya.normalise.facts import Facts, build_facts, case_linked, seed_entities
from sakshya.normalise.ingest import ingest
from sakshya.people.cluster import cluster
from sakshya.predict.hmm import predict
from sakshya.reach.freeze import freeze_list
from sakshya.views import build_graph, build_map, build_people, build_timeline, summarise_links

ACTIONS_FILE = "actions.json"
BUNDLE_SCHEMA = 2


class AnalysisCancelled(Exception):
    pass


def analysis_inputs(
    manifest: dict[str, Any], digests: dict[str, str | None], actions: list[dict[str, Any]], as_of: float | None
) -> dict[str, Any]:
    sources = sorted({item["source"] for item in manifest["evidence"]})
    return {
        "schema": BUNDLE_SCHEMA,
        "engine": __version__,
        "evidence": dict(sorted(digests.items())),
        "parsers": {source: PARSER_VERSIONS[source] for source in sources},
        "configuration": config_digest(),
        "actions": sha256_json(actions),
        "as_of": as_of,
    }


@dataclass
class Analysis:
    case_dir: Path
    manifest: dict[str, Any]
    evidence: list[Evidence]
    obs: pd.DataFrame
    facts: Facts
    clocks: dict[str, ClockEstimate]
    links: list[Link]
    transfers: list[Transfer]
    books: dict[str, Statement]
    taint: TaintResult
    view: CaseView
    explained: dict[str, Any]
    seeds: list[str]
    reference_t: float | None
    media: list[dict[str, Any]]
    warnings: dict[str, list[str]]
    actions: list[dict[str, Any]]
    blocked_merges: list[dict[str, Any]]
    presence_scored: list[dict[str, Any]] = field(default_factory=list)
    timings: dict[str, float] = field(default_factory=dict)
    inputs: dict[str, Any] = field(default_factory=dict)
    as_of: float | None = None
    parse_status: dict[str, dict[str, Any]] = field(default_factory=dict)
    coverage: dict[str, Any] = field(default_factory=dict)
    fragility: dict[str, Any] = field(default_factory=dict)
    blocking: dict[str, dict[str, int]] = field(default_factory=dict)

    @property
    def cache_key(self) -> str:
        return sha256_json(self.inputs)

    @property
    def case_id(self) -> str:
        return str(self.manifest["id"])

    def crime_hypothesis(self) -> dict[str, Any] | None:
        label = self.explained["decision"]["label"]
        for hypothesis in self.explained["hypotheses"]:
            if hypothesis["template"] == label:
                return hypothesis
        return next((h for h in self.explained["hypotheses"] if h["template"] != "no_offence"), None)

    def default_as_of(self) -> float:
        if self.as_of is not None:
            return self.as_of
        if self.reference_t is not None:
            return self.reference_t
        times = self.obs["t"].dropna()
        return float(times.max()) if not times.empty else 0.0

    def time_range(self) -> tuple[float, float]:
        hypothesis = self.crime_hypothesis()
        stamps = [t for p in (hypothesis or {}).get("phases", []) for t in p.get("times", [])]
        if not stamps:
            series = self.obs["t"].dropna()
            stamps = [float(series.min()), float(series.max())] if not series.empty else [0.0, 0.0]
        return min(stamps), max(max(stamps), self.default_as_of())

    def money(self, as_of: float | None = None, policy: str | None = None) -> TaintResult:
        if as_of is None and (policy is None or policy == self.taint.policy):
            return self.taint
        return trace(
            self.transfers,
            self.books,
            [s for s in self.seeds if s.startswith("account:")],
            policy or settings()["money"]["default_policy"],
            as_of,
            settings()["money"]["new_payee_days"],
            self.reference_t,
        )

    def predict(self, as_of: float | None = None) -> dict[str, Any]:
        if self.explained["decision"].get("outcome") != "OFFENCE_SUPPORTED":
            return {"available": False, "reason": "No offence pattern was confirmed, so there is no trajectory to project"}
        moment = as_of if as_of is not None else self.default_as_of()
        return predict(self.crime_hypothesis(), moment)

    def forecast(self) -> dict[str, Any]:
        moment = self.default_as_of()
        times = self.obs["t"].dropna()
        return {
            "cutoff": self.as_of,
            "as_of": moment,
            "outcome": self.explained["decision"].get("outcome"),
            "decision": self.explained["decision"]["label"],
            "evidence_available": {
                "files": int(self.obs["evidence_id"].nunique()) if not self.obs.empty else 0,
                "records": len(self.obs),
                "latest_record": float(times.max()) if not times.empty else None,
            },
            "prediction": self.predict(moment),
        }

    def reach(self, as_of: float | None = None, policy: str | None = None) -> dict[str, Any]:
        moment = as_of if as_of is not None else self.default_as_of()
        taint = self.money(moment, policy)
        prediction = self.predict(moment)
        return {
            "as_of": moment,
            "policy": taint.policy,
            "trace": taint.to_dict(),
            "freeze": freeze_list(taint, prediction, self.crime_hypothesis(), self.books),
            "prediction": prediction,
        }


def load_actions(path: Path) -> list[dict[str, Any]]:
    return load_json(path) if path.exists() else []


def _apply_actions(links: list[Link], actions: list[dict[str, Any]]) -> set[frozenset[str]]:
    by_id = {link.link_id: link for link in links}
    forbidden: set[frozenset[str]] = set()
    revoked = {a.get("target") for a in actions if a.get("type") == "revoke"}
    for action in actions:
        if action.get("type") == "revoke" or action.get("id") in revoked:
            continue
        target = action.get("target")
        if action["type"] in {"reject_link", "confirm_link"} and target in by_id:
            link = by_id[target]
            if action["type"] == "reject_link":
                link.status = "rejected"
                if link.type == "same_actor":
                    forbidden.add(frozenset({link.a, link.b}))
            else:
                link.status = "confirmed"
            verdict = "Rejected" if action["type"] == "reject_link" else "Confirmed"
            link.note = f"{verdict} by investigator: {action.get('reason', '')}".strip()
        elif action["type"] == "forbid_merge" and isinstance(target, list) and len(target) == 2:
            forbidden.add(frozenset(target))
    return forbidden


def _snapshot(intake: Any, evidence: list[Evidence], as_of: float) -> tuple[pd.DataFrame, dict[str, ClockEstimate]]:
    late = {e.evidence_id for e in evidence if _acquired(e) is not None and _acquired(e) > as_of}
    raw = intake.obs[~intake.obs["evidence_id"].isin(late)]
    current = raw[raw["t_raw"].isna() | (raw["t_raw"] <= as_of)]
    clocks: dict[str, ClockEstimate] = {}
    for _ in range(2):
        clocks = estimate_offsets(current, evidence)
        corrected = apply_offsets(current, clocks)
        keep = corrected["t"].isna() | (corrected["t"] <= as_of)
        current = current[keep.to_numpy()]
    clocks = estimate_offsets(current, evidence)
    return apply_offsets(current, clocks), clocks


def _acquired(item: Evidence) -> float | None:
    value = item.entry.get("acquired")
    if value in (None, ""):
        return None
    try:
        return parse_local(str(value), None, IST)
    except ValueError:
        return None


def identity_positions(obs: pd.DataFrame) -> dict[str, list[tuple[float, float, float, float]]]:
    frame = obs[
        obs["source"].isin(["cdr", "tower_dump"])
        & obs["lat"].notna()
        & obs["t"].notna()
        & (obs["radius_m"].fillna(1e9) <= 3000)
        & (obs["sigma_t"] <= 300)
    ]
    positions: dict[str, list[tuple[float, float, float, float]]] = {}
    for attrs, t, lat, lon, radius in zip(frame["attrs"], frame["t"], frame["lat"], frame["lon"], frame["radius_m"]):
        subscriber = attrs.get("subscriber")
        if subscriber:
            positions.setdefault(f"phone:{subscriber}", []).append((float(t), float(lat), float(lon), float(radius)))
    for fixes in positions.values():
        fixes.sort()
    return positions


def coverage_of(evidence: list[Evidence], obs: pd.DataFrame, status: dict[str, dict[str, Any]]) -> dict[str, Any]:
    families: dict[str, int] = {}
    if not obs.empty:
        families = {str(k): int(v) for k, v in obs.groupby("family").size().items()}
    parsed = [e for e in evidence if status.get(e.evidence_id, {}).get("state") in {"parsed", "partial"}]
    failed = [e.evidence_id for e in evidence if status.get(e.evidence_id, {}).get("state") == "failed"]
    empty = [e.evidence_id for e in evidence if status.get(e.evidence_id, {}).get("state") == "empty"]
    substantive = {k: v for k, v in families.items() if k != "records"}
    return {
        "files": len(evidence),
        "parsed_files": len(parsed),
        "failed_files": failed,
        "empty_files": empty,
        "records": len(obs),
        "families": families,
        "substantive_records": int(sum(substantive.values())),
        "sources": sorted({e.source for e in parsed}),
    }


def analyse(
    case_dir: Path,
    *,
    ledger: Ledger | None = None,
    actions: list[dict[str, Any]] | None = None,
    as_of: float | None = None,
    digests: dict[str, str | None] | None = None,
    cancel: Any = None,
) -> Analysis:
    timings: dict[str, float] = {}
    clock = time.perf_counter()

    def mark(name: str) -> None:
        nonlocal clock
        if cancel is not None and cancel():
            raise AnalysisCancelled(name)
        now = time.perf_counter()
        timings[name] = round(now - clock, 4)
        clock = now

    cfg = settings()
    manifest = load_manifest(case_dir)
    digests = digests or digest_files(case_dir, manifest)
    actions = list(actions or [])
    evidence = register_evidence(case_dir, manifest, ledger, digests)
    intake = ingest(case_dir, evidence)
    if as_of is not None:
        obs, clocks = _snapshot(intake, evidence, as_of)
        intake.ids = intake.ids[intake.ids["obs_id"].isin(set(obs["obs_id"]))]
    else:
        clocks = estimate_offsets(intake.obs, evidence)
        obs = apply_offsets(intake.obs, clocks)
    mark("intake_and_normalise")
    frames = {}
    for row in obs[obs["kind"] == "cctv_event"].itertuples(index=False):
        if row.attrs.get("frame_file"):
            frames[row.attrs["frame_file"]] = (row.attrs.get("frame_sha256", ""), row.obs_id)
    media = check_media(evidence, frames)
    facts = build_facts(obs, intake.ids)
    attach_kyc_dates(facts, obs)
    seeds = seed_entities(manifest, facts)
    linked = case_linked(facts, seeds, cfg["links"]["case_link_depth"])
    ctx = build_context(obs, facts, seeds, linked)
    mark("facts")
    same_event = same_event_links(ctx)
    events = cash_events(ctx, same_event)
    copresence, impossible, presence_scored = co_presence_links(ctx, events)
    same_actor = same_actor_links(ctx)
    complaints = ctx.obs[ctx.obs["kind"] == "complaint"]["t"].dropna()
    reference_t = float(complaints.min()) if not complaints.empty else None
    money_reference = reference_t if reference_t is not None else as_of
    transfers, books = build_transfers(ctx.obs, facts)
    seed_accounts = [s for s in seeds if s.startswith("account:")]
    taint = trace(
        transfers, books, seed_accounts, cfg["money"]["default_policy"], None, cfg["money"]["new_payee_days"], money_reference
    )
    beta = fit_beta(transfers, books)
    sequence = sequence_links(transfers, books, ctx.obs, ctx.cfg, beta)
    origins = suspicious_payments(transfers, seed_accounts, cfg["money"]["new_payee_days"], money_reference)
    seed_out = [tr for tr in transfers if tr.src in seed_accounts]
    span = (max((tr.t for tr in seed_out), default=0) - min((tr.t for tr in seed_out), default=0)) / 86400.0
    background_per_day = len(seed_out) / max(span, 30.0)
    contact = contact_payment_links(origins, ctx.obs, facts.roles, seeds, ctx.cfg, background_per_day)
    links = same_event + copresence + impossible + same_actor + sequence + contact
    mark("links")
    forbidden = _apply_actions(links, actions)
    persons, entity_person, blocked = cluster(
        facts.entities,
        links,
        seeds,
        cfg["links"]["merge_w"],
        forbidden,
        linked,
        identity_positions(ctx.obs),
        float(cfg["links"].get("identity_speed_kmh", 900)),
    )
    indicators = compute(ctx.obs, facts, transfers, books, taint, links, seeds)
    subjects = {}
    for evidence_id, items in intake.subjects.items():
        subjects[evidence_id] = [f"{kind}:{value}" for kind, value in items]
    for item in evidence:
        if item.entry.get("account"):
            subjects.setdefault(item.evidence_id, []).append(f"account:{item.entry['account']}")
    view = CaseView(
        ctx.obs,
        facts,
        links,
        persons,
        entity_person,
        indicators,
        taint,
        seeds,
        subjects,
        {e.evidence_id: e.source for e in evidence},
    )
    mark("people_and_indicators")
    coverage = coverage_of(evidence, ctx.obs, intake.status)
    explained = explain(view, coverage)
    mark("explain")
    analysis = Analysis(
        case_dir,
        manifest,
        evidence,
        ctx.obs,
        facts,
        clocks,
        links,
        transfers,
        books,
        taint,
        view,
        explained,
        seeds,
        reference_t,
        media,
        intake.warnings,
        actions,
        blocked,
        presence_scored,
        timings,
        analysis_inputs(manifest, digests, actions, as_of),
        as_of,
        intake.status,
        coverage,
    )
    analysis.blocking = ctx.stats
    for link in links:
        ctx.count(link.type, "links_scored")
    if explained["decision"].get("outcome") == "OFFENCE_SUPPORTED":
        analysis.fragility = recompute_fragility(analysis, linked, cfg)
    mark("fragility")
    if ledger is not None:
        _record_run(analysis, ledger)
    return analysis


def _rescore(analysis: Analysis, removed: list[str], linked: dict[str, int], cfg: dict[str, Any]) -> dict[str, Any]:
    links = []
    forbidden = _apply_actions([], analysis.actions)
    for link in analysis.links:
        copy = replace(link, extra=dict(link.extra), terms=list(link.terms))
        if link.link_id in removed:
            copy.status = "rejected"
            if link.type == "same_actor":
                forbidden.add(frozenset({link.a, link.b}))
        links.append(copy)
    forbidden |= _apply_actions(links, analysis.actions)
    persons, entity_person, _ = cluster(
        analysis.facts.entities,
        links,
        analysis.seeds,
        cfg["links"]["merge_w"],
        forbidden,
        linked,
        identity_positions(analysis.obs),
        float(cfg["links"].get("identity_speed_kmh", 900)),
    )
    indicators = compute(analysis.obs, analysis.facts, analysis.transfers, analysis.books, analysis.taint, links, analysis.seeds)
    view = CaseView(
        analysis.obs,
        analysis.facts,
        links,
        persons,
        entity_person,
        indicators,
        analysis.taint,
        analysis.seeds,
        analysis.view.evidence_subjects,
        analysis.view.evidence_sources,
        analysis.view.spans,
    )
    return explain(view, analysis.coverage)


def recompute_fragility(analysis: Analysis, linked: dict[str, int], cfg: dict[str, Any]) -> dict[str, Any]:
    decision = analysis.explained["decision"]
    top = next((h for h in analysis.explained["hypotheses"] if h["template"] == decision["label"]), None)
    if top is None:
        return {"available": False}
    rivals = [h["score"] for h in analysis.explained["hypotheses"] if h["template"] != top["template"]]
    rival = max(rivals) if rivals else 0.0
    links_by_id = {link.link_id: link for link in analysis.links}
    persons = {p.person_id: p for p in analysis.view.persons}
    limit_pairs = int(cfg["decide"].get("fragility_pairs", 3))
    singles = fragility_candidates(top, links_by_id, persons, int(cfg["decide"].get("fragility_singles", 5)))
    trials = [[unit] for unit in singles]
    trials += [[a, b] for i, a in enumerate(singles[:limit_pairs]) for b in singles[i + 1 : limit_pairs]]
    experiments = []
    for units in trials:
        removed = sorted({link_id for unit in units for link_id in unit})
        result = _rescore(analysis, removed, linked, cfg)
        after = result["decision"]
        best = next((h for h in result["hypotheses"] if h["template"] == top["template"]), None)
        roles_after = best.get("binding", {}) if best else {}
        changed_roles = sorted(r for r, bound in top.get("binding", {}).items() if roles_after.get(r) != bound)
        experiments.append(
            {
                "units": len(units),
                "removed": removed,
                "details": [
                    {
                        "link_id": unit[0],
                        "links": len(unit),
                        "label": links_by_id[unit[0]].claim
                        + (f" (with {len(unit) - 1} more links from the same source group)" if len(unit) > 1 else ""),
                        "w": round(sum(links_by_id[k].w for k in unit), 3),
                        "type": links_by_id[unit[0]].type,
                    }
                    for unit in units
                ],
                "outcome_after": after.get("outcome"),
                "decision_after": after["label"],
                "score_after": round(best["score"], 3) if best else None,
                "margin_after": after.get("margin"),
                "changed_roles": changed_roles,
                "changes_conclusion": after["label"] != decision["label"] or after.get("outcome") != decision.get("outcome"),
            }
        )
    return summarise_fragility(top, rival, experiments)


def bundle(analysis: Analysis) -> dict[str, Any]:
    started = time.perf_counter()
    explained = analysis.explained
    hypotheses = explained["hypotheses"]
    crime = analysis.crime_hypothesis()
    default_as_of = analysis.default_as_of()
    reach = analysis.reach(default_as_of)
    leads_input = _lead_context(analysis, hypotheses)
    people = build_people(analysis)
    data = {
        "case": {
            "id": analysis.case_id,
            "title": analysis.manifest.get("title", analysis.case_id),
            "seed": analysis.manifest.get("seed", {}),
            "seed_entities": analysis.seeds,
            "complaint_time": analysis.reference_t,
            "time_range": analysis.time_range(),
            "default_as_of": default_as_of,
            "engine_version": __version__,
        },
        "decision": explained["decision"],
        "hypotheses": [_public_hypothesis(analysis, h) for h in hypotheses],
        "people": people,
        "fragility": analysis.fragility or fragility(hypotheses),
        "leads": rank_leads(leads_input),
        "reach": reach,
        "links": summarise_links(analysis),
        "timeline": build_timeline(analysis, crime),
        "graph": build_graph(analysis, crime),
        "map": build_map(analysis, crime),
        "evidence": evidence_view(analysis),
        "coverage": analysis.coverage,
        "as_of": analysis.as_of,
        "inputs": analysis.inputs,
        "actions": analysis.actions,
        "blocked_merges": analysis.blocked_merges,
        "counts": {
            "observations": len(analysis.obs),
            "evidence": len(analysis.evidence),
            "links": len(analysis.links),
            "persons": len(analysis.view.persons),
            "entities": len(analysis.facts.entities),
        },
    }
    data["schema"] = BUNDLE_SCHEMA
    data["cache_key"] = analysis.cache_key
    data["digest"] = analysis_digest(data)
    analysis.timings["views"] = round(time.perf_counter() - started, 4)
    data["timings"] = analysis.timings
    return data


def _public_hypothesis(analysis: Analysis, hypothesis: dict[str, Any]) -> dict[str, Any]:
    view = analysis.view
    roles = []
    for role in hypothesis.get("roles", []):
        units = []
        for unit in role["units"]:
            if unit.startswith("P") and unit[1:].isdigit():
                person = view.person(unit)
                units.append(
                    {
                        "id": unit,
                        "kind": "person",
                        "label": person.label,
                        "names": person.names,
                        "identifiers": list(person.members)[:12],
                    }
                )
            else:
                person_id = view.entity_person.get(unit)
                units.append(
                    {
                        "id": unit,
                        "kind": "account",
                        "label": unit.split(":", 1)[1].replace(":", " "),
                        "person": person_id,
                        "names": view.person(person_id).names if person_id else [],
                    }
                )
        roles.append({**role, "units": units})
    phases = [{k: v for k, v in phase.items() if k != "times"} for phase in hypothesis.get("phases", [])]
    return {**{k: v for k, v in hypothesis.items() if k not in {"roles", "phases"}}, "roles": roles, "phases": phases}


def _lead_context(analysis: Analysis, hypotheses: list[dict[str, Any]]) -> dict[str, Any]:
    sources = {e.source for e in analysis.evidence}
    statement_accounts = set(analysis.books)
    cdr_phones = {
        s for e in analysis.evidence if e.source == "cdr" for s in analysis.view.evidence_subjects.get(e.evidence_id, [])
    }
    person_phones = {p.person_id: [m for m in p.members if m.startswith("phone:")] for p in analysis.view.persons}
    cash_atms = sorted({f["atm"] for f in analysis.taint.flows if f["kind"] == "cash" and f.get("atm")})
    cctv_atms = {f"atm:{e.entry.get('atm_id')}" for e in analysis.evidence if e.source == "cctv_log"}
    dump_atms = set()
    for e in analysis.evidence:
        if e.source == "tower_dump":
            for atm in cash_atms:
                if atm.split(":", 1)[1] in e.file:
                    dump_atms.add(atm)
    infrastructure = set()
    for link in analysis.links:
        if link.type == "same_actor" and link.extra.get("basis") == "infrastructure" and link.status != "rejected":
            infrastructure.add(f"domain:{link.extra['domain']}")
    return {
        "sources": sources,
        "statement_accounts": statement_accounts,
        "cdr_phones": cdr_phones,
        "person_phones": person_phones,
        "cash_atms": cash_atms,
        "cctv_atms": cctv_atms,
        "dump_atms": dump_atms,
        "infrastructure": sorted(infrastructure),
        "hypotheses": hypotheses,
        "tainted_accounts": sorted(a for a, info in analysis.taint.accounts.items() if info.tainted_in > 0),
        "held": {a: info.tainted_held for a, info in analysis.taint.accounts.items()},
    }


def evidence_view(analysis: Analysis) -> dict[str, Any]:
    items = []
    counts = analysis.obs.groupby("evidence_id").size().to_dict() if not analysis.obs.empty else {}
    for item in analysis.evidence:
        clock = analysis.clocks.get(item.evidence_id)
        items.append(
            {
                **item.to_dict(),
                "records": int(counts.get(item.evidence_id, 0)),
                "clock": clock.to_dict() if clock else None,
                "warnings": analysis.warnings.get(item.evidence_id, []),
                "parse": analysis.parse_status.get(item.evidence_id, {}),
            }
        )
    return {"items": items, "media": analysis.media}


VOLATILE_EVIDENCE = {"custody", "verification"}


def analysis_digest(data: dict[str, Any]) -> str:
    content = {k: v for k, v in data.items() if k not in {"timings", "digest", "ledger", "freshness", "run"}}
    evidence = dict(data["evidence"])
    evidence["items"] = [
        {**{k: v for k, v in item.items() if k not in VOLATILE_EVIDENCE}, "verification": item["verification"]["status"]}
        for item in evidence["items"]
    ]
    content["evidence"] = {k: v for k, v in evidence.items() if k not in {"ledger", "ledger_entries"}}
    return sha256_json(content)


def ledger_view(ledger: Ledger) -> dict[str, Any]:
    return {"ledger": ledger.verify().to_dict(), "ledger_entries": ledger.entries()[-60:]}


def _record_run(analysis: Analysis, ledger: Ledger) -> None:
    digest = analysis.cache_key
    last = ledger.last("analysis")
    if last is None or last["payload"].get("inputs_sha256") != digest:
        ledger.append(
            "analysis",
            {
                "inputs_sha256": digest,
                "engine": __version__,
                "configuration_sha256": analysis.inputs["configuration"],
                "parsers": analysis.inputs["parsers"],
                "as_of": analysis.as_of,
                "outcome": analysis.explained["decision"].get("outcome"),
                "decision": analysis.explained["decision"]["label"],
                "score": analysis.explained["decision"]["score"],
            },
        )


def save_bundle(directory: Path, data: dict[str, Any]) -> Path:
    path = directory / "bundle.json"
    dump_json(path, data)
    return path
