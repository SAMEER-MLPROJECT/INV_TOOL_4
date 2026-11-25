from __future__ import annotations

import math

from sakshya.model import Link, Term

LN10 = math.log(10.0)


def time_term(dt: float, mu: float, sigma2: float, window: float, source: str, what: str) -> Term:
    sigma2 = max(sigma2, 1.0)
    density = math.exp(-((dt - mu) ** 2) / (2 * sigma2)) / math.sqrt(2 * math.pi * sigma2)
    w = math.log10(max(density * window, 1e-12))
    detail = (
        f"{what}: {abs(dt):.0f} s apart (expected {mu:.0f} s, uncertainty {math.sqrt(sigma2):.0f} s) "
        f"against any time in a {window / 60:.0f} min window"
    )
    return Term("time", w, source, detail)


def place_term(distance: float, r_a: float, r_b: float, area_radius: float, source: str, what: str) -> Term:
    sigma2 = max((r_a**2 + r_b**2) / 4.0, 25.0)
    area = math.pi * area_radius**2
    w = math.log10(area / (2 * math.pi * sigma2)) - (distance**2) / (2 * sigma2 * LN10)
    detail = (
        f"{what}: {distance:.0f} m apart (location radii {r_a:.0f} m and {r_b:.0f} m) "
        f"against a random point within {area_radius / 1000:.0f} km"
    )
    return Term("place", w, source, detail)


def agreement_term(name: str, agree: bool, m: float, u: float, source: str, detail: str) -> Term:
    u = min(max(u, 1e-9), 0.999)
    m = min(max(m, 1e-6), 0.999999)
    w = math.log10(m / u) if agree else math.log10((1 - m) / (1 - u))
    return Term(name, w, source, detail)


def smoothed(count: float, total: float, categories: float = 2.0, alpha: float = 1.0) -> float:
    return (count + alpha) / (total + alpha * categories)


def finalize(
    link: Link,
    cap: float,
    accept: float,
    min_sources: int,
    scale: float,
    cross_source: bool = True,
    groups: dict[str, str] | None = None,
) -> Link:
    groups = groups or {}
    totals: dict[str, float] = {}
    for term in link.terms:
        if not term.group:
            term.group = groups.get(term.source, term.source)
        totals[term.group] = totals.get(term.group, 0.0) + term.w
    capped = sum(max(-cap, min(cap, value)) for value in totals.values())
    link.raw_w = sum(t.w for t in link.terms)
    link.scale = scale
    source_groups = sorted({groups.get(s, s) for s in link.sources})
    link.extra["source_groups"] = source_groups
    link.extra["group_totals"] = {k: round(v, 3) for k, v in sorted(totals.items())}
    link.w = capped
    if link.status == "observed":
        return link
    independent = len(source_groups) if link.type != "same_event" else len(set(link.sources))
    link.extra["independent_groups"] = independent
    if link.w >= accept and (independent >= min_sources or not cross_source):
        link.status = "inferred"
    elif link.w > 0:
        link.status = "candidate"
        if cross_source and independent < min_sources and link.w >= accept:
            link.note = (
                "Strong but rests on records that share one origin; independent corroboration is needed before it is relied on"
            )
    else:
        link.status = "candidate" if link.type == "impossibility" else "weak"
    if link.type == "impossibility":
        link.status = "inferred"
    return link
