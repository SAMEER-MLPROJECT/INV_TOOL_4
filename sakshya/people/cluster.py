from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import defaultdict

from sakshya.core.geo import haversine_m
from sakshya.core.identifiers import PERSON_TYPES, display, kind_of, name_similarity
from sakshya.model import Link, Person
from sakshya.normalise.facts import EntityInfo

KIND_ORDER = ["phone", "account", "upi", "email", "cloud", "imsi", "imei", "mac", "host"]


class UnionFind:
    def __init__(self, items: list[str]) -> None:
        self.parent = {i: i for i in items}
        self.members = {i: {i} for i in items}

    def find(self, item: str) -> str:
        root = item
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[item] != root:
            self.parent[item], item = root, self.parent[item]
        return root

    def union(self, a: str, b: str) -> str:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return ra
        if len(self.members[ra]) < len(self.members[rb]):
            ra, rb = rb, ra
        self.parent[rb] = ra
        self.members[ra] |= self.members.pop(rb)
        return ra


Fix = tuple[float, float, float, float]
HUB_DEGREE = 3
NAME_CONFLICT = 0.6
SIMULTANEOUS_S = 600.0


def _names(entities: dict[str, EntityInfo], group: set[str]) -> list[str]:
    return sorted({n for e in group if e in entities for n in entities[e].names if n})


def _name_conflict(entities: dict[str, EntityInfo], a: set[str], b: set[str]) -> str | None:
    names_a, names_b = _names(entities, a), _names(entities, b)
    if not names_a or not names_b:
        return None
    best = max(name_similarity(x, y) for x in names_a for y in names_b)
    if best < NAME_CONFLICT:
        return f"registered names differ ({names_a[0]} and {names_b[0]})"
    return None


def _place_conflict(positions: dict[str, list[Fix]], a: set[str], b: set[str], speed: float) -> str | None:
    left = [(e, fixes) for e in sorted(a) if (fixes := positions.get(e))]
    right = [(e, fixes) for e in sorted(b) if (fixes := positions.get(e))]
    for ea, fa in left:
        times = [f[0] for f in fa]
        for eb, fb in right:
            for t, lat, lon, radius in fb:
                lo = bisect_left(times, t - SIMULTANEOUS_S)
                hi = bisect_right(times, t + SIMULTANEOUS_S)
                for t2, lat2, lon2, radius2 in fa[lo:hi]:
                    distance = haversine_m(lat, lon, lat2, lon2)
                    allowed = radius + radius2 + speed * abs(t - t2) + 5000.0
                    if distance > allowed:
                        return (
                            f"{display(ea)} and {display(eb)} were {distance / 1000:.0f} km apart within "
                            f"{abs(t - t2) / 60:.0f} min, too far for one person even by air"
                        )
    return None


def _hubs(links: list[Link]) -> set[str]:
    neighbours: dict[str, set[str]] = defaultdict(set)
    for link in links:
        if link.status == "inferred":
            neighbours[link.a].add(link.b)
            neighbours[link.b].add(link.a)
    hubs = set()
    for entity, others in neighbours.items():
        kinds = defaultdict(int)
        for other in others:
            kinds[kind_of(other)] += 1
        if any(count >= HUB_DEGREE for count in kinds.values()):
            hubs.add(entity)
    return hubs


def cluster(
    entities: dict[str, EntityInfo],
    links: list[Link],
    seeds: list[str],
    merge_w: float,
    forbidden: set[frozenset[str]],
    distance: dict[str, int] | None = None,
    positions: dict[str, list[Fix]] | None = None,
    speed_kmh: float = 900.0,
) -> tuple[list[Person], dict[str, str], list[dict]]:
    positions = positions or {}
    speed = speed_kmh / 3.6
    node_set = {e for e, info in entities.items() if info.kind in PERSON_TYPES and info.case_relevant}
    for link in links:
        if link.type == "same_actor" and link.status in {"observed", "inferred", "confirmed"}:
            for end in (link.a, link.b):
                if kind_of(end) in PERSON_TYPES:
                    node_set.add(end)
    nodes = sorted(node_set)
    uf = UnionFind(nodes)
    via: dict[str, str] = {}
    score: dict[str, float] = {}
    blocked: list[dict] = []
    seed_set = set(seeds)
    usable = [
        l
        for l in links
        if l.type == "same_actor"
        and l.a in uf.parent
        and l.b in uf.parent
        and (l.status in {"observed", "confirmed"} or (l.status == "inferred" and l.w >= merge_w))
    ]
    usable.sort(key=lambda l: (0 if l.status in {"observed", "confirmed"} else 1, -l.w, l.link_id))
    hubs = _hubs(usable)
    for link in usable:
        ra, rb = uf.find(link.a), uf.find(link.b)
        if ra == rb:
            continue
        group_a, group_b = uf.members[ra], uf.members[rb]
        clash = next((pair for pair in forbidden if (pair & group_a) and (pair & group_b)), None) if forbidden else None
        if clash is not None:
            blocked.append({"link_id": link.link_id, "reason": "Merge would join identifiers marked as different people"})
            continue
        if (
            (group_a & seed_set or group_b & seed_set)
            and link.status == "inferred"
            and link.extra.get("basis") == "shared_handset"
        ):
            blocked.append(
                {"link_id": link.link_id, "reason": "Shared handset does not attach new identifiers to the complainant"}
            )
            continue
        if link.status == "inferred":
            hub = next((end for end in (link.a, link.b) if end in hubs), None)
            if hub is not None:
                blocked.append(
                    {
                        "link_id": link.link_id,
                        "reason": f"{display(hub)} is shared with several other identifiers, so it cannot join people on its own",
                    }
                )
                continue
            conflict = _name_conflict(entities, group_a, group_b) or _place_conflict(positions, group_a, group_b, speed)
            if conflict is not None:
                blocked.append({"link_id": link.link_id, "reason": f"Kept apart: {conflict}"})
                continue
        uf.union(link.a, link.b)
        for end in (link.a, link.b):
            if end not in via:
                via[end] = link.link_id
                score[end] = link.w
    groups = defaultdict(list)
    for node in nodes:
        groups[uf.find(node)].append(node)
    persons: list[Person] = []
    for members in groups.values():
        members.sort(key=lambda e: (KIND_ORDER.index(kind_of(e)) if kind_of(e) in KIND_ORDER else 99, e))
        names: list[str] = []
        for member in members:
            for name in entities.get(member).names if member in entities else []:
                if name not in names:
                    names.append(name)
        is_seed = bool(set(members) & seed_set)
        label = display(members[0])
        persons.append(
            Person(
                person_id="",
                members={m: round(score.get(m, 4.0), 3) for m in members},
                via={m: via[m] for m in members if m in via},
                names=names,
                label=label,
                is_seed=is_seed,
            )
        )
    reach = distance or {}
    persons.sort(key=lambda p: (not p.is_seed, min((reach.get(m, 99) for m in p.members), default=99), -len(p.members), p.label))
    entity_person: dict[str, str] = {}
    for index, person in enumerate(persons, start=1):
        person.person_id = f"P{index:02d}"
        for member in person.members:
            entity_person[member] = person.person_id
    return persons, entity_person, blocked
