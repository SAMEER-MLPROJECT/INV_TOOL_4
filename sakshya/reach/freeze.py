from __future__ import annotations

from typing import Any

from sakshya.core.identifiers import display
from sakshya.money.flows import Statement, TaintResult


def _balance_at(book: Statement | None, moment: float | None) -> float | None:
    if book is None:
        return None
    value = book.opening if book.opening_known else None
    for t, direction, amount, balance in book.rows:
        if moment is not None and t > moment:
            break
        if balance is not None:
            value = balance
        elif value is not None:
            value += amount if direction == "CR" else -amount
    return value


def freeze_list(
    taint: TaintResult,
    prediction: dict[str, Any],
    hypothesis: dict[str, Any] | None,
    books: dict[str, Statement] | None = None,
) -> list[dict[str, Any]]:
    books = books or {}
    cash_roles: set[str] = set()
    if hypothesis:
        binding = hypothesis.get("binding", {})
        for role in ("mule_l1", "mule_l2"):
            cash_roles |= set(binding.get(role, []))
    model_p = prediction.get("p_before_freeze") if prediction.get("next") == "cash_out" else None
    calibration = prediction.get("calibration_status", "not validated")
    rows = []
    for account in taint.accounts.values():
        if account.tainted_held <= 1:
            continue
        book = books.get(account.account)
        verified = _balance_at(book, taint.as_of)
        bound = min(account.tainted_held, max(verified, 0.0)) if verified is not None else account.tainted_held
        reasoning = [
            f"Rs {account.tainted_held:,.0f} of complainant money is attributed to this account under the "
            f"{taint.policy.replace('_', '-')} convention",
        ]
        if verified is not None:
            reasoning.append(f"Statement balance at that time was Rs {verified:,.0f}, so at most Rs {bound:,.0f} can be held")
        else:
            reasoning.append("No statement for this account, so the balance is not verified")
        if book is not None and not book.complete:
            reasoning.append("The statement has gaps or balance discrepancies; the figure is uncertain")
        if model_p is not None and account.account in cash_roles:
            p_move = round(float(model_p), 3)
            expected = round(bound * (1.0 - p_move), 2)
            basis = "model estimate"
            reasoning.append(
                f"Phase model gives a {p_move:.0%} chance that cash-out happens before a freeze lands "
                f"({calibration}); expected recoverable Rs {expected:,.0f}"
            )
            low, high = round(bound * (1.0 - min(1.0, p_move + 0.2)), 2), round(bound * (1.0 - max(0.0, p_move - 0.2)), 2)
            reasoning.append("The range shows the effect of the chance being 20 points higher or lower")
        else:
            p_move = None
            expected = None
            basis = "heuristic"
            reasoning.append("No validated estimate of how soon this money moves; priority is by amount and hop")
            low, high = 0.0, round(bound, 2)
        rows.append(
            {
                "account": account.account,
                "label": display(account.account),
                "hop": account.hop,
                "held": round(account.tainted_held, 2),
                "received": round(account.tainted_in, 2),
                "statement": account.statement,
                "verified_balance": None if verified is None else round(verified, 2),
                "recoverable_upper": round(bound, 2),
                "p_move": p_move,
                "expected_recoverable": expected,
                "range": [low, high],
                "priority_basis": basis,
                "completeness": "no statement" if book is None else ("complete" if book.complete else "incomplete"),
                "reasoning": reasoning,
                "action": (
                    "Request immediate debit freeze"
                    if account.statement
                    else "Request statement and debit freeze; no statement in the case yet"
                ),
            }
        )
    rows.sort(
        key=lambda r: (
            -(r["expected_recoverable"] if r["expected_recoverable"] is not None else r["recoverable_upper"] * 0.5),
            r["hop"],
            r["account"],
        )
    )
    for rank, row in enumerate(rows, start=1):
        row["rank"] = rank
    return rows


def linked_cases(case_id: str, entities: set[str], index: dict[str, set[str]]) -> list[dict[str, Any]]:
    shared: dict[str, set[str]] = {}
    for entity in entities:
        for other in index.get(entity, set()):
            if other != case_id:
                shared.setdefault(other, set()).add(entity)
    return [{"case_id": other, "shared": sorted(items)} for other, items in sorted(shared.items(), key=lambda kv: -len(kv[1]))]
