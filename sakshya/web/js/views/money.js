import { api } from "../api.js";
import { bar, clear, h, pill, table } from "../dom.js";
import { showAccount, showObservation, toast } from "../drawer.js";
import { inr, ist, pct, short } from "../format.js";
import { setState, state } from "../state.js";

export function timeSlider(onChange) {
  const [start, end] = state.bundle.case.time_range;
  const value = state.asOf ?? state.bundle.case.default_as_of;
  const input = h("input", {
    type: "range",
    min: String(Math.floor(start - 3600)),
    max: String(Math.ceil(end)),
    step: "60",
    value: String(value),
    "aria-label": "Analysis time",
  });
  const label = h("span", { class: "big-time", text: `${ist(value)} IST` });
  let timer = null;
  input.addEventListener("input", () => {
    label.textContent = `${ist(Number(input.value))} IST`;
    clearTimeout(timer);
    timer = setTimeout(() => onChange(Number(input.value)), 160);
  });
  return { element: h("div", { class: "slider-row" }, h("span", { class: "faint", text: "As of" }), input, label), input, label };
}

export async function loadReach(asOf) {
  setState({ asOf });
  return api.reach(state.caseId, asOf, state.policy);
}

function hopColumns(trace) {
  const hops = new Map();
  for (const account of trace.accounts) {
    if (!hops.has(account.hop)) hops.set(account.hop, []);
    hops.get(account.hop).push(account);
  }
  const max = Math.max(1, ...trace.accounts.map((a) => a.tainted_in));
  return h(
    "div",
    { class: "hop-cols" },
    [...hops.entries()]
      .sort((a, b) => a[0] - b[0])
      .map(([hop, accounts]) =>
        h(
          "div",
          null,
          h("h3", { text: hop === 1 ? "Paid by the complainant" : `Hop ${hop}` }),
          accounts.map((a) =>
            h(
              "div",
              { class: "acct", onclick: () => showAccount(a.account) },
              h("div", { class: "t", text: short(a.account) }),
              bar(a.tainted_in, max, "teal"),
              h(
                "div",
                { class: "lines" },
                "Received",
                h("b", { text: inr(a.tainted_in) }),
                "Sent on",
                h("b", { text: inr(a.tainted_out) }),
                "Cash",
                h("b", { text: inr(a.tainted_cash) }),
                "Still held",
                h("b", { text: inr(a.tainted_held) }),
              ),
              a.statement ? null : h("div", { class: "faint", text: "No statement in the case yet" }),
            ),
          ),
        ),
      ),
  );
}

function freezeTable(rows) {
  if (!rows.length) return h("div", { class: "empty", text: "No traced money is held anywhere at this time." });
  return table(
    [
      { label: "#", num: true, key: "rank" },
      { label: "Account", render: (r) => h("span", { class: "mono", text: r.label }) },
      { label: "Attributed", num: true, render: (r) => inr(r.held) },
      {
        label: "Balance check",
        render: (r) =>
          r.verified_balance === null
            ? pill("not verified", "warn")
            : h(
                "span",
                null,
                inr(r.verified_balance),
                " ",
                pill(r.completeness, r.completeness === "complete" ? "good" : "warn"),
              ),
      },
      {
        label: "Chance it moves first",
        num: true,
        render: (r) => (r.p_move === null ? h("span", { class: "faint", text: "not estimated" }) : pct(r.p_move)),
      },
      {
        label: "Recoverable",
        num: true,
        render: (r) =>
          h(
            "div",
            null,
            h("strong", {
              text: r.expected_recoverable === null ? `up to ${inr(r.recoverable_upper)}` : inr(r.expected_recoverable),
            }),
            h("div", { class: "faint", text: `range ${inr(r.range[0])} to ${inr(r.range[1])}` }),
          ),
      },
      { label: "Basis", render: (r) => pill(r.priority_basis, r.priority_basis === "heuristic" ? "grey" : "teal") },
      {
        label: "Action",
        render: (r) => h("div", null, r.action, h("div", { class: "faint", text: r.reasoning.slice(1).join(". ") })),
      },
    ],
    rows,
    (row) => showAccount(row.account),
  );
}

function reconciliationTable(items) {
  const problems = items.filter((r) => !r.complete);
  return h(
    "div",
    { class: "card", style: { marginTop: "16px" } },
    h("h2", { text: "Statement reconciliation" }),
    h("p", {
      class: "faint",
      text: "Opening balance plus credits minus debits is checked against every reported running balance. Discrepancies are reported, never forced to match.",
    }),
    table(
      [
        {
          label: "Account",
          render: (r) => h("span", { class: "mono", text: r.account.replace(/^account:/, "").replace(":", " ") }),
        },
        { label: "Credits", num: true, render: (r) => inr(r.totals.credits) },
        { label: "Debits", num: true, render: (r) => inr(r.totals.debits) },
        { label: "Closing", num: true, render: (r) => inr(r.totals.closing) },
        {
          label: "Unexplained",
          num: true,
          render: (r) => (r.totals.unexplained === null ? "opening unknown" : inr(r.totals.unexplained)),
        },
        {
          label: "State",
          render: (r) =>
            r.complete
              ? pill("reconciles", "good")
              : pill(`${r.discrepancies.length} discrepancies, ${r.gaps.length} gaps`, "bad"),
        },
      ],
      items,
    ),
    problems.length
      ? h("p", {
          class: "note-box",
          text: "Accounts with discrepancies may have missing statement periods; traced amounts on them are uncertain.",
        })
      : null,
  );
}

export function renderMoney(root) {
  const body = h("div", { class: "stack" });
  const policy = h(
    "div",
    { class: "segmented" },
    h("button", { type: "button", class: state.policy === "pro_rata" ? "on" : "", text: "Pro-rata" }),
    h("button", { type: "button", class: state.policy === "fifo" ? "on" : "", text: "First in, first out" }),
  );
  const draw = (reach) => {
    clear(body);
    const trace = reach.trace;
    const totalHeld = reach.freeze.reduce((s, r) => s + r.held, 0);
    const cash = trace.accounts.reduce((s, a) => s + a.tainted_cash, 0);
    body.append(
      h(
        "div",
        { class: "kpis" },
        h(
          "div",
          { class: "kpi" },
          h("div", { class: "v", text: inr(trace.victim_out) }),
          h("div", { class: "l", text: "Left the complainant" }),
        ),
        h(
          "div",
          { class: "kpi" },
          h("div", { class: "v", text: String(trace.accounts.length) }),
          h("div", { class: "l", text: "Accounts reached" }),
        ),
        h(
          "div",
          { class: "kpi" },
          h("div", { class: "v", text: inr(cash) }),
          h("div", { class: "l", text: "Withdrawn in cash" }),
        ),
        h("div", { class: "kpi" }, h("div", { class: "v", text: inr(totalHeld) }), h("div", { class: "l", text: "Still held" })),
        trace.returned_to_complainant
          ? h(
              "div",
              { class: "kpi" },
              h("div", { class: "v", text: inr(trace.returned_to_complainant) }),
              h("div", { class: "l", text: "Returned to complainant" }),
            )
          : null,
      ),
      trace.accounts.length
        ? hopColumns(trace)
        : h("div", { class: "empty", text: "No payments from the complainant to new payees were found up to this time." }),
      h("h2", { text: "Freeze priority" }),
      h("p", {
        class: "faint",
        text: "Expected recoverable is shown only where a phase model gives a chance of the money moving first; otherwise the upper bound is shown and the ranking is a labelled heuristic by amount and hop.",
      }),
      h("div", { class: "note-box", text: trace.convention }),
      freezeTable(reach.freeze),
      reconciliationTable(trace.reconciliation || []),
      trace.flows.length ? h("h2", { style: { marginTop: "18px" }, text: "Traced transfers" }) : null,
      trace.flows.length
        ? table(
            [
              { label: "Time (IST)", render: (r) => ist(r.t) },
              { label: "From", render: (r) => h("span", { class: "mono", text: short(r.src) }) },
              {
                label: "To",
                render: (r) => h("span", { class: "mono", text: r.kind === "cash" ? `Cash at ${short(r.atm)}` : short(r.dst) }),
              },
              { label: "Amount", num: true, render: (r) => inr(r.amount) },
              { label: "Complainant's money", num: true, render: (r) => inr(r.tainted) },
              { label: "", render: (r) => (r.origin ? pill("payment", "warn") : null) },
            ],
            trace.flows,
            (row) => showObservation(row.obs_ids[0]),
          )
        : null,
    );
  };
  const refresh = async (asOf) => {
    try {
      draw(await loadReach(asOf));
    } catch (error) {
      toast(error.message);
    }
  };
  const slider = timeSlider(refresh);
  const [proRata, fifo] = policy.querySelectorAll("button");
  proRata.addEventListener("click", () => {
    setState({ policy: "pro_rata" });
    proRata.classList.add("on");
    fifo.classList.remove("on");
    refresh(Number(slider.input.value));
  });
  fifo.addEventListener("click", () => {
    setState({ policy: "fifo" });
    fifo.classList.add("on");
    proRata.classList.remove("on");
    refresh(Number(slider.input.value));
  });
  root.append(
    h("h1", { text: "Money and freeze" }),
    h("p", {
      class: "lead",
      text: "Where the complainant's money went, hop by hop, and which accounts to freeze first. Move the time to see the trail as it stood at any moment.",
    }),
    h(
      "div",
      { class: "card" },
      h("div", { class: "toolbar" }, h("span", { class: "faint", text: "Attribution rule" }), policy),
      slider.element,
    ),
    body,
  );
  if (state.asOf === null && state.policy === "pro_rata") draw(state.bundle.reach);
  else refresh(Number(slider.input.value));
}
