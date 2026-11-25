import { api } from "../api.js";
import { bar, h, pill, table } from "../dom.js";
import { pct, words } from "../format.js";

function verdict(ok) {
  return ok === null || ok === undefined ? pill("reported", "grey") : ok ? pill("met", "good") : pill("below target", "warn");
}

function num(value, digits = 3) {
  return value === null || value === undefined ? "n/a" : Number(value).toFixed(digits);
}

function card(title, ...children) {
  return h("div", { class: "card", style: { marginTop: "16px" } }, h("h2", { text: title }), ...children);
}

function rubricRows(data) {
  const r = data.heldout;
  const coverage = Object.values(r.extraction).map((s) => s.mean_coverage);
  const minCoverage = Math.min(...coverage);
  const models = (data.forecast && data.forecast.models) || {};
  const hsmm = models.hsmm || {};
  const baseline = models.baseline_median || {};
  const parsers = data.parsers;
  return [
    {
      line: "Evidence processing and extraction (15)",
      metric: `Records parsed, worst of ${coverage.length} generated source types`,
      value: pct(minCoverage, 1),
      target: "98% or more",
      ok: minCoverage >= 0.98,
    },
    parsers
      ? {
          line: "",
          metric: `Field-level precision / recall on ${parsers.fixtures.length} labelled fixtures`,
          value: `${num(parsers.min_precision)} / ${num(parsers.min_recall)} (worst format)`,
          target: "0.95 or more",
          ok: parsers.min_precision >= 0.95 && parsers.min_recall >= 0.95,
        }
      : null,
    {
      line: "Cross-source correlation (20)",
      metric: "Same-event links, precision / recall",
      value: `${num(r.same_event.precision)} / ${num(r.same_event.recall)}`,
      target: "0.95 or more",
      ok: r.same_event.precision >= 0.95 && r.same_event.recall >= 0.95,
    },
    {
      line: "",
      metric: "Presence links, precision",
      value: num(r.presence.link_precision),
      target: "0.95 or more",
      ok: r.presence.link_precision >= 0.95,
    },
    {
      line: "",
      metric: "Identity resolution, precision / recall / F1",
      value: `${num(r.resolution.precision)} / ${num(r.resolution.recall)} / ${num(r.resolution.f1)}`,
      target: "precision 0.95 or more",
      ok: r.resolution.precision >= 0.95,
    },
    {
      line: "",
      metric: "Decoys wrongly merged",
      value: `${r.resolution.decoy_merges} of ${r.resolution.decoy_pairs}`,
      target: "none",
      ok: r.resolution.decoy_merges === 0,
    },
    {
      line: "Timeline and reconstruction (20)",
      metric: "Clock offset error, median / worst",
      value: `${num(r.clock.median_error_s, 1)} s / ${num(r.clock.max_error_s, 1)} s`,
      target: "under 60 s",
      ok: r.clock.max_error_s < 60,
    },
    {
      line: "",
      metric: "Wrong time zones detected",
      value: `${r.clock.timezone_detected} of ${r.clock.timezone_cases}`,
      target: "all",
      ok: r.clock.timezone_detected === r.clock.timezone_cases,
    },
    {
      line: "",
      metric: "Event ordering (Kendall tau), before / after correction",
      value: `${num(r.timeline.kendall_tau_before)} / ${num(r.timeline.kendall_tau_after)}`,
      target: "0.95 or more after",
      ok: r.timeline.kendall_tau_after >= 0.95,
    },
    {
      line: "Accuracy, traceability, explainability (25)",
      metric: "Findings with a resolvable evidence pointer",
      value: `${pct(r.traceability.share, 1)} of ${r.traceability.pointers}`,
      target: "100%",
      ok: r.traceability.share === 1,
    },
    {
      line: "",
      metric: "Same input gives identical output",
      value: data.determinism.identical ? "yes" : "no",
      target: "yes",
      ok: data.determinism.identical,
    },
    {
      line: "",
      metric: "Tampered CCTV frames caught",
      value: `${r.tamper.caught} of ${r.tamper.expected}, ${r.tamper.false_alarms} false alarms`,
      target: "all, no false alarms",
      ok: r.tamper.caught === r.tamper.expected && r.tamper.false_alarms === 0,
    },
    {
      line: "Multimedia and fraud analysis (10)",
      metric: "Accounts reached by the money, precision / recall",
      value: `${num(r.money.precision)} / ${num(r.money.recall)}`,
      target: "0.95 or more",
      ok: r.money.precision >= 0.95 && r.money.recall >= 0.95,
    },
    {
      line: "",
      metric: "Cash withdrawn, relative error",
      value: pct(r.money.cash_error_share, 1),
      target: "under 5%",
      ok: r.money.cash_error_share < 0.05,
    },
    {
      line: "",
      metric: "First-layer mule identified",
      value: pct(r.roles.mule_l1_accuracy, 0),
      target: "95% or more",
      ok: r.roles.mule_l1_accuracy >= 0.95,
    },
    {
      line: "Performance and usability (10)",
      metric: "Analysis time per case, median / worst",
      value: `${num(r.analysis_time_s.median, 2)} s / ${num(r.analysis_time_s.max, 2)} s`,
      target: "reported",
      ok: null,
    },
    {
      line: "Beyond the rubric",
      metric: "Offence type, including unknown and no offence",
      value: pct(r.classification.accuracy, 0),
      target: "reported",
      ok: null,
    },
    { line: "", metric: "Cash-out person identified", value: pct(r.roles.cashout_accuracy, 0), target: "reported", ok: null },
    hsmm.brier_60 !== undefined
      ? {
          line: "",
          metric: "Cash-out within 60 min of a cut-off, Brier score: phase model / median baseline",
          value: `${num(hsmm.brier_60)} / ${num(baseline.brier_60)}`,
          target: "lower than baseline",
          ok: hsmm.brier_60 < baseline.brier_60,
        }
      : null,
  ].filter(Boolean);
}

function reliabilityCard(data) {
  const types = data.heldout.calibration_by_type || {};
  const fitted = (data.calibration_fit && data.calibration_fit.types) || {};
  return card(
    "Calibration of link weights by type",
    h("p", {
      class: "faint",
      text: "Share of held-out links that are true, by weight band, with 95% Wilson intervals. Links are accepted at W of 2.",
    }),
    Object.entries(types).map(([type, bands]) => {
      const fit = fitted[type] || {};
      return h(
        "div",
        { style: { marginTop: "12px" } },
        h("h3", { text: words(type) }),
        bands.map((band) =>
          h(
            "div",
            { class: "posterior-row wide" },
            h("span", { class: "label", text: `${band.band} (${band.links})` }),
            bar(band.true_share, 1, band.true_share > 0.5 ? "teal" : "red"),
            h("span", { class: "num", text: pct(band.true_share, 0) }),
            h("span", { class: "faint", text: `95% interval ${pct(band.ci95[0], 0)} to ${pct(band.ci95[1], 0)}` }),
          ),
        ),
        fit.status
          ? h("p", {
              class: "faint",
              text:
                fit.status === "fitted"
                  ? `Fitted on ${fit.links} training links: scale ${fit.scale}, Brier ${fit.brier} against ${fit.brier_unscaled} unscaled.${fit.scale >= 2 ? " The scale reached its upper bound, so the weights are, if anything, understated." : ""}`
                  : `Not calibrated: ${fit.status}.`,
            })
          : null,
      );
    }),
  );
}

function forecastCard(data) {
  const forecast = data.forecast;
  if (!forecast) return null;
  const names = {
    hsmm: "Semi-Markov phase model",
    hmm: "Hidden Markov model",
    baseline_median: "Median duration",
    base_rate: "Base rate",
  };
  const rows = Object.entries(forecast.models).map(([name, m]) => ({ name, ...m }));
  return card(
    "Forecast of cash-out, strict cut-offs",
    h("p", {
      class: "faint",
      text: `${forecast.cutoffs} cut-offs on ${forecast.cases} held-out cases. Training and held-out cases use different seeds, and at each cut-off the whole analysis is re-run on records time-stamped up to that moment, so no later record can leak into a forecast.`,
    }),
    table(
      [
        { label: "Model", render: (x) => h("strong", { text: names[x.name] || words(x.name) }) },
        { label: "Brier (60 min)", num: true, render: (x) => num(x.brier_60) },
        { label: "Median error, min", num: true, render: (x) => num(x.median_abs_error_min, 1) },
        {
          label: "80% interval coverage",
          num: true,
          render: (x) => (x.interval_coverage_80 === undefined ? "n/a" : pct(x.interval_coverage_80, 0)),
        },
        { label: "Phase correct", num: true, render: (x) => (x.phase_accuracy === undefined ? "n/a" : pct(x.phase_accuracy, 0)) },
      ],
      rows,
    ),
  );
}

function parserCard(data) {
  if (!data.parsers) return null;
  return card(
    "Parser validation",
    h("p", { class: "faint", text: data.parsers.note }),
    table(
      [
        { label: "Format", render: (x) => words(x.source) },
        { label: "Fixture", key: "file" },
        { label: "Records", num: true, key: "records" },
        { label: "Precision", num: true, render: (x) => num(x.precision) },
        { label: "Recall", num: true, render: (x) => num(x.recall) },
        { label: "Value checks", num: true, render: (x) => `${x.value_checks_passed} of ${x.value_checks}` },
      ],
      data.parsers.fixtures,
    ),
  );
}

export async function renderEvaluation(root) {
  root.append(
    h("h1", { text: "Evaluation" }),
    h("p", {
      class: "lead",
      text: "Measured on held-out generated cases with answer keys that the engine never reads. All figures describe synthetic data and are not a measure of accuracy on real case files.",
    }),
  );
  let data;
  try {
    data = await api.evaluation();
  } catch (error) {
    root.append(h("div", { class: "empty", text: `Evaluation results are not available: ${error.message}` }));
    return;
  }
  const r = data.heldout;
  const classes = Object.keys(r.classification.confusion);
  root.append(
    h(
      "div",
      { class: "row" },
      pill(`${r.cases} held-out cases`),
      pill(`engine ${data.engine}`, "grey"),
      pill(`generated ${data.generated}`, "grey"),
      data.synthetic ? pill("synthetic data", "warn") : null,
    ),
    card(
      "Against the SUTRAM rubric",
      table(
        [
          { label: "Rubric line (weight)", render: (x) => h("strong", { text: x.line }) },
          { label: "Metric", key: "metric" },
          { label: "Result", num: true, render: (x) => h("strong", { text: x.value }) },
          { label: "Target", key: "target" },
          { label: "", render: (x) => verdict(x.ok) },
        ],
        rubricRows(data),
      ),
    ),
    forecastCard(data),
    reliabilityCard(data),
    h(
      "div",
      null,
      card(
        "Offence type, confusion matrix",
        table(
          [
            { label: "Truth \\ found", render: (x) => words(x.truth) },
            ...classes.map((c) => ({ label: words(c), num: true, render: (x) => x[c] || 0 })),
          ],
          classes.map((truth) => ({ truth, ...r.classification.confusion[truth] })),
        ),
      ),
      card(
        "Scaling",
        table(
          [
            { label: "Size", render: (x) => `${x.scale}x` },
            { label: "Records", num: true, render: (x) => x.observations.toLocaleString("en-IN") },
            { label: "Identifiers", num: true, render: (x) => x.entities.toLocaleString("en-IN") },
            {
              label: "Presence pairs kept by blocking",
              num: true,
              render: (x) => {
                const block = (x.blocking && x.blocking.co_presence) || {};
                return block.all_pairs
                  ? `${block.spatial_candidates.toLocaleString("en-IN")} of ${block.all_pairs.toLocaleString("en-IN")}`
                  : "n/a";
              },
            },
            { label: "Seconds, traced", num: true, render: (x) => x.seconds.toFixed(1) },
            {
              label: "Peak MB",
              num: true,
              render: (x) => (x.peak_memory_mb === undefined ? "n/a" : x.peak_memory_mb.toFixed(0)),
            },
          ],
          data.scaling,
        ),
      ),
    ),
    parserCard(data),
    h("div", { class: "note-box", style: { marginTop: "16px" }, text: data.note }),
  );
}
