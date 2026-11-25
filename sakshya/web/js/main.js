import { api, loadBundle, onUnauthorized, setCsrf } from "./api.js";
import { hideAuth, requireLogin } from "./auth.js";
import { clear, h } from "./dom.js";
import { closeDrawer, toast } from "./drawer.js";
import { setState, state, subscribe } from "./state.js";
import { openUpload } from "./upload.js";
import { renderAdmin } from "./views/admin.js";
import { renderEvaluation } from "./views/evaluation.js";
import { destroyGraph, renderGraph } from "./views/graph.js";
import { renderEvidence, renderLeads, renderLinks, renderPeople } from "./views/lists.js";
import { destroyMap, renderMap } from "./views/map.js";
import { renderMoney } from "./views/money.js";
import { renderOverview } from "./views/overview.js";
import { renderPredict, stopReplay } from "./views/predict.js";
import { destroyTimeline, renderTimeline } from "./views/timeline.js";

const VIEWS = {
  overview: renderOverview,
  timeline: renderTimeline,
  graph: renderGraph,
  map: renderMap,
  money: renderMoney,
  predict: renderPredict,
  leads: renderLeads,
  people: renderPeople,
  links: renderLinks,
  evidence: renderEvidence,
  evaluation: renderEvaluation,
  admin: renderAdmin,
};
const CASE_FREE = new Set(["evaluation", "admin"]);

const viewEl = document.getElementById("view");
const select = document.getElementById("case-select");
const reportBtn = document.getElementById("report-btn");
const userEl = document.getElementById("user-menu");
const uploadBtn = document.getElementById("upload-btn");

function parseHash() {
  const parts = location.hash.replace(/^#\/?/, "").split("/").filter(Boolean).map(decodeURIComponent);
  return { caseId: parts[0] && parts[0] !== "-" ? parts[0] : null, view: VIEWS[parts[1]] ? parts[1] : "overview" };
}

function go(caseId, view) {
  const target = `#/${encodeURIComponent(caseId || "-")}/${view}`;
  if (location.hash !== target) location.hash = target;
  else route();
}

function teardown() {
  destroyGraph();
  destroyMap();
  destroyTimeline();
  stopReplay();
}

function render() {
  teardown();
  clear(viewEl);
  for (const link of document.querySelectorAll(".sidenav a")) {
    link.classList.toggle("active", link.dataset.view === state.view);
    link.setAttribute("href", `#/${encodeURIComponent(state.caseId || "-")}/${link.dataset.view}`);
  }
  if (!state.bundle && !CASE_FREE.has(state.view)) {
    viewEl.append(
      h("div", {
        class: "loading",
        text: state.waiting
          ? "Analysing the case; this view opens when the analysis is ready"
          : state.caseId
            ? "Loading case"
            : "No case is available to you yet",
      }),
    );
    return;
  }
  try {
    const result = VIEWS[state.view](viewEl);
    if (result && typeof result.catch === "function")
      result.catch((error) => viewEl.append(h("div", { class: "note-box", text: error.message })));
  } catch (error) {
    viewEl.append(h("div", { class: "note-box", text: `This view could not be drawn: ${error.message}` }));
  }
  viewEl.focus({ preventScroll: true });
}

async function loadCase(caseId) {
  setState({ caseId, bundle: null, asOf: null, waiting: false });
  render();
  try {
    const bundle = await loadBundle(caseId, () => {
      state.waiting = true;
      render();
    });
    if (state.caseId !== caseId) return;
    state.bundle = bundle;
    state.waiting = false;
    reportBtn.hidden = !state.user.permissions.includes("report");
    reportBtn.href = `/api/cases/${encodeURIComponent(caseId)}/report`;
    select.value = caseId;
    const option = Array.from(select.options).find((o) => o.value === caseId);
    if (option && bundle.decision) option.textContent = `${caseId}  |  ${bundle.case.title}  |  ${bundle.decision.title}`;
    render();
  } catch (error) {
    clear(viewEl);
    viewEl.append(h("div", { class: "note-box", text: `Could not load case ${caseId}: ${error.message}` }));
  }
}

export async function reloadCase() {
  if (state.caseId) await loadCase(state.caseId);
}

async function route() {
  const { caseId, view } = parseHash();
  closeDrawer();
  state.view = view;
  if (!caseId) {
    const first = select.options[0]?.value;
    if (first && !CASE_FREE.has(view)) {
      go(first, view);
      return;
    }
    render();
    return;
  }
  if (caseId !== state.caseId) await loadCase(caseId);
  else render();
}

async function refreshCases(selectId) {
  const cases = await api.cases();
  clear(select);
  for (const item of cases) {
    const outcome = item.decision_title || (item.state === "pending" ? "analysis pending" : item.error ? "could not load" : "");
    select.append(h("option", { value: item.id, text: `${item.id}  |  ${item.title}  |  ${outcome}` }));
  }
  if (selectId) select.value = selectId;
  return cases;
}

function renderUser(user) {
  clear(userEl);
  userEl.append(
    h("span", { class: "who", text: `${user.display_name} (${user.role})` }),
    h("button", {
      class: "btn ghost small",
      type: "button",
      text: "Sign out",
      onclick: async () => {
        try {
          await api.logout();
        } finally {
          location.hash = "";
          location.reload();
        }
      },
    }),
  );
  uploadBtn.hidden = !user.permissions.includes("upload");
  for (const link of document.querySelectorAll(".sidenav a[data-requires]"))
    link.hidden = !user.permissions.includes(link.dataset.requires);
}

subscribe((current, patch) => {
  if ("bundle" in patch && patch.bundle) render();
});

select.addEventListener("change", () => go(select.value, state.view));
uploadBtn.addEventListener("click", () =>
  openUpload(async (caseId) => {
    await refreshCases(caseId);
    toast(`Case ${caseId} added and analysed`);
    go(caseId, "overview");
  }),
);
window.addEventListener("hashchange", route);
onUnauthorized(() => location.reload());

(async () => {
  try {
    const auth = await api.authState();
    state.map = auth.map;
    let user = auth.user;
    if (user) setCsrf(auth.csrf);
    else user = await requireLogin(auth);
    hideAuth();
    state.user = user;
    renderUser(user);
    await refreshCases();
    route();
  } catch (error) {
    viewEl.append(h("div", { class: "note-box", text: `The server could not be reached: ${error.message}` }));
  }
})();
