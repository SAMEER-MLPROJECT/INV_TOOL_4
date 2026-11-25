import { api, waitForJob } from "./api.js";
import { clear, h } from "./dom.js";

const modal = document.getElementById("modal");
const title = document.getElementById("modal-title");
const body = document.getElementById("modal-body");

document.getElementById("modal-close").addEventListener("click", closeModal);
modal.addEventListener("click", (event) => {
  if (event.target === modal) closeModal();
});

export function closeModal() {
  modal.hidden = true;
}

export function openModal(heading, ...content) {
  title.textContent = heading;
  clear(body);
  body.append(...content.flat().filter(Boolean));
  modal.hidden = false;
}

const EXAMPLE = `id: CASE-2611-0201
title: Short description of the case
seed:
  kind: complaint
  identifiers:
    - {type: phone, value: "+919800000000"}
    - {type: account, value: "IVBK0123456:50100012345678"}
evidence:
  - {file: evidence/complaint.txt, source: complaint}
  - {file: evidence/statement.csv, source: bank_statement, account: "IVBK0123456:50100012345678", sha256: "<hash at receipt>"}
  - {file: evidence/capture.pcapng, source: pcap}
  - {file: evidence/cdr.csv, source: cdr, colmap: {columns: {time: "Call Start"}, time_format: "%d/%m/%Y %H:%M"}}`;

export function openUpload(onDone) {
  const input = h("input", { type: "file", accept: ".zip,application/zip", "aria-label": "Case archive" });
  const status = h("div", { class: "faint", role: "status" });
  const submit = h("button", { class: "btn", type: "button", text: "Upload and analyse" });
  submit.addEventListener("click", async () => {
    const file = input.files && input.files[0];
    if (!file) {
      status.textContent = "Choose a .zip file first.";
      return;
    }
    submit.disabled = true;
    status.textContent = "Uploading";
    try {
      const result = await api.upload(file);
      status.textContent = "Checking the archive and analysing";
      const job = await waitForJob(result.job, (j) => {
        status.textContent = j.note ? `Working: ${j.note}` : "Working";
      });
      closeModal();
      onDone(job.result.case_id);
    } catch (error) {
      status.textContent = error.message;
    } finally {
      submit.disabled = false;
    }
  });
  openModal(
    "Add a case",
    h("p", {
      text: "Upload a .zip archive holding case.yaml and the evidence files it lists. Every file is hashed and logged in the custody ledger before analysis. Nothing is added to the workspace unless the archive passes every check.",
    }),
    h("p", {
      class: "faint",
      text: "Give the acquisition hash of each file as sha256 so it can be verified. A colmap entry maps differently named columns, time formats or time zones without code changes.",
    }),
    h("div", { class: "raw", text: EXAMPLE }),
    h("div", { class: "row", style: { marginTop: "12px" } }, input, submit),
    status,
  );
}
