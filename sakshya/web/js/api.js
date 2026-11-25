const session = { csrf: null, onUnauthorized: null };

export class ApiError extends Error {
  constructor(message, status, body) {
    super(message);
    this.status = status;
    this.body = body || {};
  }
}

export function setCsrf(token) {
  session.csrf = token;
}

export function onUnauthorized(handler) {
  session.onUnauthorized = handler;
}

async function request(path, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = { Accept: "application/json", ...(options.headers || {}) };
  if (method !== "GET" && session.csrf) headers["X-CSRF-Token"] = session.csrf;
  const response = await fetch(path, { ...options, method, headers, credentials: "same-origin" });
  let body = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  if (!response.ok) {
    const detail = body && body.detail ? (typeof body.detail === "string" ? body.detail : "Request failed") : response.statusText;
    if (response.status === 401 && session.onUnauthorized && !path.startsWith("/api/auth/")) session.onUnauthorized();
    throw new ApiError(detail || `Request failed (${response.status})`, response.status, body);
  }
  return body;
}

function json(method, body) {
  return { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
}

const enc = encodeURIComponent;

export const api = {
  authState: () => request("/api/auth/state"),
  login: (username, password) => request("/api/auth/login", json("POST", { username, password })),
  demo: () => request("/api/auth/demo", json("POST", {})),
  logout: () => request("/api/auth/logout", { method: "POST" }),
  bootstrap: (body) => request("/api/auth/bootstrap", json("POST", body)),
  changePassword: (current, next) => request("/api/auth/password", json("POST", { current, new: next })),
  cases: () => request("/api/cases"),
  bundle: (caseId) => request(`/api/cases/${enc(caseId)}`),
  reach: (caseId, asOf, policy) => {
    const params = new URLSearchParams();
    if (asOf !== null && asOf !== undefined) params.set("as_of", String(asOf));
    if (policy) params.set("policy", policy);
    return request(`/api/cases/${enc(caseId)}/reach?${params}`);
  },
  forecast: (caseId, cutoff) => request(`/api/cases/${enc(caseId)}/forecast?cutoff=${enc(String(cutoff))}`),
  link: (caseId, linkId) => request(`/api/cases/${enc(caseId)}/links/${enc(linkId)}`),
  observation: (caseId, obsId) => request(`/api/cases/${enc(caseId)}/observations/${enc(obsId)}`),
  frameUrl: (caseId, evidenceId, index) => `/api/cases/${enc(caseId)}/evidence/${enc(evidenceId)}/frames/${Number(index)}.png`,
  runs: (caseId) => request(`/api/cases/${enc(caseId)}/runs`),
  run: (caseId, runId) => request(`/api/cases/${enc(caseId)}/runs/${enc(runId)}`),
  act: (caseId, body, key) =>
    request(`/api/cases/${enc(caseId)}/actions`, {
      ...json("POST", body),
      headers: { "Content-Type": "application/json", "Idempotency-Key": key },
    }),
  reanalyse: (caseId) => request(`/api/cases/${enc(caseId)}/analyse`, { method: "POST" }),
  audit: (caseId) => request(`/api/cases/${enc(caseId)}/audit`),
  upload: (file) => request("/api/cases", { method: "POST", headers: { "Content-Type": "application/zip" }, body: file }),
  job: (jobId) => request(`/api/jobs/${enc(jobId)}`),
  evaluation: () => request("/api/evaluation"),
  users: () => request("/api/admin/users"),
  createUser: (body) => request("/api/admin/users", json("POST", body)),
  updateUser: (id, body) => request(`/api/admin/users/${enc(String(id))}`, json("PATCH", body)),
  revokeSessions: (id) => request(`/api/admin/users/${enc(String(id))}/revoke-sessions`, { method: "POST" }),
  access: (caseId) => request(`/api/cases/${enc(caseId)}/access`),
  grant: (caseId, userId) => request(`/api/cases/${enc(caseId)}/access`, json("POST", { user_id: userId })),
  revokeAccess: (caseId, userId) => request(`/api/cases/${enc(caseId)}/access/${enc(String(userId))}`, { method: "DELETE" }),
};

export async function waitForJob(jobId, onProgress) {
  for (let attempt = 0; attempt < 600; attempt += 1) {
    const job = await api.job(jobId);
    if (onProgress) onProgress(job);
    if (job.status === "completed") return job;
    if (job.status === "failed" || job.status === "cancelled") throw new ApiError(job.error || `Job ${job.status}`, 500, job);
    await new Promise((resolve) => setTimeout(resolve, attempt < 10 ? 400 : 1000));
  }
  throw new ApiError("The job is taking too long", 504);
}

export async function loadBundle(caseId, onWait) {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    try {
      return await api.bundle(caseId);
    } catch (error) {
      if (error.status !== 409) throw error;
      if (onWait) onWait();
      if (error.body && error.body.job) await waitForJob(error.body.job);
      else await new Promise((resolve) => setTimeout(resolve, 800));
    }
  }
  throw new ApiError("The analysis is not ready yet", 409);
}

export function newKey() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
