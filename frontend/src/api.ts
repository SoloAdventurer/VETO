import type { AppState, AuditRecord, ChainStatus, RequestRow, Scenario } from "./types";

const KEY = "veto.apikey";
let onUnauthorized: () => void = () => undefined;
export const auth = {
  get: (): string | null => {
    try { return sessionStorage.getItem(KEY); } catch { return null; }
  },
  set: (k: string) => { try { sessionStorage.setItem(KEY, k); } catch { /* storage blocked */ } },
  clear: () => { try { sessionStorage.removeItem(KEY); } catch { /* storage blocked */ } },
  onUnauthorized: (fn: () => void) => { onUnauthorized = fn; },
};

export interface Me { id: string; roles: string[]; tenant: string | null; demo: boolean }

async function call<T>(path: string, init?: RequestInit, key?: string): Promise<T> {
  const token = key ?? auth.get();
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    ...init,
  });
  if (res.status === 401 && key === undefined) onUnauthorized();
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail ?? detail;
    } catch {
      /* non-JSON error body */
    }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

const post = <T>(path: string, body?: unknown) =>
  call<T>(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) });

export const api = {
  me: (key?: string) => call<Me>("/v1/auth/me", undefined, key ?? auth.get() ?? ""),
  state: () => call<AppState>("/v1/state"),
  requests: () => call<RequestRow[]>("/v1/requests?limit=200"),
  audit: () => call<AuditRecord[]>("/v1/audit?limit=500"),
  verify: () => call<ChainStatus>("/v1/audit/verify"),
  scenarios: () => call<Scenario[]>("/v1/demo/scenarios"),
  runScenario: (id: string) => post<{ scenario: string }>(`/v1/demo/scenarios/${id}`),
  reset: () => post<{ ok: boolean }>("/v1/demo/reset"),
  approve: (id: string, outcome: "approved" | "rejected", note = "") =>
    post(`/v1/approvals/${id}`, { outcome, note }),
  resetContext: (agentId: string) => post(`/v1/operator/agents/${agentId}/context-reset`),
  containment: (active: boolean, reason: string) => post("/v1/containment", { active, reason }),
};
