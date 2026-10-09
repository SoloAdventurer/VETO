import type { AppState, AuditRecord, ChainStatus, RequestRow, Scenario } from "./types";

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
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
  state: () => call<AppState>("/v1/state"),
  requests: () => call<RequestRow[]>("/v1/requests?limit=200"),
  audit: () => call<AuditRecord[]>("/v1/audit?limit=500"),
  verify: () => call<ChainStatus>("/v1/audit/verify"),
  scenarios: () => call<Scenario[]>("/v1/demo/scenarios"),
  runScenario: (id: string) => post<{ scenario: string }>(`/v1/demo/scenarios/${id}`),
  reset: () => post<{ ok: boolean }>("/v1/demo/reset"),
  approve: (id: string, approver: string, outcome: "approved" | "rejected", note = "") =>
    post(`/v1/approvals/${id}`, { approver_id: approver, outcome, note }),
  resetContext: (agentId: string, by: string) =>
    post(`/v1/operator/agents/${agentId}/context-reset`, { by }),
  containment: (active: boolean, by: string, reason: string) =>
    post("/v1/containment", { active, by, reason }),
};
