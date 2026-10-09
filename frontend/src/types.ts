export type Band = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type Decision = "allow" | "allow_monitor" | "require_approval" | "block";
export type Status =
  | "executed"
  | "executed_unverified"
  | "blocked"
  | "pending_approval"
  | "rejected"
  | "failed"
  | "pending_execution";

export interface Risk {
  score: number;
  band: Band;
  components: Record<string, number>;
}

export interface Anomaly {
  score: number;
  flagged: boolean;
  model_version: string;
}

export interface RuleEval {
  rule_id: string;
  result: "matched" | "not_matched" | "error";
  effect?: "allow" | "deny" | "require_approval" | "monitor";
}

export interface RequestedAction {
  action: string;
  agent_id?: string;
  target?: { resource: string; id: string };
  parameters?: Record<string, unknown>;
  justification?: string;
  channel?: string;
}

export interface AuditRecord {
  seq: number;
  event_id: string;
  request_id: string;
  timestamp: string;
  agent_id: string;
  requested_action?: RequestedAction;
  action_hash: string;
  observation_ids?: string[];
  effective_provenance?: string[];
  provenance_detail?: { ref: string; origin: string; via: "declared" | "ambient" }[];
  policies_evaluated: RuleEval[];
  risk?: Risk;
  anomaly?: Anomaly;
  decision: Decision;
  decision_reason?: string;
  human_decision?: { approver_id?: string; outcome?: string; timestamp?: string; note?: string } | null;
  execution?: { status: string; adapter?: string; result_summary?: string } | null;
  verification?: { status: string; detail?: string } | null;
  policy_version?: string;
  containment_active?: boolean;
  prev_hash: string;
  record_hash: string;
}

export interface RequestRow extends AuditRecord {
  status: Status;
  first_seq: number;
  first_timestamp: string;
  events: number;
  tags: { scenario: string; unsafe: boolean } | null;
}

export interface Door {
  id: string;
  name: string;
  requirement: number;
  state: "locked" | "unlocked";
  unlocked_until: number | null;
  last_subject: string | null;
}

export interface Person {
  id: string;
  name: string;
  unit: string;
  clearance: number;
}

export interface Stats {
  total: number;
  by_status: Record<string, number>;
  pending_approvals: number;
  unsafe_attempted: number;
  unsafe_intercepted: number;
  uir: number | null;
  direct_access_denied: number;
}

export interface ChainStatus {
  ok: boolean;
  count: number;
  broken_at: number | null;
  detail: string;
}

export interface AgentView {
  id: string;
  role: string;
  base_risk: number;
  tainted_by: { ref: string; source: string; origin: string }[];
}

export interface AppState {
  agents: AgentView[];
  taint_window_s: number;
  containment: boolean;
  doors: Door[];
  personnel: Person[];
  incident_total: number;
  stats: Stats;
  chain: ChainStatus;
  policy: { id: string; version: string; rules: number; agents: Record<string, { role: string; base_risk: number }> };
}

export interface Scenario {
  id: string;
  title: string;
  kind: "legit" | "attack" | "anomaly";
  agent: string;
  expect: string;
  blurb: string;
}
