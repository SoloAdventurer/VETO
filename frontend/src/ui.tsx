import { AlertTriangle, Ban, CheckCircle2, Clock, Eye, ShieldAlert, XCircle } from "lucide-react";
import type { ReactNode } from "react";
import type { Band, Decision, Status } from "./types";

export const cx = (...c: (string | false | null | undefined)[]) => c.filter(Boolean).join(" ");

export const timeOf = (iso: string) => iso.slice(11, 19);
export const short = (h: string, n = 8) => (h ? h.slice(0, n) : "—");

const STATUS: Record<Status, { label: string; cls: string; icon: ReactNode }> = {
  executed: { label: "Executed · verified", cls: "text-ok border-ok/40 bg-ok/10", icon: <CheckCircle2 size={13} /> },
  executed_unverified: { label: "Executed · UNVERIFIED", cls: "text-warn border-warn/40 bg-warn/10", icon: <AlertTriangle size={13} /> },
  blocked: { label: "Blocked", cls: "text-bad border-bad/40 bg-bad/10", icon: <Ban size={13} /> },
  pending_approval: { label: "Awaiting human", cls: "text-warn border-warn/40 bg-warn/10", icon: <Clock size={13} /> },
  rejected: { label: "Rejected by human", cls: "text-bad border-bad/40 bg-bad/10", icon: <XCircle size={13} /> },
  expired: { label: "Expired · not executed", cls: "text-muted border-line bg-panel2", icon: <Clock size={13} /> },
  failed: { label: "Failed", cls: "text-warn border-warn/40 bg-warn/10", icon: <AlertTriangle size={13} /> },
  pending_execution: { label: "Pending", cls: "text-muted border-line bg-panel2", icon: <Clock size={13} /> },
};

export function StatusChip({ status }: { status: Status }) {
  const s = STATUS[status];
  return (
    <span className={cx("inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11.5px] font-semibold whitespace-nowrap", s.cls)}>
      {s.icon}
      {s.label}
    </span>
  );
}

const DECISION: Record<Decision, { label: string; cls: string }> = {
  allow: { label: "ALLOW", cls: "text-ok" },
  allow_monitor: { label: "ALLOW + MONITOR", cls: "text-info" },
  require_approval: { label: "HUMAN APPROVAL", cls: "text-warn" },
  block: { label: "BLOCK", cls: "text-bad" },
};

export function DecisionLabel({ d }: { d: Decision }) {
  return <span className={cx("mono text-[11px] font-medium tracking-wide", DECISION[d].cls)}>{DECISION[d].label}</span>;
}

export const decisionBar = (d: Decision) =>
  ({ allow: "bg-ok", allow_monitor: "bg-info", require_approval: "bg-warn", block: "bg-bad" })[d];

const BAND_CLS: Record<Band, string> = {
  LOW: "text-ok border-ok/40",
  MEDIUM: "text-info border-info/40",
  HIGH: "text-warn border-warn/40",
  CRITICAL: "text-bad border-bad/40",
};

export function RiskPill({ score, band }: { score: number; band: Band }) {
  return (
    <span className={cx("mono inline-flex items-center gap-1.5 rounded-md border px-1.5 py-0.5 text-[11px]", BAND_CLS[band])} title={`Risk ${score}/100 · ${band}`}>
      <span className="font-medium">{score}</span>
      <span className="text-[9.5px] tracking-wider opacity-80">{band}</span>
    </span>
  );
}

const TRUSTED = new Set(["operator_input", "trusted_store"]);
export function OriginChip({ origin }: { origin: string }) {
  const trusted = TRUSTED.has(origin);
  return (
    <span className={cx("mono inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[10.5px]", trusted ? "border-ok/40 bg-ok/10 text-ok" : "border-bad/40 bg-bad/10 text-bad")}>
      {trusted ? <Eye size={10} /> : <ShieldAlert size={10} />}
      {origin}
    </span>
  );
}

export function Section({ title, right, children, className }: { title: string; right?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={cx("card p-4", className)}>
      <div className="mb-3 flex items-center justify-between">
        <h3 className="eyebrow">{title}</h3>
        {right}
      </div>
      {children}
    </section>
  );
}

export function Empty({ icon, title, hint }: { icon: ReactNode; title: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-14 text-center text-muted">
      <div className="text-faint">{icon}</div>
      <div className="font-medium text-ink/80">{title}</div>
      {hint && <div className="max-w-sm text-[12.5px]">{hint}</div>}
    </div>
  );
}

export function actionTitle(rec: { requested_action?: { action: string; target?: { id: string } } }) {
  const a = rec.requested_action;
  if (!a) return "—";
  return a.target ? `${a.action} · ${a.target.id}` : a.action;
}
