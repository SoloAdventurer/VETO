import { ChevronDown, Fingerprint, Gavel, Sparkles } from "lucide-react";
import { useState } from "react";
import type { RequestRow } from "./types";
import { actionTitle, cx, decisionBar, DecisionLabel, OriginChip, RiskPill, short, StatusChip, timeOf } from "./ui";

const COMPONENT_LABEL: Record<string, string> = {
  action_sensitivity: "Action sensitivity",
  target_sensitivity: "Target sensitivity",
  agent_risk: "Agent baseline",
  environmental_risk: "Untrusted context",
  behavioral_anomaly: "Behavioural anomaly",
};

export function RequestDetails({ r }: { r: RequestRow }) {
  const matched = r.policies_evaluated.filter((p) => p.result === "matched");
  const rest = r.policies_evaluated.filter((p) => p.result !== "matched");
  const comps = r.risk?.components ?? {};
  const prov = r.effective_provenance ?? [];
  const detail = r.provenance_detail ?? [];
  return (
    <div className="grid gap-4 border-t border-line px-4 py-4 md:grid-cols-3">
      <div>
        <div className="eyebrow mb-2 flex items-center gap-1.5"><Gavel size={12} /> Policy decision</div>
        <ul className="space-y-1">
          {matched.map((p) => (
            <li key={p.rule_id} className="mono flex flex-wrap items-center gap-x-2 text-[11.5px]">
              <span className={cx("h-1.5 w-1.5 shrink-0 rounded-full", p.effect === "deny" ? "bg-bad" : p.effect === "allow" ? "bg-ok" : "bg-warn")} />
              <span className="break-all text-ink">{p.rule_id}</span>
              <span className="text-faint">→ {p.effect}</span>
            </li>
          ))}
          {matched.length === 0 && <li className="text-[12px] text-muted">No rule matched — default deny.</li>}
        </ul>
        {rest.length > 0 && (
          <details className="mt-2 text-[10.5px] text-faint">
            <summary className="cursor-pointer select-none hover:text-muted">{rest.length} other rules evaluated, not matched</summary>
            <ul className="mono mt-1 space-y-0.5 leading-relaxed">{rest.map((p) => <li key={p.rule_id} className="break-all">{p.rule_id}</li>)}</ul>
          </details>
        )}
        {r.requested_action?.justification && (
          <div className="mt-3 rounded-lg border border-line bg-bg/60 p-2.5 text-[12px] text-muted">
            <div className="eyebrow mb-1">Agent's stated reason (never grants authority)</div>
            “{r.requested_action.justification}”
          </div>
        )}
      </div>

      <div>
        <div className="eyebrow mb-2 flex items-center gap-1.5"><Sparkles size={12} /> Risk &amp; behaviour</div>
        {r.risk ? (
          <div className="space-y-1.5">
            {Object.entries(comps).map(([k, v]) => (
              <div key={k} className="text-[11.5px]">
                <div className="flex justify-between text-muted"><span>{COMPONENT_LABEL[k] ?? k}</span><span className="mono">{v}</span></div>
                <div className="mt-0.5 h-1 rounded bg-line"><div className="h-1 rounded bg-accent/80" style={{ width: `${Math.min(100, (v / 40) * 100)}%` }} /></div>
              </div>
            ))}
            <div className="mono pt-1 text-[11px] text-muted">
              total {r.risk.score}/100 · anomaly {r.anomaly?.score ?? 0}
              {r.anomaly?.flagged && <span className="ml-1 text-warn">flagged</span>}
            </div>
            {r.anomaly?.reasons && r.anomaly.reasons.length > 0 && (
              <ul className="mt-1 space-y-0.5 text-[11px] text-warn">
                {r.anomaly.reasons.map((reason) => <li key={reason}>· {reason}</li>)}
              </ul>
            )}
          </div>
        ) : (
          <div className="text-[12px] text-muted">Rejected before scoring.</div>
        )}
        <div className="eyebrow mb-1.5 mt-4">Provenance (assigned by VETO)</div>
        <div className="flex flex-wrap gap-1.5">
          {detail.length
            ? detail.map((d) => (
                <span key={d.ref} className="inline-flex items-center gap-1" title={d.via === "ambient" ? `${d.ref}: added by VETO, the agent read this earlier in its session but did not declare it` : `${d.ref}: declared by the agent`}>
                  <OriginChip origin={d.origin} />
                  {d.via === "ambient" && <span className="mono rounded border border-warn/40 px-1 text-[9.5px] uppercase tracking-wider text-warn">undeclared</span>}
                </span>
              ))
            : prov.length ? prov.map((p) => <OriginChip key={p} origin={p} />) : <span className="text-[12px] text-muted">No external inputs in this session.</span>}
        </div>
      </div>

      <div>
        <div className="eyebrow mb-2 flex items-center gap-1.5"><Fingerprint size={12} /> Evidence</div>
        <dl className="mono space-y-1 text-[11px] text-muted">
          <div className="flex justify-between gap-2"><dt>action hash</dt><dd className="text-ink">{short(r.action_hash, 14)}</dd></div>
          <div className="flex justify-between gap-2"><dt>audit events</dt><dd className="text-ink">{r.events}</dd></div>
          <div className="flex justify-between gap-2"><dt>latest record</dt><dd className="text-ink">{short(r.record_hash, 14)}</dd></div>
          <div className="flex justify-between gap-2"><dt>policy</dt><dd className="text-ink">{r.policy_version?.split("+")[1] ?? "—"}</dd></div>
        </dl>
        {r.execution && (
          <div className="mt-3 rounded-lg border border-line bg-bg/60 p-2.5 text-[12px]">
            <div className="eyebrow mb-1">Execution</div>
            <div className="text-ink">{r.execution.result_summary}</div>
            {r.verification && <div className="mt-1 text-muted">Verified: {r.verification.detail}</div>}
          </div>
        )}
        {r.human_decision && (
          <div className="mt-2 rounded-lg border border-line bg-bg/60 p-2.5 text-[12px]">
            <div className="eyebrow mb-1">Human decision</div>
            <span className="text-ink">{r.human_decision.approver_id}</span> {r.human_decision.outcome}
          </div>
        )}
      </div>
    </div>
  );
}

export function RequestCard({ r, defaultOpen = false }: { r: RequestRow; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  const a = r.requested_action;
  return (
    <article className="card row-in overflow-hidden">
      <button className="flex w-full items-stretch text-left" onClick={() => setOpen((o) => !o)}>
        <div className={cx("w-1 shrink-0", decisionBar(r.decision))} />
        <div className="flex min-w-0 flex-1 flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
          <div className="min-w-0 flex-1 basis-[260px]">
            <div className="flex flex-wrap items-center gap-2">
              <span className="mono text-[11px] text-faint">{timeOf(r.first_timestamp)}</span>
              <span className="mono rounded bg-panel2 px-1.5 py-0.5 text-[11px] text-muted">{r.agent_id}</span>
              <DecisionLabel d={r.decision} />
              {r.tags?.unsafe && <span className="rounded border border-bad/30 px-1.5 py-0.5 text-[9.5px] font-semibold uppercase tracking-wider text-bad/80">unsafe attempt</span>}
            </div>
            <div className="mt-1 truncate text-[14px] font-semibold">{actionTitle(r)}
              {a?.parameters && Object.keys(a.parameters).length > 0 && (
                <span className="mono ml-2 text-[11.5px] font-normal text-muted">
                  {Object.entries(a.parameters).map(([k, v]) => `${k}=${String(v)}`).join(" ")}
                </span>
              )}
            </div>
            <div className="mt-0.5 truncate text-[12.5px] text-muted">{r.decision_reason}</div>
          </div>
          <div className="flex items-center gap-3">
            {r.risk && <RiskPill score={r.risk.score} band={r.risk.band} />}
            <StatusChip status={r.status} />
            <ChevronDown size={16} className={cx("text-faint transition-transform", open && "rotate-180")} />
          </div>
        </div>
      </button>
      {open && <RequestDetails r={r} />}
    </article>
  );
}
