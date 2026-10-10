import { Check, Inbox, UserRound, X } from "lucide-react";
import { useState } from "react";
import { api, type Me } from "./api";
import type { RequestRow } from "./types";
import { actionTitle, Empty, OriginChip, RiskPill, timeOf } from "./ui";

function Card({ r, canApprove, onDone }: { r: RequestRow; canApprove: boolean; onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const act = async (outcome: "approved" | "rejected") => {
    setBusy(true);
    setErr(null);
    try {
      await api.approve(r.request_id, outcome);
      onDone();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const prov = r.effective_provenance ?? [];
  const params = r.requested_action?.parameters ?? {};
  return (
    <article className="card row-in overflow-hidden">
      <div className="flex">
        <div className="w-1 bg-warn" />
        <div className="flex-1 p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <div className="mono text-[11px] text-faint">{timeOf(r.first_timestamp)} · {r.request_id}</div>
              <div className="mt-1 text-[16px] font-semibold">{actionTitle(r)}</div>
              <div className="mono mt-0.5 text-[12px] text-muted">
                requested by {r.agent_id}
                {Object.entries(params).map(([k, v]) => ` · ${k}=${String(v)}`)}
              </div>
            </div>
            {r.risk && <RiskPill score={r.risk.score} band={r.risk.band} />}
          </div>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            <div className="rounded-lg border border-line bg-bg/60 p-3">
              <div className="eyebrow mb-1">Why a human is needed</div>
              <div className="text-[13px]">{r.decision_reason}</div>
            </div>
            <div className="rounded-lg border border-line bg-bg/60 p-3">
              <div className="eyebrow mb-1.5">What the agent relied on</div>
              <div className="flex flex-wrap gap-1.5">
                {prov.length ? prov.map((p) => <OriginChip key={p} origin={p} />) : <span className="text-[12.5px] text-muted">Only operator-authenticated input.</span>}
              </div>
            </div>
          </div>
          {r.requested_action?.justification && (
            <div className="mt-3 text-[12.5px] text-muted">Agent says: “{r.requested_action.justification}” <span className="text-faint">(informational only)</span></div>
          )}
          <div className="mt-4 flex flex-wrap items-center gap-2">
            <button className="btn btn-ok" disabled={busy || !canApprove} title={canApprove ? undefined : "Requires the approver role"} onClick={() => act("approved")}><Check size={14} />Approve &amp; execute</button>
            <button className="btn btn-bad" disabled={busy || !canApprove} title={canApprove ? undefined : "Requires the approver role"} onClick={() => act("rejected")}><X size={14} />Reject</button>
            {err && <span className="text-[12px] text-bad">{err}</span>}
          </div>
        </div>
      </div>
    </article>
  );
}

export function Approvals({ rows, refresh, me }: { rows: RequestRow[]; refresh: () => void; me: Me }) {
  const canApprove = me.roles.includes("approver");
  const pending = rows.filter((r) => r.status === "pending_approval");
  const recent = rows.filter((r) => r.human_decision).slice(0, 6);
  return (
    <div className="mx-auto max-w-4xl space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-[18px] font-semibold">Approval queue</h2>
          <p className="mt-1 max-w-xl text-[13px] text-muted">Anything VETO is not certain about waits here. Nothing runs until a person decides, the decision is written to the audit log first, and an agent can never approve itself.</p>
        </div>
        <div className="flex items-center gap-2 text-[12px] text-muted"><UserRound size={14} />{canApprove ? "Approving as" : "Read-only:"} <span className="mono text-ink">{me.id}</span></div>
      </div>
      {pending.length === 0 ? (
        <div className="card"><Empty icon={<Inbox size={34} />} title="Queue is clear" hint="Run “Clearance change” or “Low-and-slow data harvesting” from the Live view to see requests held for review." /></div>
      ) : (
        pending.map((r) => <Card key={r.request_id} r={r} canApprove={canApprove} onDone={refresh} />)
      )}
      {recent.length > 0 && (
        <div className="card p-4">
          <div className="eyebrow mb-2">Recently decided</div>
          <ul className="divide-y divide-line">
            {recent.map((r) => (
              <li key={r.request_id} className="flex items-center justify-between py-2 text-[12.5px]">
                <span>{actionTitle(r)} <span className="mono text-faint">· {r.agent_id}</span></span>
                <span className="mono text-[11px] text-muted">{r.human_decision?.approver_id} {r.human_decision?.outcome}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
