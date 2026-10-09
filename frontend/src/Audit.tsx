import { Link2, ShieldCheck, ShieldX } from "lucide-react";
import { Fragment, useState } from "react";
import { api } from "./api";
import type { AppState, AuditRecord, ChainStatus } from "./types";
import { actionTitle, cx, DecisionLabel, short, timeOf } from "./ui";

export function Audit({ state, records }: { state: AppState; records: AuditRecord[] }) {
  const [verify, setVerify] = useState<ChainStatus | null>(null);
  const [open, setOpen] = useState<number | null>(null);
  const chain = verify ?? state.chain;
  const rows = [...records].reverse();
  return (
    <div className="mx-auto max-w-6xl space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-[18px] font-semibold">Audit trail</h2>
          <p className="mt-1 max-w-2xl text-[13px] text-muted">Append-only and hash-chained. Each record commits to the one before it, so editing or deleting history — even directly in the database — breaks the chain and is detected. Decisions are recorded before anything executes.</p>
        </div>
        <div className={cx("flex items-center gap-3 rounded-xl border px-4 py-2.5", chain.ok ? "border-ok/40 bg-ok/10" : "border-bad/50 bg-bad/10")}>
          {chain.ok ? <ShieldCheck className="text-ok" size={20} /> : <ShieldX className="text-bad" size={20} />}
          <div>
            <div className={cx("text-[13px] font-semibold", chain.ok ? "text-ok" : "text-bad")}>{chain.ok ? "Chain intact" : `Chain BROKEN at #${chain.broken_at}`}</div>
            <div className="mono text-[11px] text-muted">{chain.count} records verified</div>
          </div>
          <button className="btn ml-2" onClick={async () => setVerify(await api.verify())}>Re-verify</button>
        </div>
      </div>

      <div className="card overflow-x-auto">
        <table className="w-full min-w-[820px] text-left text-[12.5px]">
          <thead>
            <tr className="eyebrow border-b border-line">
              <th className="px-4 py-2.5 font-semibold">#</th><th className="py-2.5 font-semibold">Time</th><th className="py-2.5 font-semibold">Agent</th>
              <th className="py-2.5 font-semibold">Action</th><th className="py-2.5 font-semibold">Decision</th><th className="py-2.5 font-semibold">Outcome</th>
              <th className="py-2.5 pr-4 text-right font-semibold"><Link2 size={12} className="mr-1 inline" />prev → hash</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const outcome = r.human_decision ? `human ${r.human_decision.outcome}` : r.execution ? `${r.execution.status}${r.verification ? ` · ${r.verification.status}` : ""}` : "decided";
              return (
                <Fragment key={r.seq}>
                  <tr className="cursor-pointer border-b border-line/60 hover:bg-panel2/60" onClick={() => setOpen(open === r.seq ? null : r.seq)}>
                    <td className="mono px-4 py-2 text-faint">{r.seq}</td>
                    <td className="mono py-2 text-muted">{timeOf(r.timestamp)}</td>
                    <td className="mono py-2 text-muted">{r.agent_id}</td>
                    <td className="py-2 font-medium">{actionTitle(r)}</td>
                    <td className="py-2"><DecisionLabel d={r.decision} /></td>
                    <td className="mono py-2 text-[11.5px] text-muted">{outcome}</td>
                    <td className="mono py-2 pr-4 text-right text-[11px] text-faint">{short(r.prev_hash, 6)} → <span className="text-ink">{short(r.record_hash, 6)}</span></td>
                  </tr>
                  {open === r.seq && (
                    <tr className="border-b border-line/60 bg-bg/60">
                      <td colSpan={7} className="px-4 py-3"><pre className="mono max-h-72 overflow-auto text-[11px] leading-relaxed text-muted">{JSON.stringify(r, null, 2)}</pre></td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
        {rows.length === 0 && <div className="py-12 text-center text-muted">No records yet.</div>}
      </div>
    </div>
  );
}
