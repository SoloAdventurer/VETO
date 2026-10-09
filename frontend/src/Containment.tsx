import { OctagonAlert, Power, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { api } from "./api";
import type { AppState, RequestRow } from "./types";
import { cx, timeOf } from "./ui";

export function Containment({ state, rows, refresh }: { state: AppState; rows: RequestRow[]; refresh: () => void }) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const on = state.containment;
  const toggle = async () => {
    setBusy(true);
    try {
      await api.containment(!on, "operator-1", reason || (on ? "all clear" : "operator initiated"));
      setReason("");
      refresh();
    } finally {
      setBusy(false);
    }
  };
  const events = rows.filter((r) => r.request_id.startsWith("sys-")).slice(0, 5);
  return (
    <div className="mx-auto max-w-3xl space-y-4">
      <div>
        <h2 className="text-[18px] font-semibold">Emergency containment</h2>
        <p className="mt-1 max-w-xl text-[13px] text-muted">The kill switch. While engaged, VETO blocks every agent action — including ones that were already approved — and the Execution Gateway refuses to run anything. It is checked first, on every request.</p>
      </div>

      <div className={cx("card flex flex-col items-center gap-5 px-6 py-10 text-center", on && "border-bad/50")}>
        <button
          onClick={toggle}
          disabled={busy}
          aria-pressed={on}
          aria-label={on ? "Release containment" : "Engage containment"}
          className={cx("grid h-36 w-36 place-items-center rounded-full border-2 transition", on ? "pulse-bad border-bad bg-bad/15 text-bad" : "border-line bg-panel2 text-muted hover:border-bad/60 hover:text-bad")}
        >
          <Power size={54} strokeWidth={1.6} />
        </button>
        <div>
          <div className={cx("mono text-[22px] font-medium tracking-wide", on ? "text-bad" : "text-ok")}>{on ? "CONTAINMENT ENGAGED" : "NORMAL OPERATION"}</div>
          <div className="mt-1 flex items-center justify-center gap-2 text-[13px] text-muted">
            {on ? <OctagonAlert size={14} className="text-bad" /> : <ShieldCheck size={14} className="text-ok" />}
            {on ? "All agent actions are being blocked." : "Agents may propose actions; VETO decides each one."}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <input className="w-72" placeholder={on ? "Reason for release (optional)" : "Reason (optional)"} value={reason} onChange={(e) => setReason(e.target.value)} />
          <button className={cx("btn", on ? "btn-ok" : "btn-bad")} onClick={toggle} disabled={busy}>{on ? "Release" : "Engage"}</button>
        </div>
      </div>

      <div className="card p-4">
        <div className="eyebrow mb-2">Containment events</div>
        {events.length === 0 ? <div className="text-[12.5px] text-muted">No containment events yet.</div> : (
          <ul className="divide-y divide-line">
            {events.map((e) => (
              <li key={e.request_id} className="flex items-center justify-between gap-3 py-2 text-[12.5px]">
                <span>{e.decision_reason}</span>
                <span className="mono shrink-0 text-[11px] text-faint">{timeOf(e.first_timestamp)} · {e.agent_id}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
