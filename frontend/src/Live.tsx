import { Activity, Bot, DoorClosed, DoorOpen, Eraser, Play, RotateCcw, ShieldCheck, Skull, Swords, UserCheck } from "lucide-react";
import { useState } from "react";
import { api } from "./api";
import { RequestCard } from "./RequestCard";
import type { AppState, RequestRow, Scenario } from "./types";
import { cx, Empty, Section } from "./ui";

function Kpi({ label, value, sub, tone }: { label: string; value: string; sub: string; tone?: "ok" | "warn" | "bad" }) {
  const color = tone === "ok" ? "text-ok" : tone === "warn" ? "text-warn" : tone === "bad" ? "text-bad" : "text-ink";
  return (
    <div className="card px-4 py-3">
      <div className="eyebrow">{label}</div>
      <div className={cx("mono mt-1 text-[26px] font-medium leading-none", color)}>{value}</div>
      <div className="mt-1.5 text-[12px] text-muted">{sub}</div>
    </div>
  );
}

const KIND = {
  legit: { icon: <UserCheck size={14} />, cls: "text-ok", label: "Legitimate" },
  attack: { icon: <Skull size={14} />, cls: "text-bad", label: "Attack" },
  anomaly: { icon: <Activity size={14} />, cls: "text-warn", label: "Behaviour" },
};

function ScenarioPanel({ scenarios, onRan, busy, setBusy }: { scenarios: Scenario[]; onRan: () => void; busy: string | null; setBusy: (s: string | null) => void }) {
  const run = async (id: string) => {
    setBusy(id);
    try {
      await api.runScenario(id);
      onRan();
    } finally {
      setBusy(null);
    }
  };
  const groups: Scenario["kind"][] = ["legit", "attack", "anomaly"];
  return (
    <Section title="Agent scenarios" right={<span className="text-[11px] text-faint">scripted agents · real gateway</span>}>
      <div className="space-y-4">
        {groups.map((g) => (
          <div key={g}>
            <div className={cx("mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider", KIND[g].cls)}>
              {KIND[g].icon}{KIND[g].label}
            </div>
            <div className="space-y-1.5">
              {scenarios.filter((s) => s.kind === g).map((s) => (
                <div key={s.id} className="group rounded-lg border border-line bg-bg/40 p-2.5 transition hover:border-[#34475c]">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="text-[13px] font-semibold leading-snug">{s.title}</div>
                      <div className="mt-0.5 text-[11.5px] leading-snug text-muted">{s.blurb}</div>
                    </div>
                    <button className="btn btn-accent shrink-0" disabled={busy !== null} onClick={() => run(s.id)} aria-label={`Run ${s.title}`}>
                      <Play size={12} fill="currentColor" />{busy === s.id ? "…" : "Run"}
                    </button>
                  </div>
                  <div className="mono mt-1.5 text-[10.5px] text-faint"><Bot size={10} className="mr-1 inline" />{s.agent} · expect: {s.expect}</div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </Section>
  );
}

function AgentContexts({ state, refresh }: { state: AppState; refresh: () => void }) {
  return (
    <Section title="Agent sessions" right={<span className="text-[11px] text-faint">taint window {Math.round(state.taint_window_s / 60)} min</span>}>
      <div className="space-y-1.5">
        {state.agents.map((a) => {
          const tainted = a.tainted_by.length > 0;
          return (
            <div key={a.id} className={cx("rounded-lg border px-3 py-2", tainted ? "border-bad/40 bg-bad/10" : "border-line bg-bg/40")}>
              <div className="flex items-center justify-between gap-2">
                <div className="min-w-0">
                  <div className="mono truncate text-[12px] font-medium">{a.id}</div>
                  <div className={cx("text-[11px]", tainted ? "text-bad" : "text-ok")}>
                    {tainted ? `tainted by ${a.tainted_by.length} untrusted input${a.tainted_by.length > 1 ? "s" : ""}` : "clean session"}
                  </div>
                </div>
                {tainted && (
                  <button className="btn" title="Operator clears the session taint (audited)" onClick={async () => { await api.resetContext(a.id, "operator-1"); refresh(); }}>
                    <Eraser size={12} />Reset
                  </button>
                )}
              </div>
              {tainted && (
                <div className="mono mt-1 truncate text-[10.5px] text-faint">{a.tainted_by.map((t) => `${t.source}`).join(" · ")}</div>
              )}
            </div>
          );
        })}
      </div>
      <p className="mt-2.5 text-[11px] leading-snug text-faint">Anything an agent reads from an untrusted source taints everything it does next, even if it never mentions it.</p>
    </Section>
  );
}

function Resources({ state }: { state: AppState }) {
  const key = state.personnel.filter((p) => ["emp-1042", "emp-2210", "visitor-77"].includes(p.id));
  return (
    <Section title="Protected resources" right={<span className="text-[11px] text-faint">mock security-ops · synthetic</span>}>
      <div className="space-y-1.5">
        {state.doors.map((d) => (
          <div key={d.id} className={cx("flex items-center justify-between rounded-lg border px-3 py-2", d.state === "unlocked" ? "border-warn/50 bg-warn/10" : "border-line bg-bg/40")}>
            <div className="flex items-center gap-2.5">
              {d.state === "unlocked" ? <DoorOpen size={16} className="text-warn" /> : <DoorClosed size={16} className="text-muted" />}
              <div>
                <div className="text-[13px] font-semibold">{d.name}</div>
                <div className="mono text-[10.5px] text-faint">{d.id} · requires level {d.requirement}</div>
              </div>
            </div>
            <div className="text-right">
              <div className={cx("mono text-[11px] font-medium uppercase", d.state === "unlocked" ? "text-warn" : "text-muted")}>{d.state}</div>
              {d.last_subject && <div className="mono text-[10px] text-faint">{d.last_subject}</div>}
            </div>
          </div>
        ))}
      </div>
      <div className="eyebrow mb-1.5 mt-4">Personnel store (trusted)</div>
      <div className="space-y-1">
        {key.map((p) => (
          <div key={p.id} className="flex items-center justify-between text-[12.5px]">
            <span><span className="mono mr-2 text-[11px] text-faint">{p.id}</span>{p.name}</span>
            <span className="mono rounded border border-line px-1.5 text-[11px] text-muted">L{p.clearance}</span>
          </div>
        ))}
      </div>
      <div className="mono mt-3 text-[10.5px] text-faint">{state.personnel.length} personnel · {state.incident_total} incident rows</div>
    </Section>
  );
}

export function Live({ state, rows, scenarios, refresh }: { state: AppState; rows: RequestRow[]; scenarios: Scenario[]; refresh: () => void }) {
  const [busy, setBusy] = useState<string | null>(null);
  const s = state.stats;
  const uir = s.uir === null ? "—" : `${Math.round(s.uir * 100)}%`;
  const agentRows = rows.filter((r) => !r.request_id.startsWith("sys-"));
  const sys = rows.filter((r) => r.request_id.startsWith("sys-"));
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Kpi label="Unsafe attempts intercepted" value={`${s.unsafe_intercepted}/${s.unsafe_attempted}`} sub={`interception rate ${uir}`} tone={s.unsafe_attempted === 0 ? undefined : s.uir === 1 ? "ok" : "bad"} />
        <Kpi label="Requests mediated" value={String(s.total)} sub={`${s.by_status.executed ?? 0} executed · ${s.by_status.blocked ?? 0} blocked`} />
        <Kpi label="Awaiting a human" value={String(s.pending_approvals)} sub="held until approved or rejected" tone={s.pending_approvals ? "warn" : undefined} />
        <Kpi label="Gateway bypass refused" value={String(s.direct_access_denied)} sub="direct resource calls without a key" tone={s.direct_access_denied ? "ok" : undefined} />
      </div>

      <div className="grid gap-4 xl:grid-cols-[340px_minmax(0,1fr)_320px]">
        <div className="space-y-4 xl:sticky xl:top-[84px] xl:order-1 xl:max-h-[calc(100vh-100px)] xl:self-start xl:overflow-y-auto xl:pr-1"><ScenarioPanel scenarios={scenarios} onRan={refresh} busy={busy} setBusy={setBusy} />
          <button className="btn w-full justify-center text-muted" onClick={async () => { await api.reset(); refresh(); }}><RotateCcw size={13} />Reset demo state</button>
        </div>

        <div className="space-y-3 xl:order-2">
          <div className="flex items-center justify-between">
            <h2 className="flex items-center gap-2 text-[15px] font-semibold"><Swords size={16} className="text-accent" />Live decision feed</h2>
            <span className="mono text-[11px] text-faint">{agentRows.length} requests · click a row for the evidence</span>
          </div>
          {agentRows.length === 0 && sys.length === 0 ? (
            <div className="card"><Empty icon={<ShieldCheck size={34} />} title="Nothing proposed yet" hint="Run a scenario on the left. Every action an agent proposes is shown here with the decision VETO made and why." /></div>
          ) : (
            [...rows].map((r, i) => <RequestCard key={r.request_id} r={r} defaultOpen={i === 0} />)
          )}
        </div>

        <div className="space-y-4 xl:sticky xl:top-[84px] xl:order-3 xl:max-h-[calc(100vh-100px)] xl:self-start xl:overflow-y-auto xl:pr-1"><AgentContexts state={state} refresh={refresh} /><Resources state={state} /></div>
      </div>
    </div>
  );
}
