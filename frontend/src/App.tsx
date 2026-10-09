import { Activity, Inbox, Power, ScrollText } from "lucide-react";
import { Fragment, useCallback, useEffect, useState } from "react";
import { api } from "./api";
import { Approvals } from "./Approvals";
import { Audit } from "./Audit";
import { Containment } from "./Containment";
import { Live } from "./Live";
import type { AppState, AuditRecord, RequestRow, Scenario } from "./types";
import { cx } from "./ui";

type Tab = "live" | "approvals" | "containment" | "audit";

function Logo() {
  return (
    <div className="flex items-center gap-3">
      <svg width="30" height="30" viewBox="0 0 32 32" aria-hidden>
        <rect width="32" height="32" rx="8" fill="#131b24" stroke="#1f2a37" />
        <path d="M7 9l9 15 9-15" fill="none" stroke="#f2a93b" strokeWidth="3.2" strokeLinecap="round" strokeLinejoin="round" />
        <path d="M12 9h8" stroke="#f2a93b" strokeWidth="3.2" strokeLinecap="round" />
      </svg>
      <div className="leading-tight">
        <div className="text-[16px] font-bold tracking-[0.2em]">VETO</div>
        <div className="text-[10.5px] text-muted">Autonomy does not imply authority</div>
      </div>
    </div>
  );
}

export default function App() {
  const [tab, setTab] = useState<Tab>("live");
  const [state, setState] = useState<AppState | null>(null);
  const [rows, setRows] = useState<RequestRow[]>([]);
  const [audit, setAudit] = useState<AuditRecord[]>([]);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [offline, setOffline] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [s, r] = await Promise.all([api.state(), api.requests()]);
      setState(s);
      setRows(r);
      if (tab === "audit") setAudit(await api.audit());
      setOffline(false);
    } catch {
      setOffline(true);
    }
  }, [tab]);

  useEffect(() => {
    api.scenarios().then(setScenarios).catch(() => undefined);
  }, []);
  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 1000);
    return () => clearInterval(t);
  }, [refresh]);

  const tabs: { id: Tab; label: string; icon: JSX.Element; badge?: number }[] = [
    { id: "live", label: "Live feed", icon: <Activity size={15} /> },
    { id: "approvals", label: "Approvals", icon: <Inbox size={15} />, badge: state?.stats.pending_approvals },
    { id: "containment", label: "Containment", icon: <Power size={15} /> },
    { id: "audit", label: "Audit trail", icon: <ScrollText size={15} /> },
  ];

  return (
    <div className="min-h-full">
      {state?.containment && (
        <div className="pulse-bad flex items-center justify-center gap-2 bg-bad px-4 py-1.5 text-[12.5px] font-semibold text-white">
          CONTAINMENT ENGAGED — all agent actions are blocked
        </div>
      )}
      <header className="sticky top-0 z-20 border-b border-line bg-bg/80 backdrop-blur">
        <div className="mx-auto flex max-w-[1500px] flex-wrap items-center justify-between gap-x-6 gap-y-3 px-5 py-3">
          <Logo />
          <nav className="flex gap-1 rounded-xl border border-line bg-panel p-1" aria-label="Views">
            {tabs.map((t) => (
              <button key={t.id} onClick={() => setTab(t.id)} className={cx("flex items-center gap-2 rounded-lg px-3.5 py-1.5 text-[13px] font-semibold transition", tab === t.id ? "bg-panel2 text-ink shadow-[inset_0_0_0_1px_#2a3846]" : "text-muted hover:text-ink")}>
                {t.icon}{t.label}
                {t.badge ? <span className="pulse-warn rounded-full bg-warn px-1.5 text-[10.5px] font-bold text-black">{t.badge}</span> : null}
              </button>
            ))}
          </nav>
          <div className="mono flex items-center gap-4 text-[11px] text-muted">
            {state && (
              <Fragment>
                <span title="Policy version">policy {state.policy.version.split("@")[1]}</span>
                <span className={cx("flex items-center gap-1.5", state.chain.ok ? "text-ok" : "text-bad")}>
                  <span className={cx("h-1.5 w-1.5 rounded-full", state.chain.ok ? "bg-ok" : "bg-bad")} />
                  audit chain {state.chain.ok ? "intact" : "BROKEN"} · {state.chain.count}
                </span>
              </Fragment>
            )}
            <span className={cx("flex items-center gap-1.5", offline ? "text-bad" : "text-ok")}>
              <span className={cx("h-1.5 w-1.5 rounded-full", offline ? "bg-bad" : "bg-ok")} />{offline ? "gateway offline" : "gateway online"}
            </span>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-[1500px] px-5 py-5">
        {!state ? (
          <div className="py-24 text-center text-muted">{offline ? "Cannot reach the VETO gateway on this host." : "Connecting to gateway…"}</div>
        ) : tab === "live" ? (
          <Live state={state} rows={rows} scenarios={scenarios} refresh={refresh} />
        ) : tab === "approvals" ? (
          <Approvals rows={rows} refresh={refresh} />
        ) : tab === "containment" ? (
          <Containment state={state} rows={rows} refresh={refresh} />
        ) : (
          <Audit state={state} records={audit} />
        )}
      </main>
    </div>
  );
}
