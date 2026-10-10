import { KeyRound, LogIn } from "lucide-react";
import { useState } from "react";
import { api, auth, type Me } from "./api";

export function Login({ onLogin }: { onLogin: (me: Me) => void }) {
  const [key, setKey] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const me = await api.me(key.trim());
      if (me.roles.includes("agent")) throw new Error("Agent keys cannot sign in to the dashboard.");
      auth.set(key.trim());
      onLogin(me);
    } catch (e2) {
      setErr(e2 instanceof Error ? e2.message : "Sign-in failed");
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="mx-auto mt-24 max-w-md px-5">
      <form onSubmit={submit} className="card space-y-4 p-6">
        <div className="flex items-center gap-2 text-[16px] font-semibold"><KeyRound size={17} className="text-accent" />Sign in to VETO</div>
        <p className="text-[12.5px] text-muted">Paste an operator, approver or viewer API key. Who you are comes from the key; it is kept in this tab only and every action you take is recorded under it.</p>
        <input className="mono w-full" type="password" autoFocus placeholder="veto_…" value={key} onChange={(e) => setKey(e.target.value)} aria-label="API key" />
        {err && <div className="text-[12.5px] text-bad" role="alert">{err}</div>}
        <button className="btn btn-ok w-full justify-center" disabled={busy || key.trim().length < 10}><LogIn size={14} />Sign in</button>
      </form>
    </div>
  );
}
