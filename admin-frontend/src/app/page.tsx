"use client";

import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { createClient, Session } from "@supabase/supabase-js";

type Verdict = "known_phishing" | "high_risk" | "suspicious" | "no_indicators" | "unknown";
type Assessment = { verdict?: Verdict; risk_score?: number; matched_brand?: string | null; official_url?: string | null; signals?: { code: string; label: string; severity: string; points: number }[] };
type Scan = { job_id: string; domain: string; status: string; created_at: string; user_email: string; phishing?: Assessment | null };
type Result = { status?: string; domain?: string; data?: Record<string, unknown> };

const apiBase = (process.env.NODE_ENV === "development" ? "/backend" : process.env.NEXT_PUBLIC_API_URL || "").replace(/\/$/, "");
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
const supabase = supabaseUrl && supabaseKey ? createClient(supabaseUrl, supabaseKey) : null;

function verdictName(verdict?: Verdict) {
  return ({ known_phishing: "Known phishing", high_risk: "High risk", suspicious: "Suspicious", no_indicators: "No indicators", unknown: "Unknown" } as Record<string, string>)[verdict || "unknown"];
}

export default function AdminPage() {
  const [session, setSession] = useState<Session | null>(null);
  const [authorized, setAuthorized] = useState(false);
  const [checking, setChecking] = useState(Boolean(supabase));
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState(supabase ? "" : "Authentication is not configured.");
  const [scans, setScans] = useState<Scan[]>([]);
  const [selected, setSelected] = useState<Scan | null>(null);
  const [detail, setDetail] = useState<Result | null>(null);
  const [loading, setLoading] = useState(false);

  const authorize = useCallback(async (nextSession: Session | null) => {
    setChecking(true);
    setAuthorized(false);
    setScans([]);
    setSession(nextSession);
    if (!nextSession || !apiBase) { setChecking(false); return; }
    try {
      const headers = { Authorization: `Bearer ${nextSession.access_token}` };
      const identity = await fetch(`${apiBase}/auth/me`, { headers });
      if (!identity.ok || !(await identity.json()).is_admin) throw new Error("This account is not authorized for administration.");
      const response = await fetch(`${apiBase}/admin/scans`, { headers });
      if (!response.ok) throw new Error("Administrative scan records could not be loaded.");
      setScans(await response.json());
      setAuthorized(true);
      setMessage("");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Authorization failed.");
    } finally { setChecking(false); }
  }, []);

  useEffect(() => {
    if (!supabase) return;
    supabase.auth.getSession().then(({ data }) => authorize(data.session));
    const { data } = supabase.auth.onAuthStateChange((_event, nextSession) => { void authorize(nextSession); });
    return () => data.subscription.unsubscribe();
  }, [authorize]);

  async function signIn(event: FormEvent) {
    event.preventDefault();
    if (!supabase) return;
    setLoading(true); setMessage("");
    const { error } = await supabase.auth.signInWithPassword({ email: email.trim(), password });
    if (error) setMessage(error.message);
    setLoading(false);
  }

  async function signOut() {
    await supabase?.auth.signOut();
    setSession(null); setAuthorized(false); setScans([]); setSelected(null); setDetail(null);
  }

  async function inspect(scan: Scan) {
    if (!session) return;
    setSelected(scan); setDetail(null);
    const response = await fetch(`${apiBase}/results/${scan.job_id}`, { headers: { Authorization: `Bearer ${session.access_token}` } });
    if (response.ok) setDetail(await response.json());
  }

  const stats = useMemo(() => ({
    total: scans.length,
    threats: scans.filter((scan) => ["known_phishing", "high_risk"].includes(scan.phishing?.verdict || "")).length,
    suspicious: scans.filter((scan) => scan.phishing?.verdict === "suspicious").length,
    users: new Set(scans.map((scan) => scan.user_email)).size,
  }), [scans]);

  if (!authorized) return (
    <main className="login-shell">
      <section className="login-card">
        <div className="brand"><span>CR</span><div><strong>CyberRecon</strong><small>Restricted administration</small></div></div>
        <div className="eyebrow">Privileged access</div>
        <h1>Threat operations console</h1>
        <p>Sign in with an approved administrator account. Access is independently verified by the API.</p>
        {checking ? <div className="checking">Verifying secure session…</div> : <form onSubmit={signIn}>
          <label>Email address<input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" required /></label>
          <label>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required /></label>
          <button disabled={loading}>{loading ? "Authenticating…" : "Enter administration"}</button>
        </form>}
        {message && <div className="error" role="alert">{message}</div>}
        <small className="security-note">Protected by Supabase authentication and server-side role authorization.</small>
      </section>
    </main>
  );

  return (
    <main className="console">
      <header><div className="brand"><span>CR</span><div><strong>CyberRecon</strong><small>Threat operations</small></div></div><div className="operator"><span><i /> ADMIN VERIFIED</span><small>{session?.user.email}</small><button onClick={signOut}>Sign out</button></div></header>
      <section className="hero"><div><div className="eyebrow">Operations overview</div><h1>Reconnaissance intelligence</h1><p>Monitor public scans, phishing assessments, and account activity from a dedicated restricted surface.</p></div><a href="https://cgreglab.space" rel="noreferrer">Open public console ↗</a></section>
      <section className="metrics"><article><span>Total retained</span><strong>{String(stats.total).padStart(2, "0")}</strong><small>Most recent 100 scans</small></article><article className="danger"><span>High-risk threats</span><strong>{String(stats.threats).padStart(2, "0")}</strong><small>Known phishing or high risk</small></article><article><span>Suspicious</span><strong>{String(stats.suspicious).padStart(2, "0")}</strong><small>Requires analyst review</small></article><article><span>Users observed</span><strong>{String(stats.users).padStart(2, "0")}</strong><small>Unique scanning accounts</small></article></section>
      <section className="workspace">
        <article className="scan-panel"><div className="panel-head"><div><div className="eyebrow">Intelligence ledger</div><h2>Recent public scans</h2></div><span>{scans.length} records</span></div>
          <div className="table-wrap"><table><thead><tr><th>Target</th><th>Account</th><th>Assessment</th><th>Score</th><th>Observed</th></tr></thead><tbody>{scans.map((scan) => <tr key={scan.job_id} onClick={() => inspect(scan)} className={selected?.job_id === scan.job_id ? "selected" : ""}><td><b>{scan.domain}</b><small>{scan.status}</small></td><td>{scan.user_email}</td><td><span className={`verdict ${scan.phishing?.verdict || "unknown"}`}>{verdictName(scan.phishing?.verdict)}</span></td><td>{scan.phishing?.risk_score ?? "—"}</td><td>{new Date(scan.created_at).toLocaleString()}</td></tr>)}</tbody></table></div>
        </article>
        <aside className="detail-panel"><div className="eyebrow">Selected operation</div>{selected ? <><h2>{selected.domain}</h2><div className="score"><strong>{selected.phishing?.risk_score ?? "—"}</strong><span>risk score</span></div><dl><div><dt>Verdict</dt><dd>{verdictName(selected.phishing?.verdict)}</dd></div><div><dt>Account</dt><dd>{selected.user_email}</dd></div><div><dt>Matched brand</dt><dd>{selected.phishing?.matched_brand || "None"}</dd></div><div><dt>Official URL</dt><dd>{selected.phishing?.official_url || "Not identified"}</dd></div></dl>{detail ? <details><summary>Raw intelligence record</summary><pre>{JSON.stringify(detail.data, null, 2)}</pre></details> : <div className="checking">Loading intelligence…</div>}</> : <div className="empty">Select a scan to inspect its stored intelligence.</div>}</aside>
      </section>
    </main>
  );
}
