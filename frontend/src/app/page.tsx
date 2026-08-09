"use client";

import { useEffect, useRef, useState } from "react";
import { createClient } from "@supabase/supabase-js";

type ReconResult = {
  domain: string;
  dns?: { A?: string[]; AAAA?: string[]; MX?: { exchange: string; priority: number }[] };
  ip_info?: { ip?: string; org?: string; city?: string; country?: string; region?: string };
  subdomains?: string[];
  ports?: { host?: string; protocol?: string; port?: number; state?: string; service?: string }[];
  whois?: {
    registrar?: string;
    creation_date?: string | string[] | null;
    expiration_date?: string | string[] | null;
    emails?: string | string[] | null;
  };
  technologies?: string[];
  phishing?: PhishingAssessment;
};

type PhishingSignal = {
  code: string;
  label: string;
  severity: "low" | "medium" | "high" | "critical";
  points: number;
};

type PhishingAssessment = {
  verdict: "known_phishing" | "high_risk" | "suspicious" | "no_indicators" | "unknown";
  risk_score: number;
  confidence: string;
  matched_brand?: string | null;
  canonical_domain?: string | null;
  official_url?: string | null;
  domain_age_days?: number | null;
  signals?: PhishingSignal[];
  threat_sources?: { source: string; status: string; matched: boolean }[];
  checked_at?: string;
  disclaimer?: string;
};

type ScanHistoryItem = {
  jobId: string;
  domain: string;
  createdAt: string;
  status?: string;
};

type ApiScanHistoryItem = {
  job_id: unknown;
  domain: unknown;
  created_at?: unknown;
  status?: unknown;
};

type AuthUser = { id: string; email: string };

const API_BASE = (
  process.env.NODE_ENV === "development"
    ? "/backend"
    : process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"
).replace(/\/$/, "");
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
const authConfigured = Boolean(supabaseUrl && supabaseKey);
const supabase = supabaseUrl && supabaseKey ? createClient(supabaseUrl, supabaseKey) : null;

const Dash = () => <span aria-hidden="true">—</span>;

export default function Page() {
  const [domain, setDomain] = useState("");
  const [accessToken, setAccessToken] = useState("");
  const [user, setUser] = useState<AuthUser | null>(null);
  const [showAuth, setShowAuth] = useState(false);
  const [authMode, setAuthMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [authLoading, setAuthLoading] = useState(false);
  const [authMessage, setAuthMessage] = useState<string | null>(null);
  const [apiState, setApiState] = useState<"checking" | "online" | "offline">("checking");
  const [jobId, setJobId] = useState<string | null>(null);
  const [status, setStatus] = useState<"idle" | "queued" | "running" | "completed" | "failed" | "error">("idle");
  const [result, setResult] = useState<ReconResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const activePoll = useRef<AbortController | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    void fetch(`${API_BASE}/health`, { signal: controller.signal })
      .then((response) => setApiState(response.ok ? "online" : "offline"))
      .catch(() => setApiState("offline"));

    if (!supabase) {
      return () => {
        controller.abort();
        activePoll.current?.abort();
      };
    }

    const authClient = supabase;
    void authClient.auth.getSession().then(({ data }) => {
      const session = data.session;
      if (!session?.user.email) return;
      setAccessToken(session.access_token);
      void establishAccount(session.access_token, session.user.id, session.user.email);
    });
    const { data: authListener } = authClient.auth.onAuthStateChange((_event, session) => {
      if (session?.user.email) {
        setAccessToken(session.access_token);
        void establishAccount(session.access_token, session.user.id, session.user.email);
      } else {
        setAccessToken("");
        setUser(null);
      }
    });
    return () => {
      activePoll.current?.abort();
      controller.abort();
      authListener.subscription.unsubscribe();
    };
    // The API history loader is intentionally invoked only during session restoration.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function authHeaders(token = accessToken) {
    return { Authorization: `Bearer ${token}` };
  }

  async function establishAccount(token: string, id: string, accountEmail: string) {
    setUser({ id, email: accountEmail });
    await fetchHistoryFromAPI(token);
  }

  async function fetchHistoryFromAPI(token = accessToken) {
    try {
      const res = await fetch(`${API_BASE}/scans`, { headers: authHeaders(token) });
      if (!res.ok) throw new Error(`History request failed with ${res.status}`);
      const data = (await res.json()) as unknown;
      if (!Array.isArray(data)) return;
      const formatted = (data as ApiScanHistoryItem[]).map((item) => ({
        jobId: String(item.job_id),
        domain: String(item.domain),
        createdAt: item.created_at ? String(item.created_at) : new Date().toISOString(),
        status: item.status ? String(item.status) : undefined,
      }));
      setHistory(formatted.slice(0, 20));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function submitAuth() {
    if (!supabase) {
      setError("Supabase authentication is not configured for this environment.");
      return;
    }
    if (!email.trim() || password.length < 10) return;
    setAuthLoading(true);
    setError(null);
    setAuthMessage(null);
    try {
      if (authMode === "register") {
        const { data, error: signUpError } = await supabase.auth.signUp({
          email: email.trim(),
          password,
          options: { emailRedirectTo: window.location.origin },
        });
        if (signUpError) throw signUpError;
        setPassword("");

        const accountAlreadyExists =
          data.user &&
          Array.isArray(data.user.identities) &&
          data.user.identities.length === 0;

        if (accountAlreadyExists) {
          setAuthMode("login");
          setAuthMessage(
            "An account with this email already exists. Sign in with your password instead.",
          );
          return;
        }

        if (!data.session) {
          setAuthMessage("Check your inbox and verify your email before signing in.");
          return;
        }
      } else {
        const { data, error: signInError } = await supabase.auth.signInWithPassword({
          email: email.trim(),
          password,
        });
        if (signInError) throw signInError;
        if (!data.session || !data.user.email) throw new Error("Unable to establish a verified session");
        setAccessToken(data.session.access_token);
        await establishAccount(data.session.access_token, data.user.id, data.user.email);
        setPassword("");
        setShowAuth(false);
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setAuthLoading(false);
    }
  }

  async function logout() {
    activePoll.current?.abort();
    await supabase?.auth.signOut();
    setAccessToken("");
    setUser(null);
    setHistory([]);
    setResult(null);
    setJobId(null);
    setStatus("idle");
  }

  function saveToHistory(id: string, target: string, nextStatus = "running") {
    setHistory((current) => [
      { jobId: id, domain: target, createdAt: new Date().toISOString(), status: nextStatus },
      ...current.filter((item) => item.jobId !== id),
    ].slice(0, 20));
  }

  function updateHistoryStatus(id: string, nextStatus: string) {
    setHistory((current) => current.map((item) => item.jobId === id ? { ...item, status: nextStatus } : item));
  }

  async function pollResults(id: string, token = accessToken) {
    activePoll.current?.abort();
    const controller = new AbortController();
    activePoll.current = controller;
    try {
      while (!controller.signal.aborted) {
        const res = await fetch(`${API_BASE}/results/${id}`, {
          headers: authHeaders(token),
          signal: controller.signal,
        });
        if (!res.ok) throw new Error(`Results request failed with ${res.status}`);
        const data = (await res.json()) as { status: string; data?: ReconResult };
        if (data.status === "completed") {
          setResult(data.data ?? null);
          setStatus("completed");
          updateHistoryStatus(id, "completed");
          return;
        }
        if (data.status === "failed") {
          setStatus("failed");
          updateHistoryStatus(id, "failed");
          return;
        }
        if (data.status !== "queued" && data.status !== "running") throw new Error("Unexpected scan status returned by backend");
        setStatus(data.status);
        updateHistoryStatus(id, data.status);
        await new Promise<void>((resolve) => window.setTimeout(resolve, 3000));
      }
    } catch (e) {
      if (controller.signal.aborted) return;
      setStatus("error");
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function startScan() {
    const target = domain.trim();
    if (!accessToken || !user) {
      setShowAuth(true);
      setError("Sign in or create an account to launch a scan.");
      return;
    }
    if (!target) return;
    setError(null);
    setResult(null);
    setStatus("running");
    setJobId(null);
    try {
      const res = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({ domain: target }),
      });
      if (!res.ok) {
        const payload = await res.json().catch(() => null) as { detail?: string } | null;
        throw new Error(payload?.detail || `Scan request failed with ${res.status}`);
      }
      const job = (await res.json()) as { job_id?: string; status?: "queued" | "running" };
      if (!job.job_id) throw new Error("Backend response did not include a job ID");
      const initialStatus = job.status === "queued" ? "queued" : "running";
      setStatus(initialStatus);
      setJobId(job.job_id);
      saveToHistory(job.job_id, target, initialStatus);
      void pollResults(job.job_id);
    } catch (e) {
      setStatus("error");
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  function loadScan(item: ScanHistoryItem) {
    if (!accessToken || !user) {
      setShowAuth(true);
      setError("Sign in to load your stored results.");
      return;
    }
    setDomain(item.domain);
    setJobId(item.jobId);
    setResult(null);
    setError(null);
    setStatus("running");
    void pollResults(item.jobId);
  }

  function closeOperation() {
    activePoll.current?.abort();
    setDomain("");
    setJobId(null);
    setResult(null);
    setError(null);
    setStatus("idle");
  }

  function loadPhishingDemo() {
    activePoll.current?.abort();
    setDomain("paypa1-secure-login.example");
    setJobId("local-demo");
    setError(null);
    setStatus("completed");
    setResult({
      domain: "paypa1-secure-login.example",
      dns: {},
      ip_info: {},
      subdomains: [],
      ports: [],
      technologies: [],
      whois: {},
      phishing: {
        verdict: "suspicious",
        risk_score: 44,
        confidence: "medium",
        matched_brand: "PayPal",
        canonical_domain: "paypal.com",
        official_url: "https://paypal.com",
        signals: [
          { code: "brand_lookalike", label: "Domain closely resembles PayPal", severity: "high", points: 35 },
          { code: "suspicious_terms", label: "Contains urgent login or security language", severity: "medium", points: 9 },
        ],
        threat_sources: [{ source: "Google Web Risk", status: "not_configured", matched: false }],
        checked_at: new Date().toISOString(),
        disclaimer: "Automated risk assessment only. Verify suspicious domains through trusted security channels.",
      },
    });
    window.setTimeout(() => document.getElementById("results")?.scrollIntoView({ behavior: "smooth", block: "start" }), 0);
  }

  function downloadReport() {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `cyberrecon-${result.domain}-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(url);
  }

  const dns = result?.dns ?? {};
  const ip = result?.ip_info ?? {};
  const ports = result?.ports ?? [];
  const whois = result?.whois ?? {};
  const subdomains = result?.subdomains ?? [];
  const technologies = result?.technologies ?? [];
  const finished = history.filter((item) => item.status === "completed").length;
  const active = history.filter((item) => item.status === "queued" || item.status === "running").length;
  const activeScan = status === "queued" || status === "running";
  const dateValue = (value?: string | string[] | null) => Array.isArray(value) ? value[0] : value;

  return (
    <main className="app-shell">
      <header className="topbar">
        <a className="brand" href="#top" aria-label="CyberRecon home">
          <span className="brand-mark">CR</span>
          <span><strong>CyberRecon</strong><small>Threat Intelligence Console</small></span>
        </a>
        <nav className="topnav" aria-label="Primary navigation">
          <a className="active" href="#overview">Overview</a>
          <a href="#history">Scan history</a>
          <a href="#results">Intelligence</a>
        </nav>
        <div className="top-actions">
          <span className={`system-pill ${apiState}`}><i /> API {apiState}</span>
          {user ? (
            <div className="account-actions">
              <span className="account-email">{user.email}</span>
              <button className="secondary-button" onClick={logout}>Sign out</button>
            </div>
          ) : (
            <button className="secondary-button" onClick={() => setShowAuth(true)} disabled={!authConfigured}>Sign in</button>
          )}
        </div>
      </header>

      {showAuth && (
        <aside className="settings-panel auth-panel" aria-label="Account access">
          <div><span className="eyebrow">Secure access</span><h2>{authMode === "login" ? "Sign in" : "Create account"}</h2></div>
          <button className="close-button" onClick={() => setShowAuth(false)} aria-label="Close account panel">×</button>
          <p>{authConfigured ? "Email verification is required before any account can run scans." : "Add the Supabase public URL and publishable key to frontend/.env.local, then restart the frontend."}</p>
          {authMessage && <div className="auth-message" role="status">{authMessage}</div>}
          <div className="auth-tabs" role="tablist" aria-label="Account action">
            <button className={authMode === "login" ? "active" : ""} onClick={() => setAuthMode("login")}>Sign in</button>
            <button className={authMode === "register" ? "active" : ""} onClick={() => setAuthMode("register")}>Register</button>
          </div>
          <label htmlFor="account-email">Email address</label>
          <input id="account-email" type="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@example.com" autoComplete="email" />
          <label htmlFor="account-password">Password</label>
          <input id="account-password" type="password" value={password} onChange={(event) => setPassword(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") void submitAuth(); }} placeholder="At least 10 characters" autoComplete={authMode === "login" ? "current-password" : "new-password"} />
          <button className="primary-button full" onClick={submitAuth} disabled={!authConfigured || authLoading || !email.trim() || password.length < 10}>
            {authLoading ? "Please wait…" : authMode === "login" ? "Sign in securely" : "Create account"}
          </button>
          <small className="auth-note">A real inbox is required. Limited to five authorized public-domain scans per hour.</small>
        </aside>
      )}

      <section className="hero" id="top">
        <div>
          <span className="eyebrow">Reconnaissance workspace</span>
          <h1>Map your external attack surface.</h1>
          <p>Run passive intelligence and targeted service discovery from one operational view.</p>
        </div>
        <div className="hero-signal"><span className="radar"><i /></span><div><strong>{activeScan ? (status === "queued" ? "Scan queued" : "Scan in progress") : "System ready"}</strong><small>{activeScan ? domain : "Awaiting target"}</small></div></div>
      </section>

      <section className="command-card" id="overview">
        <div className="command-label"><span>01</span><div><strong>Launch reconnaissance</strong><small>Enter an authorized public domain</small></div></div>
        <div className="target-input">
          <span>⌖</span>
          <input value={domain} onChange={(e) => setDomain(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") void startScan(); }} placeholder="example.com" aria-label="Target domain" />
        </div>
        <button className="primary-button" onClick={startScan} disabled={!domain.trim() || activeScan}>
          {activeScan ? <><span className="spinner" /> {status === "queued" ? "Queued" : "Scanning"}</> : <>Start scan <span>→</span></>}
        </button>
      </section>

      {process.env.NODE_ENV === "development" && <div className="demo-notice"><span>Local preview</span><p>Inspect the phishing warning safely with a fictional reserved domain.</p><button className="secondary-button" onClick={loadPhishingDemo}>View phishing demo</button></div>}

      {error && <div className="alert"><strong>Request interrupted</strong><span>{error}</span><button onClick={() => setError(null)}>×</button></div>}

      {!authConfigured && <div className="configuration-notice" role="status"><strong>Local authentication setup required</strong><span>Supabase public configuration is missing. The dashboard is available for review, but account access and scans remain disabled until frontend/.env.local is configured.</span></div>}

      <section className="metrics-grid">
        <article><span className="metric-icon violet">◎</span><div><small>Total scans</small><strong>{history.length.toString().padStart(2, "0")}</strong><em>Last 20 retained</em></div></article>
        <article><span className="metric-icon green">✓</span><div><small>Completed</small><strong>{finished.toString().padStart(2, "0")}</strong><em>Results available</em></div></article>
        <article><span className="metric-icon cyan">↻</span><div><small>Active jobs</small><strong>{active.toString().padStart(2, "0")}</strong><em>Polling every 3 sec</em></div></article>
        <article><span className="metric-icon amber">◈</span><div><small>Assets found</small><strong>{result ? subdomains.length + ports.length : 0}</strong><em>Current target</em></div></article>
      </section>

      <div className="workspace-grid">
        <aside className="history-panel" id="history">
          <div className="section-heading"><div><span className="eyebrow">Activity</span><h2>Recent scans</h2></div><span className="count-badge">{history.length}</span></div>
          <div className="history-list">
            {history.length === 0 ? <div className="empty-compact"><span>⌁</span><p>No scans recorded yet.</p></div> : history.map((item) => (
              <button key={item.jobId} className={`history-item ${jobId === item.jobId ? "selected" : ""}`} onClick={() => loadScan(item)}>
                <span className={`status-dot ${item.status || "stored"}`} />
                <span className="history-copy"><strong>{item.domain}</strong><small>{new Date(item.createdAt).toLocaleString()}</small></span>
                <span className="history-state">{item.status || "stored"}</span>
                <span className="history-arrow">›</span>
              </button>
            ))}
          </div>
        </aside>

        <section className="intel-panel" id="results">
          <div className="section-heading intel-heading">
            <div><span className="eyebrow">Current operation</span><h2>{result?.domain || domain || "Intelligence report"}</h2></div>
            <div className="job-meta"><span className={`status-chip ${status}`}>{status === "running" && <i />}{status}</span>{jobId && <code>{jobId.slice(0, 8)}…</code>}{result && <button className="operation-button" onClick={downloadReport}>Export JSON</button>}{(result || jobId) && <button className="operation-button danger" onClick={closeOperation}>Close operation</button>}</div>
          </div>

          {!result ? (
            <div className="empty-report"><div className="scan-orbit"><span>⌖</span><i /><b /></div><h3>{activeScan ? (status === "queued" ? "Waiting for a scan worker" : "Building intelligence profile") : "No report selected"}</h3><p>{activeScan ? (status === "queued" ? "The durable queue accepted this scan and will start it shortly." : "DNS, WHOIS, service and technology probes are running.") : "Launch a scan or choose a previous target to populate this workspace."}</p></div>
          ) : (
            <div className="report-grid">
              {result.phishing && (
                <article className={`report-card phishing-card wide-card ${result.phishing.verdict}`}>
                  <CardHeader icon="!" label="Phishing risk assessment" count={`${result.phishing.risk_score}/100`} />
                  <div className="phishing-overview">
                    <div className="risk-gauge"><strong>{result.phishing.risk_score}</strong><span>risk score</span></div>
                    <div className="risk-copy">
                      <span className={`verdict-chip ${result.phishing.verdict}`}>{verdictLabel(result.phishing.verdict)}</span>
                      <h3>{phishingHeadline(result.phishing)}</h3>
                      <p>{phishingGuidance(result.phishing)}</p>
                    </div>
                  </div>
                  {result.phishing.official_url && (
                    <div className="official-site"><span>Verified official website</span><a href={result.phishing.official_url} target="_blank" rel="noreferrer">{result.phishing.official_url}</a><small>Open the verified address directly instead of continuing on a lookalike domain.</small></div>
                  )}
                  <div className="signal-list">
                    {result.phishing.signals?.length ? result.phishing.signals.map((signal) => <div key={signal.code}><i className={signal.severity} /><span>{signal.label}</span><b>+{signal.points}</b></div>) : <div><i className="low" /><span>No deterministic phishing indicators were found.</span><b>0</b></div>}
                  </div>
                  <small className="risk-disclaimer">{result.phishing.disclaimer}</small>
                </article>
              )}

              <article className="report-card summary-card">
                <CardHeader icon="⌖" label="Target profile" count="01" />
                <div className="target-title"><span>{result.domain.slice(0, 2).toUpperCase()}</span><div><strong>{result.domain}</strong><small>{ip.org || "Organization unavailable"}</small></div></div>
                <dl className="detail-grid"><Detail label="IP address" value={ip.ip} /><Detail label="Location" value={[ip.city, ip.region, ip.country].filter(Boolean).join(", ")} /><Detail label="Country" value={ip.country} /></dl>
              </article>

              <article className="report-card">
                <CardHeader icon="≋" label="DNS records" count={String((dns.A?.length || 0) + (dns.AAAA?.length || 0) + (dns.MX?.length || 0)).padStart(2, "0")} />
                <RecordList label="A" items={dns.A} />
                <RecordList label="AAAA" items={dns.AAAA} />
                <RecordList label="MX" items={dns.MX?.map((mx) => `${mx.exchange} · priority ${mx.priority}`)} />
              </article>

              <article className="report-card">
                <CardHeader icon="◫" label="Open services" count={String(ports.length).padStart(2, "0")} />
                {ports.length ? <div className="port-list">{ports.map((port, index) => <div key={`${port.host}-${port.port}-${index}`}><span className="port-number">{port.port}</span><span><strong>{port.service || "Unknown service"}</strong><small>{port.host} · {port.protocol || "tcp"}</small></span><em>{port.state || "unknown"}</em></div>)}</div> : <EmptyCard text="No open ports detected" />}
              </article>

              <article className="report-card">
                <CardHeader icon="◉" label="WHOIS intelligence" count="04" />
                <dl className="stacked-details"><Detail label="Registrar" value={whois.registrar} /><Detail label="Created" value={dateValue(whois.creation_date)} /><Detail label="Expires" value={dateValue(whois.expiration_date)} /><Detail label="Contact" value={Array.isArray(whois.emails) ? whois.emails.join(", ") : whois.emails} /></dl>
              </article>

              <article className="report-card wide-card">
                <CardHeader icon="⌘" label="Discovered subdomains" count={String(subdomains.length).padStart(2, "0")} />
                {subdomains.length ? <div className="asset-cloud">{subdomains.map((item) => <span key={item}>{item}</span>)}</div> : <EmptyCard text="No subdomains discovered" />}
              </article>

              <article className="report-card">
                <CardHeader icon="◇" label="Technology stack" count={String(technologies.length).padStart(2, "0")} />
                {technologies.length ? <div className="tech-list">{technologies.map((item) => <span key={item}><i />{item}</span>)}</div> : <EmptyCard text="No technologies detected" />}
              </article>
            </div>
          )}
        </section>
      </div>
      <footer><span>CyberRecon <b>v1.0</b></span><span>Authorized security testing only</span><span><i /> Secure session</span></footer>
    </main>
  );
}

function CardHeader({ icon, label, count }: { icon: string; label: string; count: string }) {
  return <header className="card-header"><span className="card-icon">{icon}</span><h3>{label}</h3><em>{count}</em></header>;
}

function Detail({ label, value }: { label: string; value?: string | null }) {
  return <div><dt>{label}</dt><dd>{value || <Dash />}</dd></div>;
}

function RecordList({ label, items }: { label: string; items?: string[] }) {
  return <div className="record-group"><span>{label}</span><div>{items?.length ? items.map((item) => <code key={item}>{item}</code>) : <Dash />}</div></div>;
}

function EmptyCard({ text }: { text: string }) {
  return <div className="empty-card"><span>∅</span><p>{text}</p></div>;
}

function verdictLabel(verdict?: PhishingAssessment["verdict"]) {
  return ({
    known_phishing: "Known phishing",
    high_risk: "High risk",
    suspicious: "Suspicious",
    no_indicators: "No indicators",
    unknown: "Not assessed",
  } as const)[verdict || "unknown"];
}

function phishingHeadline(assessment: PhishingAssessment) {
  if (assessment.matched_brand) return `Possible ${assessment.matched_brand} impersonation detected`;
  if (assessment.verdict === "known_phishing") return "Threat intelligence identifies this website as unsafe";
  if (assessment.verdict === "no_indicators") return "No phishing indicators were detected";
  return "This domain deserves additional verification";
}

function phishingGuidance(assessment: PhishingAssessment) {
  if (assessment.verdict === "known_phishing" || assessment.verdict === "high_risk") return "Do not enter passwords, payment details, recovery codes, or personal information on the scanned website.";
  if (assessment.verdict === "suspicious") return "Verify the organization through a trusted source before opening the website or sharing sensitive information.";
  return "A clean automated assessment is not a guarantee of safety. Continue to verify unexpected links independently.";
}
