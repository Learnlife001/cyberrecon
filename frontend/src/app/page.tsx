"use client";

import { useState } from "react";

type ReconResult = {
  domain: string;
  dns?: {
    A?: string[];
    AAAA?: string[];
    MX?: { exchange: string; priority: number }[];
    [key: string]: unknown;
  };
  ip_info?: {
    ip?: string;
    org?: string;
    city?: string;
    country?: string;
    [key: string]: unknown;
  };
  subdomains?: string[];
  ports?: {
    host?: string;
    host_state?: string;
    protocol?: string;
    port?: number;
    state?: string;
    service?: string;
  }[];
  whois?: {
    registrar?: string;
    creation_date?: string | string[] | null;
    expiration_date?: string | string[] | null;
    emails?: string | string[] | null;
    [key: string]: unknown;
  };
  technologies?: string[];
  [key: string]: unknown;
};

const API_BASE =
  process.env.NEXT_PUBLIC_API_URL || "https://cyberrecon-jfiu.onrender.com";

export default function Page() {
  const [domain, setDomain] = useState("");
  const [jobId, setJobId] = useState<string | null>(null);
  const [status, setStatus] = useState<
    "idle" | "running" | "completed" | "failed" | "error"
  >("idle");
  const [result, setResult] = useState<ReconResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const pollResults = async (id: string) => {
    try {
      const res = await fetch(`${API_BASE}/results/${id}`);
      const data = (await res.json()) as {
        status: string;
        data?: ReconResult;
      };

      if (data.status === "completed") {
        setResult(data.data ?? null);
        setStatus("completed");
        return;
      }

      if (data.status === "running") {
        setTimeout(() => pollResults(id), 3000);
      }

      if (data.status === "failed") {
        setStatus("failed");
      }
    } catch (e) {
      setStatus("error");
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  async function startScan() {
    const trimmed = domain.trim();
    if (!trimmed) return;

    setError(null);
    setResult(null);
    setStatus("running");
    setJobId(null);

    console.log("API_BASE:", API_BASE);
    console.log("Sending request to:", `${API_BASE}/scan`);

    const attempt = async () => {
      const res = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ domain: trimmed }),
      });

      if (!res.ok) {
        throw new Error(`Server responded with ${res.status}`);
      }

      const job = (await res.json()) as { job_id?: string; status?: string };
      const jobIdFromApi = job.job_id;

      if (!jobIdFromApi) {
        throw new Error("Missing job_id in response.");
      }

      setJobId(jobIdFromApi);
      pollResults(jobIdFromApi);
    };

    try {
      await attempt();
    } catch (err) {
      console.error("Scan request failed, retrying once...", err);
      try {
        await attempt();
      } catch (err2) {
        console.error("Scan request failed after retry:", err2);
        setStatus("error");
        setError(
          "Scan request failed. The backend may be starting up. Please try again in a few seconds.",
        );
      }
    }
  }

  const dns = result?.dns ?? {};
  const ip = result?.ip_info ?? {};
  const ports = result?.ports ?? [];
  const whois = result?.whois ?? {};
  const subdomains = result?.subdomains ?? [];
  const technologies = result?.technologies ?? [];

  return (
    <main className="min-h-screen px-4 py-6 md:px-8 lg:px-12">
      <div className="max-w-6xl mx-auto">
        <h1 className="text-2xl font-bold mb-4">CyberRecon Dashboard</h1>

        <div className="flex flex-col sm:flex-row gap-3 items-stretch sm:items-center">
          <input
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="example.com"
            className="flex-1 rounded-md border border-slate-300 px-3 py-2 text-sm shadow-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 bg-white"
          />
          <button
            onClick={startScan}
            disabled={!domain.trim() || status === "running"}
            className="inline-flex items-center justify-center rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Start Scan
          </button>
        </div>

        <div className="mt-4 flex flex-wrap items-center gap-3 text-sm text-slate-700">
          <span>
            <span className="font-semibold">Status:</span> {status}
          </span>
          {jobId && (
            <span className="text-xs bg-slate-200 rounded-full px-3 py-1">
              job_id: <code>{jobId}</code>
            </span>
          )}
        </div>

        {error && (
          <div className="mt-4 rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-800">
            {error}
          </div>
        )}

        {status === "completed" && result && (
          <section className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mt-6">
            {/* Domain Summary Card */}
            <div className="p-4 border rounded-xl shadow bg-white">
              <h2 className="font-bold text-lg mb-2">Domain Summary</h2>
              <dl className="space-y-1 text-sm">
                <div>
                  <dt className="font-semibold">Domain</dt>
                  <dd>{result.domain}</dd>
                </div>
                <div>
                  <dt className="font-semibold">IP Address</dt>
                  <dd>{ip.ip ?? "—"}</dd>
                </div>
                <div>
                  <dt className="font-semibold">Organization</dt>
                  <dd>{ip.org ?? "—"}</dd>
                </div>
                <div>
                  <dt className="font-semibold">City</dt>
                  <dd>{ip.city ?? "—"}</dd>
                </div>
                <div>
                  <dt className="font-semibold">Country</dt>
                  <dd>{ip.country ?? "—"}</dd>
                </div>
              </dl>
            </div>

            {/* DNS Records Card */}
            <div className="p-4 border rounded-xl shadow bg-white">
              <h2 className="font-bold text-lg mb-2">DNS Records</h2>
              <div className="space-y-2 text-sm">
                <div>
                  <div className="font-semibold">A</div>
                  <ul className="list-disc list-inside">
                    {(dns.A as string[] | undefined)?.length
                      ? (dns.A as string[]).map((a) => <li key={a}>{a}</li>)
                      : "—"}
                  </ul>
                </div>
                <div>
                  <div className="font-semibold">AAAA</div>
                  <ul className="list-disc list-inside">
                    {(dns.AAAA as string[] | undefined)?.length
                      ? (dns.AAAA as string[]).map((a) => <li key={a}>{a}</li>)
                      : "—"}
                  </ul>
                </div>
                <div>
                  <div className="font-semibold">MX</div>
                  <ul className="list-disc list-inside">
                    {(dns.MX as { exchange: string; priority: number }[] | undefined)
                      ?.length
                      ? (
                          dns.MX as {
                            exchange: string;
                            priority: number;
                          }[]
                        ).map((mx) => (
                          <li key={`${mx.exchange}-${mx.priority}`}>
                            {mx.exchange} (prio {mx.priority})
                          </li>
                        ))
                      : "—"}
                  </ul>
                </div>
              </div>
            </div>

            {/* Open Ports Card */}
            <div className="p-4 border rounded-xl shadow bg-white">
              <h2 className="font-bold text-lg mb-2">Open Ports</h2>
              <div className="space-y-1 text-xs md:text-sm max-h-64 overflow-auto">
                {ports.length === 0 ? (
                  <div className="text-slate-500">No open ports detected or scan failed.</div>
                ) : (
                  ports.map((p, idx) => (
                    <div
                      key={`${p.host}-${p.port}-${p.protocol}-${idx}`}
                      className="flex justify-between border-b border-slate-100 py-1"
                    >
                      <div>
                        <div className="font-semibold">
                          {p.port} / {p.protocol ?? "tcp"}
                        </div>
                        <div className="text-slate-600 text-xs">
                          {p.service ?? "unknown"} ({p.state ?? "unknown"})
                        </div>
                      </div>
                      <div className="text-xs text-slate-500 text-right">
                        {p.host}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* WHOIS Card */}
            <div className="p-4 border rounded-xl shadow bg-white">
              <h2 className="font-bold text-lg mb-2">WHOIS</h2>
              <dl className="space-y-1 text-sm">
                <div>
                  <dt className="font-semibold">Registrar</dt>
                  <dd>{(whois.registrar as string) ?? "—"}</dd>
                </div>
                <div>
                  <dt className="font-semibold">Creation Date</dt>
                  <dd>
                    {Array.isArray(whois.creation_date)
                      ? (whois.creation_date[0] as string)
                      : (whois.creation_date as string | null) ?? "—"}
                  </dd>
                </div>
                <div>
                  <dt className="font-semibold">Expiration Date</dt>
                  <dd>
                    {Array.isArray(whois.expiration_date)
                      ? (whois.expiration_date[0] as string)
                      : (whois.expiration_date as string | null) ?? "—"}
                  </dd>
                </div>
                <div>
                  <dt className="font-semibold">Emails</dt>
                  <dd>
                    {Array.isArray(whois.emails)
                      ? (whois.emails as string[]).join(", ")
                      : (whois.emails as string | null) ?? "—"}
                  </dd>
                </div>
              </dl>
            </div>

            {/* Subdomains Card */}
            <div className="p-4 border rounded-xl shadow bg-white">
              <h2 className="font-bold text-lg mb-2">Subdomains</h2>
              {subdomains.length === 0 ? (
                <div className="text-sm text-slate-500">No subdomains found.</div>
              ) : (
                <div className="max-h-64 overflow-auto">
                  <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2 text-xs">
                    {subdomains.map((s) => (
                      <div
                        key={s}
                        className="truncate rounded border border-slate-200 px-2 py-1 bg-slate-50"
                      >
                        {s}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Technologies Card */}
            <div className="p-4 border rounded-xl shadow bg-white">
              <h2 className="font-bold text-lg mb-2">Technologies</h2>
              {technologies.length === 0 ? (
                <div className="text-sm text-slate-500">No technologies detected.</div>
              ) : (
                <div className="flex flex-wrap gap-2 text-xs">
                  {technologies.map((t) => (
                    <span
                      key={t}
                      className="rounded-full bg-indigo-50 px-3 py-1 text-indigo-700 border border-indigo-100"
                    >
                      {t}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </section>
        )}
      </div>
    </main>
  );
}

