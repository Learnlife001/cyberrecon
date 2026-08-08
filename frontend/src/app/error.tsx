"use client";

export default function ErrorPage({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <main className="system-page">
      <span className="brand-mark">CR</span>
      <p className="eyebrow">Operation interrupted</p>
      <h1>The intelligence console encountered an error.</h1>
      <p>Your scan data was not changed. Retry the interface or return after checking the API status.</p>
      <button className="primary-button" onClick={reset}>Retry console</button>
    </main>
  );
}
