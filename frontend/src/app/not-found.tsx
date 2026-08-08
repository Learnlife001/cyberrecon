import Link from "next/link";

export default function NotFound() {
  return (
    <main className="system-page">
      <span className="brand-mark">CR</span>
      <p className="eyebrow">404 / Unknown route</p>
      <h1>This operation does not exist.</h1>
      <p>Return to the CyberRecon workspace to launch or review an authorized scan.</p>
      <Link className="primary-button" href="/">Return to dashboard</Link>
    </main>
  );
}
