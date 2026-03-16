# CyberRecon Frontend

Minimal Next.js (TypeScript) dashboard for the CyberRecon FastAPI backend.

## Configure API base URL

Set `NEXT_PUBLIC_API_BASE_URL` to your FastAPI server base URL (no trailing slash).

Example (PowerShell):

```powershell
$env:NEXT_PUBLIC_API_BASE_URL="http://localhost:8000"
npm run dev
```

## Run

```bash
npm install
npm run dev
```

Then open the dev server URL and use the single-page dashboard to start a scan and poll results.

