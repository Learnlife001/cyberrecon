# CyberRecon

CyberRecon is a full-stack, asynchronous reconnaissance platform for security learning and authorized assessments. It combines a Next.js operations dashboard with a FastAPI API, a durable Redis/Celery job queue, PostgreSQL persistence, and containerized deployment.

> Only scan domains and systems that you own or are explicitly authorized to assess.

## Live deployment

- **Application:** [cgreglab.space](https://cgreglab.space)
- **Administration:** [admin.cgreglab.space](https://admin.cgreglab.space) (approved administrators only)
- **Frontend:** Next.js on Vercel
- **API:** FastAPI on Render
- **Authentication:** Supabase Auth with verified-email accounts
- **Database:** PostgreSQL

The production browser application uses Supabase access tokens; private scan API keys and database credentials are never shipped to the frontend.

## What it demonstrates

- Automated DNS, WHOIS, IP, subdomain, port, and technology discovery
- Explainable phishing-risk scoring with verified-brand comparison, bounded source inspection, and optional Google Web Risk intelligence
- Protected administrator intelligence showing scanned domains, users, risk scores, evidence, and official-site guidance
- Durable background jobs with queued, running, completed, and failed states
- Persistent scan history and structured results in PostgreSQL
- Verified-email registration through Supabase Auth, short-lived JWT authentication, per-user authorization, and rate limiting
- Live API health reporting, downloadable JSON reports, and explicit operation cleanup
- Protection against scans of private, loopback, link-local, and reserved networks
- Dockerized API, worker, PostgreSQL, and Redis services
- Automated backend tests, frontend checks, dependency audits, and container builds

## Architecture

```mermaid
flowchart LR
    U[Analyst] --> UI[Next.js dashboard]
    A[Administrator] --> ADMIN[Separate Next.js admin console]
    U -->|register / sign in| AUTH[Supabase Auth]
    AUTH -->|verified JWT| UI
    UI -->|Bearer JWT| API[FastAPI API]
    ADMIN -->|Bearer JWT plus admin role| API
    API --> DB[(PostgreSQL)]
    API --> Q[(Redis queue)]
    Q --> W[Celery worker]
    W --> R[Recon modules]
    R --> DNS[DNS / WHOIS / IP APIs]
    R --> NMAP[Nmap]
    W --> DB
    UI -->|poll job status| API
```

The API validates and queues each request. In the Docker deployment, a separate Celery worker performs the reconnaissance and stores its results in PostgreSQL, so API restarts do not silently discard queued work. Production can use the simpler `inprocess` mode configured by the Render blueprint. The public dashboard polls the API and renders current status, intelligence panels, and the signed-in user's scan history. A separately deployed administrator application shows cross-user intelligence only after the API independently verifies the administrator role; no administrator interface or data-fetching code is shipped in the public bundle.

## Technology stack

| Layer | Technologies |
| --- | --- |
| Frontends | Two isolated Next.js, React, and TypeScript applications |
| API | Python, FastAPI, SQLAlchemy, Uvicorn |
| Jobs | Celery, Redis |
| Data | PostgreSQL |
| Recon | Nmap, DNS, RDAP/WHOIS, certificate transparency, IP and phishing intelligence |
| Delivery | Vercel, Render, Docker Compose, GitHub Actions |

## Run the production-style stack locally

Requirements: Docker Desktop and Docker Compose.

```powershell
git clone https://github.com/Learnlife001/cyberrecon.git
cd cyberrecon
Copy-Item .env.example .env
```

Set `SCAN_API_KEY` and your Supabase project URL in `.env`, then start the services:

```powershell
docker compose up --build -d
docker compose ps
```

The API is available at `http://localhost:8000`, with interactive documentation at `http://localhost:8000/docs`. Configure the frontend separately:

```powershell
Set-Location frontend
Copy-Item .env.example .env.local
npm install
npm run dev -- --port 3001
```

Add the Supabase URL and publishable browser key to `frontend/.env.local`. Open `http://localhost:3001`, register with a real email address, follow the confirmation link, and then sign in. If the address is already registered, use **Sign in** instead of waiting for another confirmation message. The API key remains an administrative fallback and is never embedded in the browser application.

To run the isolated administrator console, copy its `.env.example` to `.env.local`, set the same three public values, and run `npm run dev -- --port 3002` from `admin-frontend`. Only accounts listed in the backend `ADMIN_EMAILS` setting (or trusted JWT `app_metadata`) are admitted.

If port 8000 is already occupied, set `API_PORT` in `.env`, for example `API_PORT=8002`.

## Configuration

The root `.env.example` documents all backend settings. The important production values are:

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | PostgreSQL connection string |
| `REDIS_URL` | Redis broker used by Celery |
| `TASK_QUEUE_MODE` | Use `celery` for durable jobs or `inprocess` for development |
| `SCAN_API_KEY` | Secret required in the `X-API-Key` header |
| `SUPABASE_URL` | Supabase project URL used to validate verified-user JWTs |
| `ALLOWED_ORIGINS` | Comma-separated trusted frontend origins |
| `SCAN_RATE_LIMIT` | Maximum scan submissions per rate window |
| `NMAP_PATH` | Optional explicit path to the Nmap executable |
| `GOOGLE_WEB_RISK_API_KEY` | Optional server-side reputation feed for known phishing and malware URLs |
| `ADMIN_EMAILS` | Comma-separated verified accounts permitted to open the administrator dashboard |

The frontend uses these public build-time values:

| Variable | Purpose |
| --- | --- |
| `NEXT_PUBLIC_API_URL` | Public HTTPS URL of the FastAPI service |
| `NEXT_PUBLIC_SUPABASE_URL` | Public Supabase project URL |
| `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` | Supabase browser publishable key |

`NEXT_PUBLIC_*` values are visible in the browser and must never contain service-role credentials. All private secrets are loaded from the backend environment and must never be committed. Local `.env` files and Vercel project metadata are excluded from Git, and environment files are excluded from the Docker build context.

## Deployment

The `main` branch is the production source branch. The public frontend is linked to the Vercel `cyberrecon` project and served through `cgreglab.space`; the isolated `admin-frontend` is deployed as the separate `cyberrecon-admin` project through `admin.cgreglab.space`. The backend configuration is declared in `render.yaml`, including both trusted production origins.

Before deploying, configure the following in the provider dashboards:

1. Set the three frontend `NEXT_PUBLIC_*` values in both Vercel projects.
2. Set the backend database, scan API key, Supabase URL, allowed origins, administrator emails, and optional Google Web Risk key in Render.
3. Configure confirmation-email SMTP credentials only in **Supabase Auth → Emails → SMTP Settings**.
4. Deploy from `main`, then verify `/health`, account confirmation, sign-in, and an authorized scan.

## API workflow

1. Supabase Auth registers the account and sends an email-confirmation link.
2. Only a confirmed email can create a Supabase session and receive an access token.
3. `POST /scan` validates the target, applies the account rate limit, and returns a job identifier.
4. Redis holds the durable task until a Celery worker accepts it.
5. `GET /results/{job_id}` reports `queued`, `running`, `completed`, or `failed` for scans owned by that user.
6. `GET /scans` returns the authenticated user's persistent scan history.
7. `GET /health` reports database health and the configured queue mode.
8. `GET /admin/scans` gives configured administrators a cross-user scan and phishing-intelligence view.

User-facing protected endpoints require:

```http
Authorization: Bearer your-short-lived-token
```

Administrative automation may instead use the private `X-API-Key` value.

## Security controls

- Domains are normalized and resolved before scanning.
- Targets resolving to non-public address ranges are rejected.
- Passwords and email confirmation are handled by Supabase Auth and are never stored by the CyberRecon API.
- The API validates Supabase JWT signatures, issuer, audience, and expiration against the project's JWKS endpoint.
- Scan results and history are restricted to their owning account.
- Administrator access uses trusted JWT `app_metadata` or the server-only `ADMIN_EMAILS` allowlist, never editable user metadata.
- The administrator UI is isolated in a separate deployment, is not linked from the public console, and is marked `noindex`/`nofollow`.
- Website inspection is bounded, rejects private-network destinations and unsafe redirects, and never executes target JavaScript.
- Scan creation is rate-limited per account, while Supabase applies authentication rate limits.
- CORS is restricted through configured origins.
- Containers run as an unprivileged application user.
- CI runs unit tests, Bandit, pip-audit, frontend lint/build/audit, and a Docker build.

These controls reduce accidental misuse; they do not turn the application into a commercial scanning service. Larger deployments should add custom SMTP delivery, multi-factor authentication, distributed rate limiting, audit logging, monitoring, and explicit authorization records.

## Development checks

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m compileall -q api_server.py worker.py modules
Set-Location frontend
npm run lint
npm run build
Set-Location ..\admin-frontend
npm run lint
npm run build
```

## Portfolio highlights

- Designed a resilient asynchronous scanning workflow instead of running long reconnaissance tasks inside request handlers.
- Implemented security boundaries around authentication, public-target validation, rate limiting, secrets, and container privileges.
- Integrated a responsive security operations interface with persisted intelligence and job-state tracking.

## Author

Chigozie Okuma — [GitHub](https://github.com/Learnlife001) · [LinkedIn](https://www.linkedin.com/in/cjokuma23/) · [Portfolio](https://learnlife-portfolio.vercel.app/)
