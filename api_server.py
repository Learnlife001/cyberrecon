import os
import ipaddress
import re
import secrets
import socket
import threading
import time
import uuid
import logging
import json
from collections import defaultdict, deque
from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from sqlalchemy import DateTime, ForeignKey, String, create_engine, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID as SA_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

try:
    from celery import Celery
except ImportError:  # Celery is optional for local in-process development.
    Celery = None

from main import run_recon

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
SCAN_API_KEY = os.getenv("SCAN_API_KEY")
TASK_QUEUE_MODE = os.getenv("TASK_QUEUE_MODE", "inprocess").strip().lower()
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

if not SCAN_API_KEY:
    raise RuntimeError("SCAN_API_KEY is not set")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

if TASK_QUEUE_MODE not in {"inprocess", "celery"}:
    raise RuntimeError("TASK_QUEUE_MODE must be 'inprocess' or 'celery'")

if TASK_QUEUE_MODE == "celery" and Celery is None:
    raise RuntimeError("Celery is required when TASK_QUEUE_MODE=celery")

celery_client = (
    Celery("cyberrecon-api", broker=REDIS_URL, backend=REDIS_URL)
    if TASK_QUEUE_MODE == "celery" and Celery is not None
    else None
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    if TASK_QUEUE_MODE == "inprocess":
        with SessionLocal() as db:
            db.query(Scan).filter(Scan.status == "running").update(
                {Scan.status: "failed"}, synchronize_session=False
            )
            db.commit()
    yield


app = FastAPI(title="CyberRecon API", version="1.0.0", lifespan=lifespan)

origins = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key"],
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cyberrecon")

class Base(DeclarativeBase):
    pass

class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        SA_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )

    domain: Mapped[str] = mapped_column(String, nullable=False)

    status: Mapped[str] = mapped_column(
        String,
        nullable=False,
        default="running"
    )

    created_at: Mapped[object] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[uuid.UUID] = mapped_column(
        SA_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        SA_UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False
    )

    results: Mapped[dict] = mapped_column(JSONB, nullable=False)

    created_at: Mapped[object] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )


@app.get("/")
def root():
    return {"service": "CyberRecon API is running"}


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
RATE_LIMIT = int(os.getenv("SCAN_RATE_LIMIT", "5"))
RATE_WINDOW_SECONDS = int(os.getenv("SCAN_RATE_WINDOW_SECONDS", "3600"))
rate_buckets: dict[str, deque[float]] = defaultdict(deque)
rate_lock = threading.Lock()


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    if x_api_key is None or not secrets.compare_digest(x_api_key, SCAN_API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")


def normalize_domain(value: str) -> str:
    return value.lower().strip().removeprefix("https://").removeprefix("http://").rstrip("/")


def validate_public_domain(domain: str) -> None:
    if not DOMAIN_PATTERN.fullmatch(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")

    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(domain, None)}
    except socket.gaierror as exc:
        raise HTTPException(status_code=400, detail="Domain does not resolve") from exc

    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise HTTPException(status_code=400, detail="Target must resolve only to public IP addresses")


def enforce_rate_limit(request: Request) -> None:
    client = request.client.host if request.client else "unknown"
    now = time.monotonic()
    with rate_lock:
        bucket = rate_buckets[client]
        while bucket and now - bucket[0] >= RATE_WINDOW_SECONDS:
            bucket.popleft()
        if len(bucket) >= RATE_LIMIT:
            raise HTTPException(status_code=429, detail="Scan rate limit exceeded")
        bucket.append(now)


def _run_scan_job(job_id: str, domain: str):

    scan_uuid = uuid.UUID(job_id)

    logger.info("Scan started %s %s", job_id, domain)

    with SessionLocal() as db:
        scan = db.get(Scan, scan_uuid)
        if scan is None:
            logger.warning("Scan %s no longer exists", job_id)
            return "missing"
        scan.status = "running"
        db.commit()

    status = "running"
    result = None

    try:
        result = run_recon(domain)
        status = "completed"

        logger.info("Scan completed %s", job_id)

    except Exception:

        status = "failed"

        logger.exception("Scan failed %s", job_id)

    with SessionLocal() as db:

        scan = db.get(Scan, scan_uuid)

        if scan is not None:
            scan.status = status

        if status == "completed" and result is not None:

            safe_result = json.loads(json.dumps(result, default=str))

            db.add(
                ScanResult(
                    scan_id=scan_uuid,
                    results=safe_result
                )
            )

        db.commit()

    return status

class ScanRequest(BaseModel):
    domain: str

@app.post("/scan", dependencies=[Depends(require_api_key)])
def scan(request: ScanRequest, background_tasks: BackgroundTasks, http_request: Request):

    domain = normalize_domain(request.domain)
    validate_public_domain(domain)
    enforce_rate_limit(http_request)

    job_uuid = uuid.uuid4()

    job_id = str(job_uuid)

    initial_status = "queued" if TASK_QUEUE_MODE == "celery" else "running"

    with SessionLocal() as db:

        db.add(
            Scan(
                id=job_uuid,
                domain=domain,
                status=initial_status
            )
        )

        db.commit()

    if TASK_QUEUE_MODE == "celery":
        try:
            celery_client.send_task("cyberrecon.run_scan", args=[job_id, domain])
        except Exception as exc:
            logger.exception("Unable to queue scan %s", job_id)
            with SessionLocal() as db:
                scan_row = db.get(Scan, job_uuid)
                if scan_row is not None:
                    scan_row.status = "failed"
                    db.commit()
            raise HTTPException(status_code=503, detail="Scan queue is unavailable") from exc
    else:
        background_tasks.add_task(_run_scan_job, job_id, domain)

    return {
        "job_id": job_id,
        "status": initial_status
    }


@app.get("/results/{job_id}", dependencies=[Depends(require_api_key)])
def get_results(job_id: str):

    try:
        scan_uuid = uuid.UUID(job_id)

    except Exception:

        raise HTTPException(
            status_code=400,
            detail="Invalid job id"
        )

    with SessionLocal() as db:

        scan = db.get(Scan, scan_uuid)

        if scan is None:

            raise HTTPException(
                status_code=404,
                detail="Job not found"
            )

        if scan.status in {"queued", "running"}:
            return {"status": scan.status}

        if scan.status == "failed":
            return {"status": "failed"}

        result_row = (
            db.query(ScanResult)
            .filter(ScanResult.scan_id == scan_uuid)
            .order_by(ScanResult.created_at.desc())
            .first()
        )

        if result_row is None:
            return {
                "status": "completed",
                "data": None
            }

        return {
            "status": "completed",
            "data": result_row.results
        }


@app.get("/scans", dependencies=[Depends(require_api_key)])
def list_scans():
    with SessionLocal() as db:
        scans = (
            db.query(Scan)
            .order_by(Scan.created_at.desc())
            .limit(20)
            .all()
        )

        return [
            {
                "job_id": str(s.id),
                "domain": s.domain,
                "status": s.status,
                "created_at": s.created_at,
            }
            for s in scans
        ]


@app.get("/health")
def health():
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
        database_status = "healthy"
    except Exception:
        logger.exception("Database health check failed")
        database_status = "unhealthy"

    status_code = 200 if database_status == "healthy" else 503
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "healthy" if status_code == 200 else "degraded",
            "database": database_status,
            "queue_mode": TASK_QUEUE_MODE,
        },
    )


@app.options("/{full_path:path}")
def preflight_handler(full_path: str):
    return JSONResponse(content={"message": "OK"})
