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
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque
from contextlib import asynccontextmanager

import jwt
from jwt import PyJWKClient
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
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
SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
TASK_QUEUE_MODE = os.getenv("TASK_QUEUE_MODE", "inprocess").strip().lower()
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

if not SCAN_API_KEY:
    raise RuntimeError("SCAN_API_KEY is not set")

if not SUPABASE_URL.startswith("https://"):
    raise RuntimeError("SUPABASE_URL must be set to the HTTPS project URL")

SUPABASE_ISSUER = f"{SUPABASE_URL}/auth/v1"
supabase_jwks = PyJWKClient(f"{SUPABASE_ISSUER}/.well-known/jwks.json", cache_keys=True)

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
    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS user_id UUID"))
        connection.execute(text("ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL"))
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
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cyberrecon")

class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        SA_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[object] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        SA_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )

    domain: Mapped[str] = mapped_column(String, nullable=False)

    user_id: Mapped[uuid.UUID | None] = mapped_column(
        SA_UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=True
    )

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
bearer_scheme = HTTPBearer(auto_error=False)


class Principal(BaseModel):
    user_id: uuid.UUID | None = None
    email: str | None = None
    is_admin: bool = False


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    if x_api_key is None or not secrets.compare_digest(x_api_key, SCAN_API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")


def require_principal(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    x_api_key: str | None = Header(default=None),
) -> Principal:
    if x_api_key and secrets.compare_digest(x_api_key, SCAN_API_KEY):
        return Principal(is_admin=True)

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Authentication required")

    try:
        signing_key = supabase_jwks.get_signing_key_from_jwt(credentials.credentials)
        payload = jwt.decode(
            credentials.credentials,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            audience="authenticated",
            issuer=SUPABASE_ISSUER,
        )
        user_id = uuid.UUID(payload["sub"])
        email = str(payload["email"]).strip().lower()
    except (jwt.PyJWTError, KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired access token") from exc

    with SessionLocal() as db:
        user = db.get(User, user_id)
        if user is None:
            user = db.query(User).filter(User.email == email).first()
            if user is None:
                user = User(id=user_id, email=email, password_hash=None)
                db.add(user)
            else:
                user.password_hash = None
            db.commit()
            db.refresh(user)
        elif user.email != email:
            user.email = email
            db.commit()
        return Principal(user_id=user.id, email=user.email)


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


def enforce_rate_limit(request: Request, scope: str = "scan") -> None:
    address = request.client.host if request.client else "unknown"
    client = f"{scope}:{address}"
    now = time.monotonic()
    with rate_lock:
        bucket = rate_buckets[client]
        while bucket and now - bucket[0] >= RATE_WINDOW_SECONDS:
            bucket.popleft()
        if len(bucket) >= RATE_LIMIT:
            raise HTTPException(status_code=429, detail=f"{scope.title()} rate limit exceeded")
        bucket.append(now)


def enforce_user_rate_limit(user_id: uuid.UUID) -> None:
    window_start = datetime.now(timezone.utc) - timedelta(seconds=RATE_WINDOW_SECONDS)
    with SessionLocal() as db:
        recent_count = (
            db.query(Scan)
            .filter(Scan.user_id == user_id, Scan.created_at >= window_start)
            .count()
        )
    if recent_count >= RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=f"Scan limit reached. Each account may run {RATE_LIMIT} scans per hour.",
        )


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


@app.get("/auth/me")
def auth_me(principal: Principal = Depends(require_principal)):
    if principal.is_admin:
        return {"id": "admin", "email": "administrator", "is_admin": True}
    return {"id": str(principal.user_id), "email": principal.email, "is_admin": False}


@app.post("/scan")
def scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    http_request: Request,
    principal: Principal = Depends(require_principal),
):

    domain = normalize_domain(request.domain)
    validate_public_domain(domain)
    if principal.user_id is not None:
        enforce_user_rate_limit(principal.user_id)
    else:
        enforce_rate_limit(http_request)

    job_uuid = uuid.uuid4()

    job_id = str(job_uuid)

    initial_status = "queued" if TASK_QUEUE_MODE == "celery" else "running"

    with SessionLocal() as db:

        db.add(
            Scan(
                id=job_uuid,
                domain=domain,
                status=initial_status,
                user_id=principal.user_id,
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


@app.get("/results/{job_id}")
def get_results(job_id: str, principal: Principal = Depends(require_principal)):

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

        if not principal.is_admin and scan.user_id != principal.user_id:
            raise HTTPException(status_code=404, detail="Job not found")

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


@app.get("/scans")
def list_scans(principal: Principal = Depends(require_principal)):
    with SessionLocal() as db:
        query = db.query(Scan)
        if not principal.is_admin:
            query = query.filter(Scan.user_id == principal.user_id)
        scans = query.order_by(Scan.created_at.desc()).limit(20).all()

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
