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
from typing import Literal

import jwt
from jwt import PyJWKClient
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    create_engine,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as SA_UUID
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

try:
    from celery import Celery
except ImportError:  # Celery is optional for local in-process development.
    Celery = None

from main import run_recon
from modules.email_alerts import (
    EmailConfigurationError,
    EmailDeliveryError,
    send_alert_email,
)
from modules.scan_alerts import build_scan_alert

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
SCAN_API_KEY = os.getenv("SCAN_API_KEY")
SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
TASK_QUEUE_MODE = os.getenv("TASK_QUEUE_MODE", "inprocess").strip().lower()
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
ALERT_RECIPIENT_EMAIL = os.getenv(
    "ALERT_RECIPIENT_EMAIL", "support@cgreglab.space"
).strip()
PUBLIC_APP_URL = os.getenv("PUBLIC_APP_URL", "https://cgreglab.space").rstrip("/")
SCAN_ALERTS_ENABLED = os.getenv("SCAN_ALERTS_ENABLED", "true").strip().lower() in {
    "1",
    "true",
    "yes",
}
MAX_MONITORS_PER_USER = int(os.getenv("MAX_MONITORS_PER_USER", "5"))
MAX_SCHEDULED_SCANS_PER_RUN = int(os.getenv("MAX_SCHEDULED_SCANS_PER_RUN", "25"))

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
        connection.execute(
            text(
                "ALTER TABLE scans ADD COLUMN IF NOT EXISTS "
                "source VARCHAR(24) NOT NULL DEFAULT 'manual'"
            )
        )
        connection.execute(text("ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL"))
        connection.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_scans_user_domain_created "
                "ON scans (user_id, domain, created_at DESC)"
            )
        )
        connection.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_scan_results_scan_id "
                "ON scan_results (scan_id)"
            )
        )
        connection.execute(text("ALTER TABLE domain_monitors ENABLE ROW LEVEL SECURITY"))
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
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
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
    __table_args__ = (
        Index("ix_scans_user_domain_created", "user_id", "domain", "created_at"),
    )

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

    source: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        default="manual",
        server_default="manual",
    )

    created_at: Mapped[object] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )


class ScanResult(Base):
    __tablename__ = "scan_results"
    __table_args__ = (Index("ix_scan_results_scan_id", "scan_id"),)

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


class DomainMonitor(Base):
    __tablename__ = "domain_monitors"
    __table_args__ = (
        UniqueConstraint("user_id", "domain", name="uq_domain_monitors_user_domain"),
        CheckConstraint(
            "cadence IN ('daily', 'weekly')",
            name="ck_domain_monitors_cadence",
        ),
        Index("ix_domain_monitors_due", "enabled", "next_run_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        SA_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        SA_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    cadence: Mapped[str] = mapped_column(String(16), nullable=False)
    enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


@app.get("/")
def root():
    return {"service": "CyberRecon API is running"}


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
RATE_LIMIT = int(os.getenv("SCAN_RATE_LIMIT", "5"))
RATE_WINDOW_SECONDS = int(os.getenv("SCAN_RATE_WINDOW_SECONDS", "3600"))
ADMIN_EMAILS = {
    email.strip().lower()
    for email in os.getenv("ADMIN_EMAILS", "").split(",")
    if email.strip()
}
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
        app_metadata = payload.get("app_metadata") or {}
        is_admin = app_metadata.get("role") == "admin" or email in ADMIN_EMAILS
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
        return Principal(user_id=user.id, email=user.email, is_admin=is_admin)


def require_admin(principal: Principal = Depends(require_principal)) -> Principal:
    if not principal.is_admin:
        raise HTTPException(status_code=403, detail="Administrator access required")
    return principal


def require_account(principal: Principal = Depends(require_principal)) -> Principal:
    if principal.user_id is None or not principal.email:
        raise HTTPException(status_code=403, detail="Verified user account required")
    return principal


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


def next_monitor_run(cadence: str, reference: datetime | None = None) -> datetime:
    current = reference or datetime.now(timezone.utc)
    if cadence == "daily":
        return current + timedelta(days=1)
    if cadence == "weekly":
        return current + timedelta(days=7)
    raise ValueError("Unsupported monitoring cadence")


def _dispatch_scan_job(
    job_id: str,
    domain: str,
    background_tasks: BackgroundTasks,
) -> None:
    if TASK_QUEUE_MODE == "celery":
        try:
            celery_client.send_task("cyberrecon.run_scan", args=[job_id, domain])
            return
        except Exception as exc:
            logger.exception("Unable to queue scan %s", job_id)
            with SessionLocal() as db:
                scan_row = db.get(Scan, uuid.UUID(job_id))
                if scan_row is not None:
                    scan_row.status = "failed"
                    db.commit()
            raise HTTPException(status_code=503, detail="Scan queue is unavailable") from exc

    background_tasks.add_task(_run_scan_job, job_id, domain)


def _deliver_scan_alert(
    *,
    job_id: str,
    domain: str,
    source: str,
    recipient: str,
    result: dict,
    previous_result: dict | None,
) -> None:
    if not SCAN_ALERTS_ENABLED:
        return

    try:
        content = build_scan_alert(
            domain=domain,
            result=result,
            previous_result=previous_result,
            source=source,
        )
        delivery = send_alert_email(
            recipient=recipient,
            subject=content.subject,
            title=content.title,
            introduction=content.introduction,
            severity=content.severity,
            details=content.details,
            action_url=PUBLIC_APP_URL,
            action_label=content.action_label,
            idempotency_key=f"cyberrecon-scan-{job_id}",
        )
        logger.info(
            "Scan alert accepted by %s for job %s with message id %s",
            delivery.provider,
            job_id,
            delivery.message_id,
        )
    except (EmailConfigurationError, EmailDeliveryError) as exc:
        logger.warning("Scan %s completed but its alert was not delivered: %s", job_id, exc)
    except Exception:
        logger.exception("Unexpected alert failure for completed scan %s", job_id)


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

    alert_payload = None
    with SessionLocal() as db:
        scan = db.get(Scan, scan_uuid)
        if scan is not None:
            scan.status = status

        if scan is not None and status == "completed" and result is not None:
            safe_result = json.loads(json.dumps(result, default=str))
            previous_query = (
                db.query(ScanResult)
                .join(Scan, ScanResult.scan_id == Scan.id)
                .filter(
                    Scan.id != scan_uuid,
                    Scan.domain == scan.domain,
                    Scan.status == "completed",
                )
            )
            if scan.user_id is None:
                previous_query = previous_query.filter(Scan.user_id.is_(None))
                recipient = ALERT_RECIPIENT_EMAIL
            else:
                previous_query = previous_query.filter(Scan.user_id == scan.user_id)
                user = db.get(User, scan.user_id)
                recipient = user.email if user else None

            previous_row = previous_query.order_by(Scan.created_at.desc()).first()
            previous_result = previous_row.results if previous_row else None
            db.add(ScanResult(scan_id=scan_uuid, results=safe_result))
            if recipient:
                alert_payload = {
                    "job_id": job_id,
                    "domain": scan.domain,
                    "source": scan.source,
                    "recipient": recipient,
                    "result": safe_result,
                    "previous_result": previous_result,
                }

        db.commit()

    if alert_payload:
        _deliver_scan_alert(**alert_payload)

    return status


class ScanRequest(BaseModel):
    domain: str


class MonitorRequest(BaseModel):
    domain: str
    cadence: Literal["daily", "weekly"] = "weekly"


class TestAlertResponse(BaseModel):
    status: str
    provider: str
    message_id: str
    recipient: str


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
                source="manual",
            )
        )

        db.commit()

    _dispatch_scan_job(job_id, domain, background_tasks)

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
                "source": s.source,
                "created_at": s.created_at,
            }
            for s in scans
        ]


def _monitor_response(monitor: DomainMonitor) -> dict:
    return {
        "id": str(monitor.id),
        "domain": monitor.domain,
        "cadence": monitor.cadence,
        "enabled": monitor.enabled,
        "next_run_at": monitor.next_run_at,
        "last_run_at": monitor.last_run_at,
        "created_at": monitor.created_at,
    }


@app.post("/monitors", status_code=201)
def create_monitor(
    request: MonitorRequest,
    principal: Principal = Depends(require_account),
):
    domain = normalize_domain(request.domain)
    validate_public_domain(domain)
    now = datetime.now(timezone.utc)

    with SessionLocal() as db:
        monitor_count = (
            db.query(DomainMonitor)
            .filter(DomainMonitor.user_id == principal.user_id)
            .count()
        )
        if monitor_count >= MAX_MONITORS_PER_USER:
            raise HTTPException(
                status_code=409,
                detail=f"Each account may monitor up to {MAX_MONITORS_PER_USER} domains",
            )

        monitor = DomainMonitor(
            user_id=principal.user_id,
            domain=domain,
            cadence=request.cadence,
            next_run_at=next_monitor_run(request.cadence, now),
        )
        db.add(monitor)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail="This domain is already monitored by the account",
            ) from exc
        db.refresh(monitor)
        return _monitor_response(monitor)


@app.get("/monitors")
def list_monitors(principal: Principal = Depends(require_account)):
    with SessionLocal() as db:
        monitors = (
            db.query(DomainMonitor)
            .filter(DomainMonitor.user_id == principal.user_id)
            .order_by(DomainMonitor.created_at.desc())
            .all()
        )
        return [_monitor_response(monitor) for monitor in monitors]


@app.delete("/monitors/{monitor_id}")
def delete_monitor(
    monitor_id: uuid.UUID,
    principal: Principal = Depends(require_account),
):
    with SessionLocal() as db:
        monitor = (
            db.query(DomainMonitor)
            .filter(
                DomainMonitor.id == monitor_id,
                DomainMonitor.user_id == principal.user_id,
            )
            .first()
        )
        if monitor is None:
            raise HTTPException(status_code=404, detail="Monitor not found")
        db.delete(monitor)
        db.commit()
    return {"status": "deleted"}


@app.post("/admin/monitoring/run-due")
def run_due_monitors(
    background_tasks: BackgroundTasks,
    http_request: Request,
    _: Principal = Depends(require_admin),
):
    """Atomically claim due monitors and dispatch their scheduled scans."""

    enforce_rate_limit(http_request, scope="scheduled monitoring")
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        due_monitors = (
            db.query(DomainMonitor)
            .filter(
                DomainMonitor.enabled.is_(True),
                DomainMonitor.next_run_at <= now,
            )
            .order_by(DomainMonitor.next_run_at)
            .with_for_update(skip_locked=True)
            .limit(MAX_SCHEDULED_SCANS_PER_RUN)
            .all()
        )
        claimed = [
            (monitor.user_id, monitor.domain, monitor.cadence)
            for monitor in due_monitors
        ]
        for monitor in due_monitors:
            monitor.last_run_at = now
            monitor.next_run_at = next_monitor_run(monitor.cadence, now)
        db.commit()

    scheduled_jobs: list[str] = []
    skipped_domains: list[str] = []
    initial_status = "queued" if TASK_QUEUE_MODE == "celery" else "running"
    for user_id, domain, cadence in claimed:
        try:
            validate_public_domain(domain)
        except HTTPException:
            logger.warning("Scheduled target no longer resolves safely: %s", domain)
            skipped_domains.append(domain)
            continue

        job_uuid = uuid.uuid4()
        job_id = str(job_uuid)
        with SessionLocal() as db:
            db.add(
                Scan(
                    id=job_uuid,
                    domain=domain,
                    status=initial_status,
                    user_id=user_id,
                    source=f"scheduled_{cadence}",
                )
            )
            db.commit()

        try:
            _dispatch_scan_job(job_id, domain, background_tasks)
            scheduled_jobs.append(job_id)
        except HTTPException:
            skipped_domains.append(domain)

    return {
        "claimed": len(claimed),
        "scheduled": len(scheduled_jobs),
        "job_ids": scheduled_jobs,
        "skipped_domains": skipped_domains,
    }


@app.get("/admin/scans")
def list_admin_scans(_: Principal = Depends(require_admin)):
    with SessionLocal() as db:
        rows = (
            db.query(Scan, User, ScanResult)
            .outerjoin(User, Scan.user_id == User.id)
            .outerjoin(ScanResult, ScanResult.scan_id == Scan.id)
            .order_by(Scan.created_at.desc())
            .limit(100)
            .all()
        )
        return [
            {
                "job_id": str(scan_row.id),
                "domain": scan_row.domain,
                "status": scan_row.status,
                "source": scan_row.source,
                "created_at": scan_row.created_at,
                "user_email": user.email if user else "administrative scan",
                "phishing": (result.results or {}).get("phishing") if result else None,
            }
            for scan_row, user, result in rows
        ]


@app.post("/admin/alerts/test", response_model=TestAlertResponse)
def send_test_alert(
    http_request: Request,
    _: Principal = Depends(require_admin),
):
    """Send a fixed-recipient delivery test without exposing a public mail relay."""

    enforce_rate_limit(http_request, scope="alert test")
    generated_at = datetime.now(timezone.utc)

    try:
        delivery = send_alert_email(
            recipient=ALERT_RECIPIENT_EMAIL,
            subject="CyberRecon alert system test",
            title="Alert delivery is operational",
            introduction=(
                "CyberRecon successfully reached the configured email delivery provider. "
                "This confirms that security notifications can be delivered from the "
                "production API."
            ),
            severity="operational",
            details={
                "Environment": os.getenv("APP_ENVIRONMENT", "production"),
                "API service": "cyberrecon-api-3ams",
                "Authorization": "Administrator-only test route",
                "Generated at": generated_at.strftime("%Y-%m-%d %H:%M UTC"),
            },
            action_url=PUBLIC_APP_URL,
            action_label="Open CyberRecon",
            idempotency_key=f"cyberrecon-alert-test-{generated_at:%Y%m%d%H%M}",
        )
    except EmailConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except EmailDeliveryError as exc:
        logger.warning("Test alert delivery failed: %s", exc)
        raise HTTPException(status_code=502, detail="Unable to send the test alert") from exc

    logger.info(
        "Test alert accepted by %s with message id %s",
        delivery.provider,
        delivery.message_id,
    )
    return TestAlertResponse(
        status="sent",
        provider=delivery.provider,
        message_id=delivery.message_id,
        recipient=delivery.recipient,
    )


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
