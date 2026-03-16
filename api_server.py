import os
import uuid
import logging
import traceback
import json

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from sqlalchemy import DateTime, ForeignKey, String, create_engine, func
from sqlalchemy.dialects.postgresql import JSONB, UUID as SA_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from main import run_recon


app = FastAPI(title="CyberRecon API", version="1.0.0")
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cyberrecon")

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set. Add it to your .env file.")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        SA_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    domain: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="running")
    created_at: Mapped[object] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[uuid.UUID] = mapped_column(
        SA_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        SA_UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    results: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[object] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


Base.metadata.create_all(bind=engine)


@app.get("/")
def root():
    return {"service": "CyberRecon API"}


def _run_scan_job(job_id: str, domain: str) -> None:
    # job_id is a string UUID we generated; convert to UUID for DB ops
    scan_uuid = uuid.UUID(job_id)

    logger.info("Scan starting job_id=%s domain=%s", job_id, domain)

    status: str = "running"
    result: dict | None = None

    try:
        result = run_recon(domain)
        status = "completed"
        logger.info("Scan finished job_id=%s domain=%s status=completed", job_id, domain)
    except Exception:
        status = "failed"
        logger.exception("Scan failed job_id=%s domain=%s", job_id, domain)
        print(traceback.format_exc())

    # Always update the DB status so nothing stays "running".
    with SessionLocal() as db:
        try:
            scan = db.get(Scan, scan_uuid)
            if scan is not None:
                scan.status = status

            if status == "completed" and result is not None:
                safe_result = json.loads(json.dumps(result, default=str))
                db.add(ScanResult(scan_id=scan_uuid, results=safe_result))
        finally:
            db.commit()


@app.post("/scan")
def scan(
    background_tasks: BackgroundTasks,
    domain: str = Query(..., description="Target domain, e.g. example.com"),
):
    """
    Start reconnaissance in the background and return a job id immediately.
    """
    domain = domain.strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain must not be empty.")

    job_uuid = uuid.uuid4()
    job_id = str(job_uuid)

    with SessionLocal() as db:
        db.add(Scan(id=job_uuid, domain=domain, status="running"))
        db.commit()

    background_tasks.add_task(_run_scan_job, job_id, domain)
    return {"job_id": job_id, "status": "running"}


@app.get("/results/{job_id}")
def get_results(job_id: str):
    try:
        scan_uuid = uuid.UUID(job_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid job_id format.")

    with SessionLocal() as db:
        scan = db.get(Scan, scan_uuid)
        if scan is None:
            raise HTTPException(status_code=404, detail="Job not found.")

        if scan.status != "completed":
            return {"status": "running"}

        result_row = (
            db.query(ScanResult)
            .filter(ScanResult.scan_id == scan_uuid)
            .order_by(ScanResult.created_at.desc())
            .first()
        )

        if result_row is None:
            return {"status": "completed", "data": None}

        return {"status": "completed", "data": result_row.results}

