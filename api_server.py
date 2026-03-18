import os
import uuid
import logging
import traceback
import json

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from sqlalchemy import DateTime, ForeignKey, String, create_engine, func
from sqlalchemy.dialects.postgresql import JSONB, UUID as SA_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from main import run_recon


app = FastAPI(title="CyberRecon API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cyberrecon")

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


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


Base.metadata.create_all(bind=engine)

@app.get("/")
def root():
    return {"service": "CyberRecon API is running"}


def _run_scan_job(job_id: str, domain: str):

    scan_uuid = uuid.UUID(job_id)

    logger.info("Scan started %s %s", job_id, domain)

    status = "running"
    result = None

    try:
        result = run_recon(domain)
        status = "completed"

        logger.info("Scan completed %s", job_id)

    except Exception:

        status = "failed"

        logger.exception("Scan failed %s", job_id)

        print(traceback.format_exc())

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

class ScanRequest(BaseModel):
    domain: str

@app.post("/scan")
def scan(request: ScanRequest, background_tasks: BackgroundTasks):

    domain = request.domain.strip()

    if not domain or " " in domain or "." not in domain:
        raise HTTPException(
            status_code=400,
            detail="Invalid domain format"
        )

    job_uuid = uuid.uuid4()

    job_id = str(job_uuid)

    with SessionLocal() as db:

        db.add(
            Scan(
                id=job_uuid,
                domain=domain,
                status="running"
            )
        )

        db.commit()

    background_tasks.add_task(
        _run_scan_job,
        job_id,
        domain
    )

    return {
        "job_id": job_id,
        "status": "running"
    }


@app.get("/results/{job_id}")
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

        if scan.status == "running":
            return {"status": "running"}

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


@app.options("/{full_path:path}")
def preflight_handler(full_path: str):
    return JSONResponse(content={"message": "OK"})