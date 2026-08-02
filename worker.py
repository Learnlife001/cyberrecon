import os

from celery import Celery

from api_server import _run_scan_job


REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery("cyberrecon-worker", broker=REDIS_URL, backend=REDIS_URL)
celery_app.conf.update(
    broker_connection_retry_on_startup=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    result_expires=3600,
)


@celery_app.task(name="cyberrecon.run_scan")
def run_scan_job(job_id: str, domain: str) -> str:
    return _run_scan_job(job_id, domain)
