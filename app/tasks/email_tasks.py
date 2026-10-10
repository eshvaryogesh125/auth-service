import asyncio

from app.core.celery_app import celery_app
from app.core.logging import logger
from app.services.email_services import get_email_service


@celery_app.task(name="app.tasks.send_password_reset_email")
def send_password_reset_email(to: str, subject: str, body: str) -> None:
    try:
        email_service = get_email_service()
        asyncio.run(email_service.send(to=to, subject=subject, body=body))
    except Exception:
        logger.exception("password_reset_email_task_failed", extra={"to": to, "subject": subject})
