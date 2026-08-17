import httpx

from abc import ABC, abstractmethod

from app.core.settings import settings
from app.core.logging import logger


class EmailService(ABC):

    @abstractmethod
    async def send(self, to: str, subject: str, body: str):
        ...

class SendGridEmailService(EmailService):

    API_URL = "https://api.sendgrid.com/v3/mail/send"

    async def send(self, to: str, subject: str, body: str):
        payload = {
            "personalizations": [{"to": [{"email": to}]}],
            "from": {"email": settings.SENDGRID_FROM_EMAIL},
            "subject": subject,
            "content": [{"type": "text/plain", "value": body}],
        }
        headers = {
            "Authorization": f"Bearer {settings.SENDGRID_API_KEY}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(self.API_URL, json=payload, headers=headers)

        if response.status_code >= 400:
            logger.info(
                "email_send_failed",
                extra={"to": to, "status": response.status_code, "body": response.text},
            )
            raise RuntimeError(f"SendGrid send failed: {response.status_code}")

        logger.info("email_sent", extra={"provider": "sendgrid", "to": to, "subject": subject})

def get_email_service() -> EmailService:
    return SendGridEmailService()