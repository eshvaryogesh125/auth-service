import sys
import logging

from pythonjsonlogger import jsonlogger

from app.core.settings import settings


class AuthJsonFormatter(jsonlogger.JsonFormatter):

    def add_fields(log_record: dict, record: logging.LogRecord, message_dict: dict) -> None:
        super().add_fields(log_record, record, message_dict)

        if "message" in log_record:
            log_record["event"] = log_record.pop("message")
 
        log_record["level"] = record.levelname
        log_record.setdefault("service", settings.PROJECT_NAME)
 


def get_logger(name: str = "auth") -> None:

    logger = logging.getlogger(name)

    if logger.handlers:
        # already configured - no need to double attach the handlers
        return logger
    
    logger.setLevel(logging.DEBUG if settings.ENV == 'development' else logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    formatter = AuthJsonFormatter(
        fmt="%(asctime)s %(levelname)s %(process)d %(name)s %(filename)s %(lineno)d %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
        rename_fields={"asctime": "timestamp", "name": "logger", "process": "pid", "lineno": "line"},
    )
    
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # no need propagate to root logger - avoids duplicate output
    logger.propogate = False

    return logger

def suppress_third_party() -> None:
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("asyncpg").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
 

logger = get_logger("auth")
suppress_third_party()
 