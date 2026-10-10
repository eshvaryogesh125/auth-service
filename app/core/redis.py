

from app.services.redis_services import blacklist_client, rate_limit_client, otp_client

from app.core.logging import logger



# blacklist class - 

class BlacklistTokenService:

    @staticmethod
    def _get_key(value: str, namespace: str = "jti") -> str:
        return f"blacklist:{namespace}:{value}"
    
    @staticmethod
    async def add(value: str, exp: int, namespace: str = "jti") -> None:
        if exp <= 0:
            return

        client = blacklist_client()
        key = BlacklistTokenService._get_key(value, namespace)
        await client.set(key, "1", ex=exp)
        logger.info("token blacklisted", extra={"namespace": namespace, "value": value, "ttl": exp})

    @staticmethod
    async def is_blacklisted(value: str, namespace: str = "jti") -> bool:
        client = blacklist_client()
        key = BlacklistTokenService._get_key(value, namespace)
        return await client.exists(key) == 1


class RateLimitService:

    @staticmethod
    def _get_key(prefix: str, identfier: str) -> str:
        """
        prefix, identifier can be - 
        (ip, client_ip);
        (login, email);
        (pwreset, email);
        """
        return f"ratelimit:{prefix}:{identfier}"

    @staticmethod
    async def check_and_increment(prefix: str, identfier: str, limit: int, window_sec: int) -> bool:
        client = rate_limit_client()
        key = RateLimitService._get_key(prefix, identfier)

        count = await client.incr(key)
        if count == 1:
            await client.expire(key, window_sec)

        if count > limit:
            logger.info("ratelimit exceeded:", extra={"key":key, "count":count, "limit":limit})
            return False
        return True

    @staticmethod
    async def reset(prefix: str, identfier: str) -> None:
        """delete/reset on user login after failed attempts"""
        client = rate_limit_client()
        key = RateLimitService._get_key(prefix, identfier)
        await client.delete(key)

class SingleUseTokenService:

    @staticmethod
    def _get_key(prefix: str, token: str) -> str:
        """password reset     - prefix -> pwreset
           email verification - prefic -> emailverify
        """
        return f"{prefix}:{token}"

    @staticmethod
    async def create(prefix:str, user_id:str, token:str, ttl:int) -> None:
        client = otp_client()
        key = SingleUseTokenService._get_key(prefix, token)

        await client.set(key, user_id, ex=ttl)

        logger.info("created token", extra={"key":key, "user_id":user_id, "ttl":ttl})

    @staticmethod
    async def consume(prefix:str, token:str) -> str | None:
        client = otp_client()
        key = SingleUseTokenService._get_key(prefix, token)

        return await client.getdel(key)
