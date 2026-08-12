from redis.asyncio import Redis, ConnectionPool

from app.core.settings import settings
from app.core.logging import logger


# 0 - blacklisted => revoked jit
# 1 - rate limiting 
# 2 - otp/email token cache

_pools:dict[int, ConnectionPool] = {}
_clients: dict[int, Redis] = {}

def _base_url() -> str:
    return settings.REDIS_URL.rsplit("/", 1)[0]

def get_pool(db: int = 0) -> ConnectionPool:
    if db not in _pools:
        _pools[db] = ConnectionPool.from_url(
            f"{_base_url()}/{db}",
            decode_responses=True,
            max_connections=20
        )

    return _pools[db]

def get_client(db: int = 0) -> Redis:
    if db not in _clients:
        _clients[db] = Redis(connection_pool=get_pool(db))
    return _clients[db]


def blacklist_client() -> Redis:
    return get_client(db=0)

def rate_limit_client() -> Redis:
    return get_client(db=1)
 
def otp_client() -> Redis:
    return get_client(db=2)

async def close_redis() -> None: #close on app shutdown
    for db, client in _clients.items():
        await client.close()
        logger.info("close_redis", extra={'db':db})

    _clients.clear()
    _pools.clear()

async def ping_redis() -> bool: #health check
    try:
        return await get_client(db=0).ping()
    except Exception as err:
        logger.error("redis_ping_failed", extra={"error": str(err)})
        return False