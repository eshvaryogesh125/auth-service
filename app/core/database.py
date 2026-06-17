from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.core.settings import settings

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=True if settings.ENV == 'development' else False,
    pool_size = 10,
    max_overflow = 20 
)

async_session_maker = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)

async def get_db_session():
    async with async_session_maker() as session:
        try:
            yield session
        finally:
            await session.close()