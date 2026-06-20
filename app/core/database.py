from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from app.core.settings import settings

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=True if settings.ENV == 'development' else False,
    pool_size = 5,
    max_overflow = 10 
)

async_session_maker = async_sessionmaker(
    bind=engine,
    expire_on_commit=False
)

async def get_db_session():
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()