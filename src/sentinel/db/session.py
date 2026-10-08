"""Async SQLAlchemy database session management.

Why async?
==========
Our FastAPI app is fully async. If we used synchronous database calls,
every DB query would block the entire event loop — meaning no other
requests could be processed while waiting for PostgreSQL to respond.
With async sessions (via asyncpg driver), DB queries run concurrently
alongside other requests, keeping the server responsive.

Architecture:
- ``create_async_engine``: Maintains a connection pool to PostgreSQL.
- ``async_sessionmaker``: Creates lightweight session objects from the pool.
- ``get_session``: FastAPI dependency that yields a session per-request
  and automatically commits/rolls back when done.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from sentinel.core.logging import get_logger

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from sqlalchemy.ext.asyncio import AsyncEngine

logger = get_logger(__name__)


def build_engine(database_url: str, echo: bool = False) -> AsyncEngine:
    """Create an async SQLAlchemy engine with connection pooling.

    Args:
        database_url: PostgreSQL connection string
                      (e.g. ``postgresql+asyncpg://user:pass@host/db``).
        echo: If True, log all SQL statements (useful for debugging).

    Returns:
        An AsyncEngine configured for production use.
    """
    engine = create_async_engine(
        database_url,
        echo=echo,
        # Pool settings tuned for a SIEM workload:
        pool_size=10,       # Max persistent connections
        max_overflow=20,    # Extra connections under load
        pool_recycle=3600,  # Recycle connections every hour
        pool_pre_ping=True, # Verify connections before use
    )
    logger.info(
        "db_engine_created",
        url=database_url[:30] + "...",
        pool_size=10,
    )
    return engine


def build_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create a session factory bound to the engine.

    A session factory is a callable that produces new AsyncSession
    objects. Each request gets its own session, ensuring isolation.

    Args:
        engine: The async engine to bind sessions to.

    Returns:
        A factory callable that creates AsyncSession instances.
    """
    return async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,  # Keep data accessible after commit
    )


async def get_session(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    """Yield an async database session (FastAPI dependency).

    Usage in a FastAPI route::

        @router.get("/alerts")
        async def list_alerts(session: AsyncSession = Depends(get_db)):
            ...

    The session is committed on success and rolled back on error.
    """
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
