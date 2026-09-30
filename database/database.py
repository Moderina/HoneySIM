import os
from datetime import datetime, timezone

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from database.models import Base

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:////db/honeysim.db")


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def make_engine(url: str = DATABASE_URL) -> Engine:
    if not url.startswith("sqlite"):
        return create_engine(url, pool_pre_ping=True)

    if url.startswith("sqlite:///") and not url.endswith(":memory:"):
        os.makedirs(os.path.dirname(url.removeprefix("sqlite:///")) or ".", exist_ok=True)
    engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": 30})

    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")  
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA busy_timeout=30000")
        cur.close()

    return engine


def init_db(engine: Engine) -> None:
    Base.metadata.create_all(engine)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)
