from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import Engine, text

from api.deps import SessionDep
from api.routes import alerts, events, stats
from database.database import init_db, make_engine, make_session_factory
from logsetup import setup_logging


def create_app(engine: Engine | None = None) -> FastAPI:
    engine = engine or make_engine()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        setup_logging("api")  
        init_db(engine)  
        yield

    app = FastAPI(title="HoneySIM API", version="1.0",
                  description="Mini SIEM: events from the honeypot, detected alerts and statistics.",
                  lifespan=lifespan)
    app.state.session_factory = make_session_factory(engine)

    app.include_router(events.router)
    app.include_router(alerts.router)
    app.include_router(stats.router)

    @app.get("/api/health", tags=["health"])
    def health(session: SessionDep):
        session.execute(text("SELECT 1"))
        return {"status": "ok", "database": "ok"}

    return app


app = create_app()
