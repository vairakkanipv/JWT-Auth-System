from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging

from app.config import settings
from app.database import create_tables
from app.routers import auth_router, users_router
from app.schemas import HealthResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup → run → shutdown."""
    logger.info("Starting up — creating database tables...")
    await create_tables()
    logger.info("Database ready.")
    yield
    logger.info("Shutting down.")


# ── App Factory ───────────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="""
## JWT Authentication API

A production-ready FastAPI authentication system featuring:

- 🔐 **JWT Access + Refresh Tokens** — stateless, HS256-signed
- 🔒 **Bcrypt password hashing** — via passlib
- 👤 **User registration & login** — with full validation
- ♻️ **Token rotation** — refresh endpoint issues new token pairs  
- 🛡️ **Role-based access** — superuser-protected admin endpoints
- 📦 **Async SQLAlchemy** — SQLite (swap to PostgreSQL in production)

### Token Flow
1. `POST /auth/register` → create account  
2. `POST /auth/login` → receive `access_token` + `refresh_token`  
3. Use `Authorization: Bearer <access_token>` on protected routes  
4. `POST /auth/refresh` → exchange refresh token for new pair  
5. `POST /auth/logout` → client discards tokens  
    """,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────

app.include_router(auth_router, prefix="/api/v1")
app.include_router(users_router, prefix="/api/v1")


# ── Core Routes ───────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
async def root():
    return {"message": f"Welcome to {settings.APP_NAME}", "docs": "/docs"}


@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Health check",
)
async def health_check():
    """Returns API and database status."""
    from sqlalchemy import text
    from app.database import engine
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception:
        db_status = "unreachable"
    return HealthResponse(
        status="ok",
        version=settings.APP_VERSION,
        database=db_status,
    )


# ── Global Exception Handlers ─────────────────────────────────────────────────

@app.exception_handler(404)
async def not_found_handler(request, exc):
    return JSONResponse(status_code=404, content={"detail": "Resource not found"})


@app.exception_handler(500)
async def server_error_handler(request, exc):
    logger.error(f"Unhandled error: {exc}")
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})
