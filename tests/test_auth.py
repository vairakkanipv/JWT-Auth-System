import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from app.main import app
from app.database import Base, get_db

# ── Test Database Setup ───────────────────────────────────────────────────────

TEST_DB_URL = "sqlite+aiosqlite:///./test_jwt_auth.db"

test_engine = create_async_engine(TEST_DB_URL, echo=False)
TestSessionLocal = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)


async def override_get_db():
    async with TestSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


app.dependency_overrides[get_db] = override_get_db


@pytest_asyncio.fixture(autouse=True, scope="function")
async def setup_db():
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


# ── Helpers ───────────────────────────────────────────────────────────────────

VALID_USER = {
    "username": "testuser",
    "email": "test@example.com",
    "password": "StrongPass1",
    "full_name": "Test User",
}


async def register_and_login(client: AsyncClient) -> dict:
    await client.post("/api/v1/auth/register", json=VALID_USER)
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": VALID_USER["username"], "password": VALID_USER["password"]},
    )
    return resp.json()


# ── Registration Tests ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_register_success(client):
    resp = await client.post("/api/v1/auth/register", json=VALID_USER)
    assert resp.status_code == 201
    data = resp.json()
    assert data["username"] == VALID_USER["username"]
    assert data["email"] == VALID_USER["email"]
    assert "hashed_password" not in data


@pytest.mark.asyncio
async def test_register_duplicate_username(client):
    await client.post("/api/v1/auth/register", json=VALID_USER)
    resp = await client.post("/api/v1/auth/register", json=VALID_USER)
    assert resp.status_code == 409
    assert "Username already registered" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_register_weak_password(client):
    bad = {**VALID_USER, "password": "weakpassword"}
    resp = await client.post("/api/v1/auth/register", json=bad)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_register_invalid_email(client):
    bad = {**VALID_USER, "email": "not-an-email"}
    resp = await client.post("/api/v1/auth/register", json=bad)
    assert resp.status_code == 422


# ── Login Tests ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_login_success(client):
    await client.post("/api/v1/auth/register", json=VALID_USER)
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": VALID_USER["username"], "password": VALID_USER["password"]},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_wrong_password(client):
    await client.post("/api/v1/auth/register", json=VALID_USER)
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": VALID_USER["username"], "password": "WrongPass9"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_unknown_user(client):
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "nobody", "password": "Whatever1"},
    )
    assert resp.status_code == 401


# ── Token Tests ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_refresh_token(client):
    tokens = await register_and_login(client)
    resp = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert resp.status_code == 200
    new_tokens = resp.json()
    assert "access_token" in new_tokens
    assert new_tokens["access_token"] != tokens["access_token"]


@pytest.mark.asyncio
async def test_refresh_with_access_token_fails(client):
    tokens = await register_and_login(client)
    resp = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tokens["access_token"]},  # wrong type
    )
    assert resp.status_code == 401


# ── Protected Routes Tests ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_me(client):
    tokens = await register_and_login(client)
    resp = await client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert resp.status_code == 200
    assert resp.json()["username"] == VALID_USER["username"]


@pytest.mark.asyncio
async def test_get_me_no_token(client):
    resp = await client.get("/api/v1/users/me")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_get_me_invalid_token(client):
    resp = await client.get(
        "/api/v1/users/me",
        headers={"Authorization": "Bearer this.is.invalid"},
    )
    assert resp.status_code == 401


# ── Health Check ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_health_check(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
