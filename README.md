# 🔐 JWT Auth API — FastAPI

A production-ready **Login & Registration System** built with FastAPI, featuring JWT access/refresh tokens, bcrypt password hashing, async SQLAlchemy, and full test coverage.

---

## ✨ Features

| Feature | Detail |
|---|---|
| **JWT Tokens** | HS256-signed access (30 min) + refresh (7 days) tokens |
| **Password Security** | bcrypt hashing via passlib |
| **Validation** | Pydantic v2 schemas with custom password rules |
| **Async DB** | SQLAlchemy 2.0 async with SQLite (PostgreSQL-ready) |
| **Role-based Auth** | Regular user + Superuser access levels |
| **Token Refresh** | Stateless rotation — new pair on each refresh |
| **Swagger UI** | Auto-generated docs at `/docs` |
| **Tests** | pytest-asyncio test suite with in-memory DB |

---

## 🗂️ Project Structure

```
jwt-auth-api/
├── app/
│   ├── __init__.py
│   ├── main.py          # FastAPI app, lifespan, middleware
│   ├── config.py        # Settings via pydantic-settings
│   ├── database.py      # Async SQLAlchemy engine + session
│   ├── models.py        # User ORM model
│   ├── schemas.py       # Pydantic request/response schemas
│   ├── security.py      # JWT creation/decoding, password hashing, auth deps
│   ├── services.py      # UserService — business logic layer
│   └── routers/
│       ├── __init__.py
│       ├── auth.py      # /auth — register, login, refresh, logout
│       └── users.py     # /users — profile, update, password change, admin
├── tests/
│   └── test_auth.py     # Full pytest-asyncio test suite
├── .env.example
├── pytest.ini
├── requirements.txt
└── README.md
```

---

## 🚀 Quick Start

### 1. Install dependencies

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env — at minimum, change SECRET_KEY!
# Generate a strong key: openssl rand -hex 32
```

### 3. Run the server

```bash
uvicorn app.main:app --reload
```

Open **http://localhost:8000/docs** for the interactive Swagger UI.

---

## 📡 API Endpoints

### Authentication — `/api/v1/auth`

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/auth/register` | ❌ | Create a new account |
| `POST` | `/auth/login` | ❌ | Get access + refresh tokens |
| `POST` | `/auth/refresh` | ❌ | Rotate token pair |
| `POST` | `/auth/logout` | ✅ | Instruct client to clear tokens |

### Users — `/api/v1/users`

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/users/me` | ✅ | Get own profile |
| `PATCH` | `/users/me` | ✅ | Update name / email |
| `POST` | `/users/me/change-password` | ✅ | Change password |
| `DELETE` | `/users/me` | ✅ | Deactivate account |
| `GET` | `/users/` | 🔑 Admin | List all users |
| `GET` | `/users/{id}` | 🔑 Admin | Get user by ID |

### System

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health + DB status |
| `GET` | `/docs` | Swagger UI |
| `GET` | `/redoc` | ReDoc UI |

---

## 🔒 Token Flow

```
1. POST /auth/register     → 201 Created (UserResponse)
2. POST /auth/login        → { access_token, refresh_token, token_type }
3. GET  /users/me          → Authorization: Bearer <access_token>
4. POST /auth/refresh      → { refresh_token } → new token pair
5. POST /auth/logout       → discard tokens client-side
```

---

## 🧪 Running Tests

```bash
pytest -v
```

Tests use an isolated SQLite in-memory database — no side effects on your dev DB.

---

## 🏭 Production Checklist

- [ ] Set a strong `SECRET_KEY` (use `openssl rand -hex 32`)
- [ ] Switch `DATABASE_URL` to PostgreSQL (`asyncpg` driver)
- [ ] Store refresh tokens in Redis for true revocation support
- [ ] Set `DEBUG=false`
- [ ] Restrict `CORS` `allow_origins` to your frontend domain
- [ ] Run behind HTTPS (TLS termination at reverse proxy)
- [ ] Use Docker + Gunicorn for deployment

---

## 🧩 Password Policy

Passwords must be:
- At least **8 characters**
- Contain at least one **uppercase letter**
- Contain at least one **lowercase letter**
- Contain at least one **digit**

---

## 📦 Tech Stack

- **FastAPI** 0.115 — modern async web framework
- **python-jose** — JWT encode/decode
- **passlib[bcrypt]** — secure password hashing
- **SQLAlchemy 2.0** — async ORM
- **Pydantic v2** — data validation
- **pytest-asyncio** — async test support
