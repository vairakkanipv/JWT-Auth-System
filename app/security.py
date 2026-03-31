from datetime import datetime, timedelta, timezone
import hashlib
import base64
import bcrypt
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
from app.database import get_db
from app.schemas import TokenPayload

# Bearer token scheme
bearer_scheme = HTTPBearer()


# ── Password Utilities ────────────────────────────────────────────────────────

def _prepare_password(password: str) -> bytes:
    """
    SHA-256 + base64 encode the password before bcrypt.
    Result is always 44 ASCII chars — safely under bcrypt's 72-byte limit.
    """
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.b64encode(digest)


def hash_password(password: str) -> str:
    """Hash a plain-text password using bcrypt directly."""
    hashed = bcrypt.hashpw(_prepare_password(password), bcrypt.gensalt(rounds=12))
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain-text password against its bcrypt hash."""
    return bcrypt.checkpw(
        _prepare_password(plain_password),
        hashed_password.encode("utf-8")
    )


# ── JWT Utilities ─────────────────────────────────────────────────────────────

def create_access_token(subject: str) -> str:
    """Create a short-lived JWT access token."""
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload = {
        "sub": subject,
        "exp": expire,
        "type": "access",
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(subject: str) -> str:
    """Create a long-lived JWT refresh token."""
    expire = datetime.now(timezone.utc) + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    payload = {
        "sub": subject,
        "exp": expire,
        "type": "refresh",
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token: str) -> TokenPayload:
    """Decode and validate a JWT token. Raises HTTPException on failure."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        token_type: str = payload.get("type")
        exp: int = payload.get("exp")
        if username is None or token_type is None:
            raise credentials_exception
        return TokenPayload(sub=username, exp=exp, type=token_type)
    except JWTError:
        raise credentials_exception


# ── Dependency: Current User ──────────────────────────────────────────────────

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
):
    """FastAPI dependency — resolves Bearer token to User ORM object."""
    from app.services import UserService

    token_data = decode_token(credentials.credentials)

    if token_data.type != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type. Use access token.",
        )

    user = await UserService.get_by_username(db, token_data.sub)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        )
    return user


async def get_current_superuser(current_user=Depends(get_current_user)):
    """Dependency that requires superuser privileges."""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough privileges",
        )
    return current_user
