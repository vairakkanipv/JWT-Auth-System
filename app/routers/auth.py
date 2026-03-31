from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.schemas import (
    Token, UserCreate, UserResponse, LoginRequest,
    RefreshTokenRequest, MessageResponse
)
from app.security import (
    create_access_token, create_refresh_token, decode_token, get_current_user
)
from app.services import UserService

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
)
async def register(user_in: UserCreate, db: AsyncSession = Depends(get_db)):
    """
    Register a new user account.

    - **username**: 3–50 chars, alphanumeric + underscores only
    - **email**: valid email address
    - **password**: min 8 chars, must include uppercase, lowercase, and digit
    - **full_name**: optional display name
    """
    user = await UserService.create(db, user_in)
    return user


@router.post(
    "/login",
    response_model=Token,
    summary="Obtain JWT access + refresh tokens",
)
async def login(credentials: LoginRequest, db: AsyncSession = Depends(get_db)):
    """
    Authenticate with username/password.

    Returns a short-lived **access token** (30 min) and a long-lived
    **refresh token** (7 days).
    """
    user = await UserService.authenticate(db, credentials.username, credentials.password)
    return Token(
        access_token=create_access_token(user.username),
        refresh_token=create_refresh_token(user.username),
    )


@router.post(
    "/refresh",
    response_model=Token,
    summary="Refresh access token using refresh token",
)
async def refresh_tokens(
    body: RefreshTokenRequest, db: AsyncSession = Depends(get_db)
):
    """
    Exchange a valid refresh token for a new token pair.

    The old refresh token is invalidated implicitly by issuing a new one
    (stateless rotation — store refresh tokens server-side in production).
    """
    token_data = decode_token(body.refresh_token)

    if token_data.type != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type. Provide a refresh token.",
        )

    user = await UserService.get_by_username(db, token_data.sub)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    return Token(
        access_token=create_access_token(user.username),
        refresh_token=create_refresh_token(user.username),
    )


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Logout (client-side token invalidation)",
)
async def logout(current_user=Depends(get_current_user)):
    """
    Logout endpoint.

    Since JWTs are stateless, true server-side invalidation requires a
    token blocklist (Redis recommended for production). Here we instruct
    the client to discard stored tokens.
    """
    return MessageResponse(message=f"User '{current_user.username}' logged out successfully.")
