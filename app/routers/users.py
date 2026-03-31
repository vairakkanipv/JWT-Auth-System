from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from app.database import get_db
from app.schemas import UserResponse, UserUpdate, MessageResponse
from app.security import get_current_user, get_current_superuser
from app.services import UserService

router = APIRouter(prefix="/users", tags=["Users"])


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8, max_length=128)


# ── Current user endpoints ────────────────────────────────────────────────────

@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
)
async def get_my_profile(current_user=Depends(get_current_user)):
    """Return the authenticated user's profile."""
    return current_user


@router.patch(
    "/me",
    response_model=UserResponse,
    summary="Update current user profile",
)
async def update_my_profile(
    update_data: UserUpdate,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update full_name or email of the authenticated user."""
    return await UserService.update(db, current_user, update_data)


@router.post(
    "/me/change-password",
    response_model=MessageResponse,
    summary="Change current user's password",
)
async def change_my_password(
    body: ChangePasswordRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Change the authenticated user's password."""
    await UserService.change_password(
        db, current_user, body.current_password, body.new_password
    )
    return MessageResponse(message="Password changed successfully.")


@router.delete(
    "/me",
    response_model=MessageResponse,
    summary="Deactivate current user account",
)
async def deactivate_my_account(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Soft-delete (deactivate) the authenticated user's account."""
    await UserService.deactivate(db, current_user)
    return MessageResponse(message="Account deactivated. Contact support to reactivate.")


# ── Admin endpoints ───────────────────────────────────────────────────────────

@router.get(
    "/",
    response_model=list[UserResponse],
    summary="[Admin] List all users",
    dependencies=[Depends(get_current_superuser)],
)
async def list_users(
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    """List all registered users. Superuser access required."""
    return await UserService.get_all(db, skip=skip, limit=limit)


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    summary="[Admin] Get user by ID",
    dependencies=[Depends(get_current_superuser)],
)
async def get_user(user_id: int, db: AsyncSession = Depends(get_db)):
    """Get a specific user by ID. Superuser access required."""
    from fastapi import HTTPException
    user = await UserService.get_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user
