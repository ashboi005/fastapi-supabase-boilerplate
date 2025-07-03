from fastapi import APIRouter, Depends, HTTPException, status, Request, Form
from dependencies.rbac import require_admin, require_admin_write, require_analytics, require_user_management, require_user_management_write
from routers.auth.auth import get_current_user
from routers.users.schemas import UserListItem, UserListResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from config import get_db
from models import UserProfile
from typing import Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["Admin"])

@router.get("/users", response_model=UserListResponse, dependencies=[Depends(require_user_management)])
async def list_all_users(
    page: int = 1,
    limit: int = 20,
    role: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Admin only: List all users with pagination and optional role filter
    """
    try:
        offset = (page - 1) * limit
        
        query = select(UserProfile)
        if role:
            query = query.where(UserProfile.role == role)
        
        query = query.offset(offset).limit(limit)
        result = await db.execute(query)
        users = result.scalars().all()
        
        user_list = [UserListItem.model_validate(user.__dict__) for user in users]
        
        return UserListResponse(
            users=user_list,
            page=page,
            limit=limit,
            total=len(users)
        )
        
    except Exception as e:
        logger.error(f"List users failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve users"
        )

@router.put("/users/{user_id}/role", dependencies=[Depends(require_user_management_write)])
async def update_user_role(
    user_id: str,
    new_role: str = Form(..., description="New role: user, moderator, admin, agent"),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Admin only: Update user role
    """
    try:
        if new_role not in ['user', 'moderator', 'admin', 'agent']:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid role. Must be one of: user, moderator, admin, agent"
            )
        
        result = await db.execute(
            select(UserProfile).where(UserProfile.user_id == user_id)
        )
        user_profile = result.scalar_one_or_none()
        
        if not user_profile:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        user_profile.role = new_role
        user_profile.updated_at = datetime.utcnow()
        
        await db.commit()
        await db.refresh(user_profile)
        
        return {
            "message": f"User role updated to {new_role}",
            "user_id": user_id,
            "new_role": new_role,
            "updated_by": current_user["role"]
        }
        
    except Exception as e:
        await db.rollback()
        logger.error(f"Update user role failed: {str(e)}")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user role"
        )
