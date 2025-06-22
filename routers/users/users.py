from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from config import get_db
from models import UserProfile
from routers.auth.auth import get_current_user
from dependencies.rbac import require_profile_read, require_profile_write, require_user_management, require_user_management_write, require_user_management, require_user_management_write
from .schemas import UserProfileUpdate, UserProfileResponse, ProfileImageUpload
from .helpers import user_helpers
from typing import Optional
from datetime import datetime
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["Users"])

security = HTTPBearer()

@router.get("/me", response_model=UserProfileResponse, dependencies=[Depends(require_profile_read)])
async def get_current_user_profile(
    current_user = Depends(get_current_user)
):
    """Get current user's profile information"""
    profile = current_user["profile"]
    supabase_user = current_user["supabase_user"]
    
    return UserProfileResponse(
        id=str(profile.id),
        user_id=str(profile.user_id),
        username=profile.username,
        email=supabase_user.email,  
        first_name=profile.first_name,
        last_name=profile.last_name,
        display_name=profile.display_name,
        bio=profile.bio,
        avatar_url=profile.avatar_url,
        custom_font=profile.custom_font,
        custom_colors=profile.custom_colors,
        date_of_birth=profile.date_of_birth,
        timezone=profile.timezone,
        language=profile.language,
        preferences=profile.preferences,
        created_at=profile.created_at,
        updated_at=profile.updated_at
    )

@router.put("/me", response_model=UserProfileResponse, dependencies=[Depends(require_profile_write)])
async def update_current_user_profile(
    profile_update: UserProfileUpdate,
    current_user = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Update current user's profile information"""
    try:
        profile = current_user["profile"]
        supabase_user = current_user["supabase_user"]
        
        if profile_update.username and profile_update.username != profile.username:
            result = await db.execute(
                select(UserProfile).where(
                    and_(
                        UserProfile.username == profile_update.username,
                        UserProfile.id != profile.id
                    )
                )
            )
            existing_user = result.scalar_one_or_none()
            if existing_user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username already taken"
                )
        
        update_data = profile_update.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(profile, field, value)
        

        profile.updated_at = datetime.utcnow()
        
        await db.commit()
        await db.refresh(profile)
        
        return UserProfileResponse(
            id=str(profile.id),
            user_id=str(profile.user_id),
            username=profile.username,
            email=supabase_user.email,  
            first_name=profile.first_name,
            last_name=profile.last_name,
            display_name=profile.display_name,
            bio=profile.bio,
            avatar_url=profile.avatar_url,
            date_of_birth=profile.date_of_birth,
            timezone=profile.timezone,
            language=profile.language,
            preferences=profile.preferences,
            created_at=profile.created_at,
            updated_at=profile.updated_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating user profile: {str(e)}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update profile"
        )

@router.post("/me/profile-image", response_model=ProfileImageUpload)
async def upload_profile_image(
    file: UploadFile = File(..., description="Profile image file (JPEG, PNG, GIF, or WebP, max 5MB)"),
    current_user = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Upload a new profile image
    
    Accepts image files in the following formats:
    - JPEG (.jpg, .jpeg)
    - PNG (.png) 
    - GIF (.gif)
    - WebP (.webp)
    
    Maximum file size: 5MB
    """
    try:
        profile = current_user["profile"]
        
        if not file.filename:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No file uploaded"
            )
        
        if profile.avatar_url:
            await user_helpers.delete_profile_image(profile.avatar_url)
        

        image_url = await user_helpers.upload_profile_image(str(profile.id), file)
        
        profile.avatar_url = image_url
        profile.updated_at = datetime.utcnow()
        await db.commit()
        
        return ProfileImageUpload(
            avatar_url=image_url,
            message="Profile image uploaded successfully"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error uploading profile image: {str(e)}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to upload profile image"
        )

@router.delete("/me/profile-image")
async def delete_profile_image(
    current_user = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Delete current user's profile image"""
    try:
        profile = current_user["profile"]
        
        if not profile.avatar_url:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No profile image found"
            )
        
        deleted = await user_helpers.delete_profile_image(profile.avatar_url)

        profile.avatar_url = None
        profile.updated_at = datetime.utcnow()
        
        await db.commit()
        
        return {
            "message": "Profile image deleted successfully",
            "storage_deleted": deleted
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting profile image: {str(e)}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete profile image"        )

# Admin-only endpoints
@router.get("/admin/users", dependencies=[Depends(require_user_management)])
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
        
        return {
            "users": [
                {
                    "id": str(user.id),
                    "user_id": str(user.user_id),
                    "username": user.username,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "display_name": user.display_name,
                    "role": user.role,
                    "created_at": user.created_at,
                    "updated_at": user.updated_at
                }
                for user in users
            ],
            "page": page,
            "limit": limit,
            "total": len(users)
        }
        
    except Exception as e:
        logger.error(f"List users failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve users"
        )

@router.put("/admin/users/{user_id}/role", dependencies=[Depends(require_user_management_write)])
async def update_user_role(
    user_id: str,
    new_role: str = Form(..., description="New role: user, moderator, admin"),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Admin only: Update user role
    """
    try:
        if new_role not in ['user', 'moderator', 'admin']:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid role. Must be one of: user, moderator, admin"
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
            "new_role": new_role
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
