from fastapi import APIRouter, Depends, HTTPException, status, Request
from dependencies.rbac import require_admin, require_admin_write, require_analytics
from routers.auth.auth import get_current_user
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["Admin"])

@router.get("/dashboard", dependencies=[Depends(require_admin)])
async def admin_dashboard(
    request: Request,
    current_user = Depends(get_current_user)
):
    """
    Admin dashboard - requires admin role
    """
    return {
        "message": "Welcome to admin dashboard",
        "user_role": current_user["profile"].role,
        "access_granted": True
    }

@router.get("/analytics", dependencies=[Depends(require_analytics)])
async def get_analytics(
    request: Request,
    current_user = Depends(get_current_user)
):
    """
    Analytics endpoint - requires analytics permission
    """
    return {
        "total_users": 100,  
        "active_users": 85,
        "new_users_today": 5,
        "user_role": current_user["profile"].role
    }

@router.post("/system-settings", dependencies=[Depends(require_admin_write)])
async def update_system_settings(
    request: Request,
    current_user = Depends(get_current_user)
):
    """
    Update system settings - requires admin write permission
    """
    return {
        "message": "System settings updated successfully",
        "updated_by": current_user["profile"].role
    }
