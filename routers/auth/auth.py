from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from config import get_db, get_supabase_client
from models import UserProfile
from .schemas import (
    UserRegister, 
    UserLogin, 
    AuthResponse, 
    UserResponse,
    TokenResponse,
    ForgotPasswordRequest,
    ResetPasswordRequest
)
from .helpers import auth_helpers
from typing import Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/auth", tags=["Authentication"])

# Security scheme for JWT tokens
security = HTTPBearer()

# Get Supabase client
supabase = get_supabase_client()

# Dependency to get current user from token
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
):
    """Get current user from JWT token"""
    token = credentials.credentials
    
    # Verify token with Supabase
    supabase_user = auth_helpers.verify_token(token)
    
    # Get user profile from our database
    result = await db.execute(
        select(UserProfile).where(UserProfile.id == supabase_user.id)
    )
    user_profile = result.scalar_one_or_none()
    
    if not user_profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User profile not found"
        )
    
    return {
        "supabase_user": supabase_user,
        "profile": user_profile
    }

@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserRegister,
    db: AsyncSession = Depends(get_db)
):
    """
    Register a new user
    
    This endpoint:
    1. Creates a user account in Supabase Auth
    2. Creates a user profile in our database
    3. Returns authentication tokens
    """
    try:
        # Step 1: Check if username already exists in our database
        existing_user = await db.execute(
            select(UserProfile).where(UserProfile.username == user_data.username)
        )
        if existing_user.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already taken"
            )
            
        # Step 2: Register with Supabase Auth
        auth_response = supabase.auth.sign_up({
            "email": user_data.email,
            "password": user_data.password,
            "options": {
                "data": {
                    "username": user_data.username,
                    "full_name": user_data.full_name
                }
            }
        })
        
        if auth_response.user is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to create user account"
            )
        
        # Step 3: Create user profile in our database
        supabase_user_id = auth_response.user.id
        new_user_profile = UserProfile(
            id=supabase_user_id,  # Use Supabase user ID as primary key
            email=user_data.email,
            username=user_data.username,
            full_name=user_data.full_name,
            created_at=datetime.utcnow()
        )
        
        db.add(new_user_profile)
        await db.commit()
        await db.refresh(new_user_profile)
        
        # Format response
        user_response = UserResponse(
            id=new_user_profile.id,
            email=new_user_profile.email,
            username=new_user_profile.username,
            full_name=new_user_profile.full_name,
            bio=new_user_profile.bio,
            profile_image_url=new_user_profile.profile_image_url,
            created_at=new_user_profile.created_at,
            updated_at=new_user_profile.updated_at
        )
        
        # Check if session exists (it might be None if email confirmation is required)
        if auth_response.session is None:
            # Return success but indicate email verification is needed
            return AuthResponse(
                access_token="",  # Empty token
                refresh_token="",  # Empty token
                user=user_response,
                message="User created successfully. Please check your email to verify your account before logging in."
            )
        
        return AuthResponse(
            access_token=auth_response.session.access_token,
            refresh_token=auth_response.session.refresh_token,
            user=user_response
        )
        
    except Exception as e:
        await db.rollback()
        logger.error(f"Registration failed: {str(e)}")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )

@router.post("/login", response_model=AuthResponse)
async def login(
    user_data: UserLogin,
    db: AsyncSession = Depends(get_db)
):
    """
    Login user
    
    This endpoint:
    1. Authenticates user with Supabase Auth
    2. Returns authentication tokens and user profile
    """
    try:
        # Login with Supabase
        auth_response = supabase.auth.sign_in_with_password({
            "email": user_data.email,
            "password": user_data.password
        })
        
        if auth_response.user is None or auth_response.session is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # Get user profile from our database
        result = await db.execute(
            select(UserProfile).where(UserProfile.id == auth_response.user.id)
        )
        user_profile = result.scalar_one_or_none()
        
        if not user_profile:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User profile not found"
            )
        
        # Format response
        user_response = UserResponse(
            id=user_profile.id,
            email=user_profile.email,
            username=user_profile.username,
            full_name=user_profile.full_name,
            bio=user_profile.bio,
            profile_image_url=user_profile.profile_image_url,
            created_at=user_profile.created_at,
            updated_at=user_profile.updated_at
        )
        
        return AuthResponse(
            access_token=auth_response.session.access_token,
            refresh_token=auth_response.session.refresh_token,
            user=user_response
        )
        
    except Exception as e:
        logger.error(f"Login failed: {str(e)}")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    refresh_token: str
):
    """
    Refresh access token using refresh token
    """
    try:
        session = await auth_helpers.refresh_token(refresh_token)
        
        return TokenResponse(
            access_token=session.access_token
        )
        
    except Exception as e:
        logger.error(f"Token refresh failed: {str(e)}")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token refresh failed"
        )

@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user = Depends(get_current_user)
):
    """
    Get current user's profile
    """
    profile = current_user["profile"]
    
    return UserResponse(
        id=profile.id,
        email=profile.email,
        username=profile.username,
        full_name=profile.full_name,
        bio=profile.bio,
        profile_image_url=profile.profile_image_url,
        created_at=profile.created_at,
        updated_at=profile.updated_at
    )

@router.post("/forgot-password")
async def forgot_password(
    request_data: ForgotPasswordRequest
):
    """
    Send password reset email
    
    This endpoint sends a password reset email to the user's email address.
    The email will contain a link that redirects to your frontend with the necessary tokens.
    
    The redirect URL is automatically determined based on the environment:
    - Production: https://yourblog.com/reset-password
    - Development: http://localhost:3000/reset-password
    """
    try:
        # Determine redirect URL based on environment
        from config import ENVIRONMENT
        
        if ENVIRONMENT == "prod":
            # Production frontend URL
            redirect_url = "https://yourblog.com/reset-password"
        elif ENVIRONMENT == "dev":
            # Development frontend URL
            redirect_url = "http://localhost:3000/reset-password"
        else:
            # Fallback for testing
            redirect_url = "http://localhost:3000/reset-password"
        
        # Send password reset email via Supabase
        response = supabase.auth.reset_password_email(
            request_data.email,
            options={"redirect_to": redirect_url}
        )
        
        return {"message": "If an account with that email exists, a password reset link has been sent."}
        
    except Exception as e:
        logger.error(f"Password reset email failed: {str(e)}")
        # Always return success for security (don't reveal if email exists)
        return {"message": "If an account with that email exists, a password reset link has been sent."}

@router.post("/reset-password")
async def reset_password(
    reset_data: ResetPasswordRequest
):
    """
    Reset password using the tokens from reset email
    
    This endpoint allows users to set a new password using the tokens
    they received in their password reset email.
    """
    try:
        # First, we need to establish a session with the provided tokens
        # Set the session in the Supabase client
        session_data = {
            "access_token": reset_data.access_token,
            "refresh_token": reset_data.refresh_token
        }
        
        # Set the session to authenticate the password update
        response = supabase.auth.set_session(
            access_token=reset_data.access_token,
            refresh_token=reset_data.refresh_token
        )
        
        if not response.session:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset tokens"
            )
        
        # Now update the password
        update_response = supabase.auth.update_user({
            "password": reset_data.new_password
        })
        
        if update_response.user is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to update password"
            )
        
        # Sign out to invalidate the reset session
        supabase.auth.sign_out()
        
        return {"message": "Password reset successfully. You can now log in with your new password."}
        
    except Exception as e:
        logger.error(f"Password reset failed: {str(e)}")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password reset failed. Please try requesting a new reset link."
        )

@router.post("/logout")
async def logout(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Logout user (invalidate token on Supabase)
    """
    try:
        token = credentials.credentials
        
        # Sign out from Supabase (this invalidates the token)
        supabase.auth.sign_out()
        
        return {"message": "Successfully logged out"}
        
    except Exception as e:
        logger.error(f"Logout failed: {str(e)}")
        return {"message": "Logout completed"}  # Always return success for logout

@router.get("/verify-reset-token")
async def verify_reset_token(
    access_token: str,
    refresh_token: str
):
    """
    Verify reset tokens from email redirect
    
    This endpoint helps verify that the tokens from the password reset email are valid.
    Frontend should extract access_token and refresh_token from the URL parameters
    and call this endpoint to verify them before showing the password reset form.
    """
    try:
        # Try to set the session with the provided tokens
        response = supabase.auth.set_session(
            access_token=access_token,
            refresh_token=refresh_token
        )
        
        if not response.session:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset tokens"
            )
        
        # Sign out immediately after verification
        supabase.auth.sign_out()
        
        return {
            "message": "Reset tokens are valid",
            "email": response.user.email if response.user else None
        }
        
    except Exception as e:
        logger.error(f"Token verification failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset tokens"
        )