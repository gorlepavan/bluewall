"""
Security Module for Authentication and Authorization

This module handles all security-related functionality for the BlueWall backend
including JWT token management, password hashing, and TOTP validation.

Features:
- JWT token creation and validation
- Secure password hashing with bcrypt
- TOTP (Time-based One-Time Password) validation
- User authentication and authorization
- Secure secret generation
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Union, Any
from jose import JWTError, jwt
from passlib.context import CryptContext
import pyotp
import secrets
import string
import os
import logging
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from db.session import get_db
from db.models import User

# Configure logging
logger = logging.getLogger(__name__)

# Security configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Password hashing context using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT token security scheme
security = HTTPBearer()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against its hash.
    
    Args:
        plain_password: The plain text password to verify
        hashed_password: The bcrypt hash to verify against
        
    Returns:
        bool: True if password matches, False otherwise
    """
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.error(f"Password verification error: {str(e)}")
        return False

def get_password_hash(password: str) -> str:
    """
    Generate a bcrypt hash for a plain password.
    
    Args:
        password: The plain text password to hash
        
    Returns:
        str: The bcrypt hash of the password
    """
    try:
        return pwd_context.hash(password)
    except Exception as e:
        logger.error(f"Password hashing error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to hash password"
        )

def generate_totp_secret() -> str:
    """
    Generate a secure random secret for TOTP generation.
    
    This function creates a 32-character random string suitable
    for use with Google Authenticator and other TOTP apps.
    
    Returns:
        str: A 32-character random secret string
    """
    try:
        # Generate 32 random characters from letters and digits
        alphabet = string.ascii_letters + string.digits
        secret = ''.join(secrets.choice(alphabet) for _ in range(32))
        logger.debug("Generated new TOTP secret")
        return secret
    except Exception as e:
        logger.error(f"Failed to generate TOTP secret: {str(e)}")
        # Fallback to a simpler method if secrets module fails
        import random
        alphabet = string.ascii_letters + string.digits
        secret = ''.join(random.choice(alphabet) for _ in range(32))
        return secret

def verify_totp(secret: str, totp_code: str, window: int = 1) -> bool:
    """
    Verify a TOTP code against the user's secret.
    
    Args:
        secret: The user's TOTP secret
        totp_code: The TOTP code to verify
        window: Time window for validation (default: 1, allows for clock skew)
        
    Returns:
        bool: True if TOTP code is valid, False otherwise
    """
    try:
        # Create TOTP object with the user's secret
        totp = pyotp.TOTP(secret)
        
        # Verify the code with the specified window
        is_valid = totp.verify(totp_code, valid_window=window)
        
        if is_valid:
            logger.debug("TOTP verification successful")
        else:
            logger.warning("TOTP verification failed")
            
        return is_valid
        
    except Exception as e:
        logger.error(f"TOTP verification error: {str(e)}")
        return False

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token with user data and expiration.
    
    Args:
        data: Dictionary containing user data (sub, role, etc.)
        expires_delta: Optional custom expiration time
        
    Returns:
        str: The encoded JWT token
    """
    try:
        to_encode = data.copy()
        
        # Set expiration time
        if expires_delta:
            expire = datetime.now(dtimezone.utc) + expires_delta
        else:
            expire = datetime.now(dtimezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
        to_encode.update({"exp": expire})
        
        # Encode the JWT token
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        
        logger.debug(f"Created access token for user: {data.get('sub', 'unknown')}")
        return encoded_jwt
        
    except Exception as e:
        logger.error(f"Failed to create access token: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create access token"
        )

def decode_access_token(token: str) -> dict:
    """
    Decode and validate a JWT access token.
    
    Args:
        token: JWT token to decode
        
    Returns:
        dict: Decoded token payload
        
    Raises:
        JWTError: If token is invalid or expired
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        logger.debug(f"JWT token decoded successfully")
        return payload
    except JWTError as e:
        logger.error(f"JWT token decode error: {str(e)}")
        raise JWTError("Invalid or expired token")

def verify_token(token: str) -> Optional[dict]:
    """
    Verify and decode a JWT token.
    
    Args:
        token: The JWT token to verify
        
    Returns:
        dict: The decoded token payload if valid, None otherwise
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        
        if username is None or role is None:
            logger.warning("Invalid token payload: missing username or role")
            return None
            
        logger.debug(f"Token verified for user: {username}")
        return payload
        
    except JWTError as e:
        logger.warning(f"JWT token verification failed: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during token verification: {str(e)}")
        return None

def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    """
    Authenticate a user with username and password.
    
    Args:
        db: Database session
        username: Username to authenticate
        password: Plain text password to verify
        
    Returns:
        User: User object if authentication successful, None otherwise
    """
    try:
        # Get user from database
        user = User.get_by_username(db, username)
        
        if not user:
            logger.warning(f"Authentication failed: user not found - {username}")
            return None
            
        if not user.is_active:
            logger.warning(f"Authentication failed: inactive user - {username}")
            return None
            
        # Verify password
        if not verify_password(password, user.password_hash):
            logger.warning(f"Authentication failed: invalid password - {username}")
            return None
            
        logger.info(f"User authenticated successfully: {username}")
        return user
        
    except Exception as e:
        logger.error(f"Authentication error for user {username}: {str(e)}")
        return None

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """
    Get the current authenticated user from JWT token.
    
    This function is used as a dependency in FastAPI routes to ensure
    the user is authenticated and to provide user information.
    
    Args:
        credentials: HTTP Bearer token from request
        db: Database session dependency
        
    Returns:
        User: The authenticated user object
        
    Raises:
        HTTPException: If authentication fails or user not found
    """
    try:
        # Verify the JWT token
        payload = verify_token(credentials.credentials)
        if payload is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Get user from database
        user = User.get_by_username(db, username)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Inactive user",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        logger.debug(f"Current user retrieved: {username}")
        return user
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting current user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """
    Get the current active user.
    
    This is a convenience function that ensures the user is active.
    
    Args:
        current_user: The current authenticated user
        
    Returns:
        User: The active user object
        
    Raises:
        HTTPException: If user is inactive
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user

def get_current_admin_user(current_user: User = Depends(get_current_user)) -> User:
    """
    Get the current user and ensure they have admin privileges.
    
    Args:
        current_user: The current authenticated user
        
    Returns:
        User: The admin user object
        
    Raises:
        HTTPException: If user is not an admin
    """
    if not current_user.is_admin():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user

def get_current_officer_user(current_user: User = Depends(get_current_user)) -> User:
    """
    Get the current user and ensure they have officer privileges.
    
    Args:
        current_user: The current authenticated user
        
    Returns:
        User: The officer user object
        
    Raises:
        HTTPException: If user is not an officer or admin
    """
    if not current_user.is_officer():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Officer or admin access required"
        )
    return current_user
