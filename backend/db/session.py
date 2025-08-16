"""
Database Session Management

This module handles database connection setup, session creation, and connection
pooling for the BlueWall backend application using SQLAlchemy.

Features:
- Database engine configuration with connection pooling
- Session factory for database operations
- Dependency injection for FastAPI routes
- Environment-based configuration support
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool
import os
from typing import Generator
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Database configuration
# Default to SQLite for development, can be overridden via environment variables
DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "sqlite:///./bluewall.db"
)

# Database engine configuration
engine = create_engine(
    DATABASE_URL,
    # Connection pooling configuration
    poolclass=QueuePool,
    pool_size=10,  # Number of connections to maintain
    max_overflow=20,  # Additional connections that can be created
    pool_pre_ping=True,  # Verify connections before use
    pool_recycle=3600,  # Recycle connections after 1 hour
    echo=os.getenv("SQL_ECHO", "false").lower() == "true"  # SQL query logging
)

# Session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# Base class for database models
Base = declarative_base()

def get_db() -> Generator[Session, None, None]:
    """
    Dependency function to get database session.
    
    This function is used by FastAPI to inject database sessions
    into route handlers. It ensures proper session cleanup.
    
    Yields:
        Session: SQLAlchemy database session
        
    Example:
        @app.get("/users")
        def get_users(db: Session = Depends(get_db)):
            return db.query(User).all()
    """
    db = SessionLocal()
    try:
        logger.debug("Database session created")
        yield db
    except Exception as e:
        logger.error(f"Database session error: {str(e)}")
        db.rollback()
        raise
    finally:
        logger.debug("Database session closed")
        db.close()

def init_db() -> None:
    """
    Initialize database by creating all tables.
    
    This function should be called during application startup
    to ensure all database tables exist.
    """
    try:
        # Import models to ensure they are registered with Base
        from .models import User
        
        # Create all tables
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
        
        # Create default admin user if it doesn't exist
        create_default_admin()
        
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        raise

def create_default_admin() -> None:
    """
    Create a default admin user if no users exist in the database.
    
    This function creates an initial admin user for first-time setup.
    The credentials should be changed immediately after first login.
    """
    try:
        db = SessionLocal()
        
        # Check if any users exist
        from .models import User
        user_count = db.query(User).count()
        
        if user_count == 0:
            from auth.security import get_password_hash, generate_totp_secret
            
            # Create default admin user
            default_admin = User(
                username="admin",
                password_hash=get_password_hash("admin123"),  # Change this in production!
                role="admin",
                totp_secret=generate_totp_secret()
            )
            
            db.add(default_admin)
            db.commit()
            
            logger.warning(
                "Default admin user created with username: 'admin' and password: 'admin123'. "
                "Please change these credentials immediately!"
            )
            
            # Log the TOTP secret for initial setup
            logger.info(f"Default admin TOTP secret: {default_admin.totp_secret}")
            
        db.close()
        
    except Exception as e:
        logger.error(f"Failed to create default admin user: {str(e)}")
        if 'db' in locals():
            db.close()

def close_db_connections() -> None:
    """
    Close all database connections.
    
    This function should be called during application shutdown
    to properly close all database connections.
    """
    try:
        engine.dispose()
        logger.info("Database connections closed successfully")
    except Exception as e:
        logger.error(f"Failed to close database connections: {str(e)}")

# Database health check
def check_db_connection() -> bool:
    """
    Check if database connection is working.
    
    Returns:
        bool: True if connection is successful, False otherwise
    """
    try:
        db = SessionLocal()
        db.execute("SELECT 1")
        db.close()
        return True
    except Exception as e:
        logger.error(f"Database connection check failed: {str(e)}")
        return False
