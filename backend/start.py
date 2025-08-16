#!/usr/bin/env python3
"""
BlueWall Backend Startup Script

This script initializes the database and starts the FastAPI application.
It should be run when starting the application for the first time or
when you need to reset the database.
"""

import os
import sys
import logging
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Main startup function."""
    try:
        logger.info("Starting BlueWall Backend...")
        
        # Check if we're in the right directory
        if not Path("main.py").exists():
            logger.error("main.py not found. Please run this script from the backend directory.")
            sys.exit(1)
        
        # Import and initialize database
        logger.info("Initializing database...")
        from db.session import init_db, check_db_connection
        
        # Check database connection
        if not check_db_connection():
            logger.error("Database connection failed!")
            sys.exit(1)
        
        # Initialize database tables
        init_db()
        logger.info("Database initialized successfully!")
        
        # Import and run the FastAPI app
        logger.info("Starting FastAPI application...")
        import uvicorn
        from main import app
        
        # Get configuration from environment
        host = os.getenv("HOST", "0.0.0.0")
        port = int(os.getenv("PORT", "8000"))
        reload = os.getenv("ENVIRONMENT", "development") == "development"
        
        logger.info(f"Starting server on {host}:{port}")
        logger.info(f"Environment: {'development' if reload else 'production'}")
        logger.info(f"API Documentation: http://{host}:{port}/docs")
        logger.info(f"Health Check: http://{host}:{port}/health")
        
        # Start the server
        uvicorn.run(
            "main:app",
            host=host,
            port=port,
            reload=reload,
            log_level="info"
        )
        
    except KeyboardInterrupt:
        logger.info("Shutdown requested by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
