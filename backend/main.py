"""
BlueWall Backend - FastAPI Application Entry Point

This module serves as the main entry point for the BlueWall backend API.
It provides authentication endpoints and implements role-based access control
for admin and officer users.

Features:
- User authentication with username/password + TOTP
- JWT token generation and validation
- Role-based access control (Admin/Officer)
- Protected routes with different permission levels
- Security wall integration for threat detection
- Comprehensive event logging and monitoring
"""

from fastapi import FastAPI, Depends, HTTPException, status, Request, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any
import logging
import time
import uuid
import json

from db.session import get_db, init_db
from db.models import User, Event, SecurityAlert
from auth.security import (
    authenticate_user, create_access_token, get_current_user,
    get_current_admin_user, get_current_officer_user, verify_totp
)

# Import security wall modules
from security_walls.air_wall import AirWall
from security_walls.fire_wall import FireWall
from security_walls.earth_wall import EarthWall
from security_walls.water_wall import WaterWall
from security_walls.ether_wall import EtherWall

# Import event logging
from logger.events import EventLogger, EventType, EventSeverity, EventCategory

# Import realtime alert manager
from realtime.alert_manager import alert_manager, broadcast_alert, get_connection_stats

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="BlueWall Backend API",
    description="Secure backend with role-based access control and comprehensive security monitoring",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize security walls
air_wall = AirWall()
fire_wall = FireWall()
earth_wall = EarthWall()
water_wall = WaterWall()
ether_wall = EtherWall()

# Initialize event logger
event_logger = EventLogger()

# Pydantic models for request/response
class LoginRequest(BaseModel):
    username: str
    password: str
    totp_code: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    role: str
    username: str

class GameEventRequest(BaseModel):
    event_type: str
    player_id: str
    player_name: str
    game_action: str
    game_state: Dict[str, Any]
    coordinates: Optional[Dict[str, float]] = None
    target_id: Optional[str] = None
    item_id: Optional[str] = None
    amount: Optional[float] = None
    game_timestamp: Optional[float] = None
    server_id: Optional[str] = None
    correlation_id: Optional[str] = None

class SecurityWallConfig(BaseModel):
    wall_name: str
    config: Dict[str, Any]

# Middleware for request monitoring
@app.middleware("http")
async def security_monitoring_middleware(request: Request, call_next):
    """Middleware to monitor all requests through security walls."""
    start_time = time.time()
    
    # Extract request information
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    method = request.method
    url = str(request.url)
    
    # Get user information if authenticated
    user_id = None
    username = None
    session_id = None
    
    # Check for authorization header
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.startswith("Bearer "):
        try:
            token = auth_header.split(" ")[1]
            # Decode token to get user info (simplified)
            # In production, use proper JWT decoding
            pass
        except Exception:
            pass
    
    # Monitor through Air Wall (network traffic analysis)
    air_wall_data = {
        "ip_address": client_ip,
        "user_id": user_id,
        "endpoint": url,
        "timestamp": start_time,
        "request_size": 0,  # Would need to calculate actual size
        "user_agent": user_agent,
        "geo_data": {}  # Would need geo-IP service
    }
    
    air_alert = air_wall.analyze_request(air_wall_data)
    if air_alert:
        # Log security alert
        alert_data = {
            "event_id": str(uuid.uuid4()),
            "alert_type": air_alert.alert_type,
            "severity": air_alert.severity,
            "source_wall": "air_wall",
            "identifier": air_alert.identifier,
            "details": air_alert.details,
            "mitigation_action": air_alert.mitigation_action
        }
        event_logger.log_security_alert(alert_data)
        
        # Log event through security wall
        wall_data = {
            "wall_name": "air_wall",
            "event_type": air_alert.alert_type,
            "severity": air_alert.severity,
            "target": air_alert.identifier,
            "details": air_alert.details,
            "action_taken": air_alert.mitigation_action,
            "threat_level": air_alert.severity
        }
        event_logger.log_security_wall_event(wall_data)
    
    # Monitor through Water Wall (API misuse detection)
    water_wall_data = {
        "ip_address": client_ip,
        "user_id": user_id,
        "endpoint": url,
        "method": method,
        "status_code": 200,  # Will be updated after response
        "response_time_ms": 0,  # Will be updated after response
        "request_size": 0,
        "user_agent": user_agent,
        "headers": dict(request.headers),
        "geo_data": {}
    }
    
    water_alert = water_wall.monitor_request(water_wall_data)
    if water_alert:
        # Log security alert
        alert_data = {
            "event_id": str(uuid.uuid4()),
            "alert_type": water_alert.alert_type,
            "severity": water_alert.severity,
            "source_wall": "water_wall",
            "identifier": water_alert.identifier,
            "details": water_alert.details,
            "mitigation_action": water_alert.mitigation_action
        }
        event_logger.log_security_alert(alert_data)
    
    # Process the request
    response = await call_next(request)
    
    # Update response information
    response_time = (time.time() - start_time) * 1000  # Convert to milliseconds
    water_wall_data["response_time_ms"] = response_time
    water_wall_data["status_code"] = response.status_code
    
    # Log the API access event
    api_event_data = {
        "event_type": EventType.API_ACCESS,
        "severity": EventSeverity.INFO,
        "category": EventCategory.SYSTEM,
        "user_id": user_id,
        "username": username,
        "ip_address": client_ip,
        "session_id": session_id,
        "details": {
            "method": method,
            "url": url,
            "status_code": response.status_code,
            "response_time_ms": response_time,
            "user_agent": user_agent
        },
        "source_module": "api_gateway",
        "correlation_id": str(uuid.uuid4())
    }
    event_logger.log_event(api_event_data)
    
    return response

# Database initialization
@app.on_event("startup")
async def startup_event():
    """Initialize database and security systems on startup."""
    try:
        # Initialize database
        init_db()
        logger.info("Database initialized successfully")
        
        # Start AlertManager for WebSocket connections
        await alert_manager.start()
        logger.info("AlertManager started successfully")
        
        # Log system startup
        startup_event_data = {
            "event_type": EventType.SYSTEM_STARTUP,
            "severity": EventSeverity.INFO,
            "category": EventCategory.SYSTEM,
            "details": {
                "version": "2.0.0",
                "security_walls": ["air_wall", "fire_wall", "earth_wall", "water_wall", "ether_wall"],
                "features": ["authentication", "role_based_access", "security_monitoring", "event_logging", "websocket_alerts"]
            },
            "source_module": "main_app"
        }
        event_logger.log_event(startup_event_data)
        
        logger.info("BlueWall Backend started successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize application: {str(e)}")
        raise

# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup resources on shutdown."""
    try:
        # Stop AlertManager
        await alert_manager.stop()
        logger.info("AlertManager stopped successfully")
        
        logger.info("BlueWall Backend shutdown completed")
        
    except Exception as e:
        logger.error(f"Error during shutdown: {str(e)}")

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "version": "2.0.0",
        "security_walls": {
            "air_wall": "active",
            "fire_wall": "active",
            "earth_wall": "active",
            "water_wall": "active",
            "ether_wall": "active"
        }
    }

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "message": "BlueWall Backend API",
        "version": "2.0.0",
        "description": "Secure backend with comprehensive security monitoring",
        "endpoints": {
            "docs": "/docs",
            "health": "/health",
            "login": "/login",
            "events": "/events"
        }
    }

# Authentication endpoint
@app.post("/login", response_model=LoginResponse)
async def login(login_request: LoginRequest, request: Request):
    """User login with username, password, and TOTP."""
    try:
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        
        # Authenticate user
        db = next(get_db())
        user = authenticate_user(db, login_request.username, login_request.password)
        
        if not user:
            # Log failed login attempt
            auth_event_data = {
                "event_type": EventType.LOGIN_FAILED,
                "severity": EventSeverity.WARNING,
                "category": EventCategory.AUTHENTICATION,
                "username": login_request.username,
                "ip_address": client_ip,
                "details": {
                    "success": False,
                    "failure_reason": "Invalid username or password",
                    "totp_used": False,
                    "user_agent": request.headers.get("user-agent", ""),
                    "auth_method": "password"
                },
                "source_module": "auth_system"
            }
            event_logger.log_authentication_event(auth_event_data)
            
            # Monitor through Fire Wall
            fire_wall_data = {
                "username": login_request.username,
                "ip_address": client_ip,
                "success": False,
                "user_agent": request.headers.get("user-agent", ""),
                "failure_reason": "Invalid username or password",
                "totp_used": False,
                "timestamp": time.time()
            }
            
            fire_alert = fire_wall.record_login_attempt(fire_wall_data)
            if fire_alert:
                # Log security alert
                alert_data = {
                    "event_id": str(uuid.uuid4()),
                    "alert_type": fire_alert.alert_type,
                    "severity": fire_alert.severity,
                    "source_wall": "fire_wall",
                    "identifier": fire_alert.identifier,
                    "details": fire_alert.details,
                    "mitigation_action": fire_alert.mitigation_action
                }
                event_logger.log_security_alert(alert_data)
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        
        # Verify TOTP
        if not verify_totp(user.totp_secret, login_request.totp_code):
            # Log failed TOTP attempt
            auth_event_data = {
                "event_type": EventType.LOGIN_FAILED,
                "severity": EventSeverity.WARNING,
                "category": EventCategory.AUTHENTICATION,
                "user_id": user.id,
                "username": user.username,
                "ip_address": client_ip,
                "details": {
                    "success": False,
                    "failure_reason": "Invalid TOTP code",
                    "totp_used": True,
                    "user_agent": request.headers.get("user-agent", ""),
                    "auth_method": "totp"
                },
                "source_module": "auth_system"
            }
            event_logger.log_authentication_event(auth_event_data)
            
            # Monitor through Fire Wall
            fire_wall_data = {
                "username": user.username,
                "ip_address": client_ip,
                "success": False,
                "user_agent": request.headers.get("user-agent", ""),
                "failure_reason": "Invalid TOTP code",
                "totp_used": True,
                "timestamp": time.time()
            }
            
            fire_alert = fire_wall.record_login_attempt(fire_wall_data)
            if fire_alert:
                # Log security alert
                alert_data = {
                    "event_id": str(uuid.uuid4()),
                    "alert_type": fire_alert.alert_type,
                    "severity": fire_alert.severity,
                    "source_wall": "fire_wall",
                    "identifier": fire_alert.identifier,
                    "details": fire_alert.details,
                    "mitigation_action": fire_alert.mitigation_action
                }
                event_logger.log_security_alert(alert_data)
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid TOTP code"
            )
        
        # Update last login
        user.update_last_login()
        db.commit()
        
        # Create access token
        access_token = create_access_token(
            data={"sub": user.username, "role": user.role}
        )
        
        # Log successful login
        auth_event_data = {
            "event_type": EventType.USER_LOGIN,
            "severity": EventSeverity.INFO,
            "category": EventCategory.AUTHENTICATION,
            "user_id": user.id,
            "username": user.username,
            "ip_address": client_ip,
            "details": {
                "success": True,
                "totp_used": True,
                "user_agent": request.headers.get("user-agent", ""),
                "auth_method": "password_totp"
            },
            "source_module": "auth_system"
        }
        event_logger.log_authentication_event(auth_event_data)
        
        # Monitor through Fire Wall
        fire_wall_data = {
            "username": user.username,
            "ip_address": client_ip,
            "success": True,
            "user_agent": request.headers.get("user-agent", ""),
            "totp_used": True,
            "timestamp": time.time()
        }
        
        fire_alert = fire_wall.record_login_attempt(fire_wall_data)
        if fire_alert:
            # Log security alert
            alert_data = {
                "event_id": str(uuid.uuid4()),
                "alert_type": fire_alert.alert_type,
                "severity": fire_alert.severity,
                "source_wall": "fire_wall",
                "identifier": fire_alert.identifier,
                "details": fire_alert.details,
                "mitigation_action": fire_alert.mitigation_action
            }
            event_logger.log_security_alert(alert_data)
        
        return LoginResponse(
            access_token=access_token,
            token_type="bearer",
            role=user.role,
            username=user.username
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

# Game event logging endpoint
@app.post("/events")
async def log_game_event(
    event_request: GameEventRequest,
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Log game events from the game server."""
    try:
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        
        # Log the game event
        game_event_data = {
            "event_type": event_request.event_type,
            "player_id": event_request.player_id,
            "player_name": event_request.player_name,
            "game_action": event_request.game_action,
            "game_state": event_request.game_state,
            "coordinates": event_request.coordinates,
            "target_id": event_request.target_id,
            "item_id": event_request.item_id,
            "amount": event_request.amount,
            "game_timestamp": event_request.game_timestamp,
            "server_id": event_request.server_id,
            "ip_address": client_ip,
            "session_id": str(uuid.uuid4()),
            "correlation_id": event_request.correlation_id
        }
        
        event_id = event_logger.log_game_event(game_event_data)
        
        # Route event through all security walls for analysis
        
        # 1. Air Wall - Network traffic analysis
        air_wall_data = {
            "ip_address": client_ip,
            "user_id": event_request.player_id,
            "endpoint": "/events",
            "timestamp": time.time(),
            "request_size": len(str(event_request.dict())),
            "user_agent": request.headers.get("user-agent", ""),
            "geo_data": {}
        }
        
        air_alert = air_wall.analyze_request(air_wall_data)
        if air_alert:
            # Log security alert
            alert_data = {
                "event_id": event_id,
                "alert_type": air_alert.alert_type,
                "severity": air_alert.severity,
                "source_wall": "air_wall",
                "identifier": air_alert.identifier,
                "details": air_alert.details,
                "mitigation_action": air_alert.mitigation_action
            }
            event_logger.log_security_alert(alert_data)
        
        # 2. Water Wall - API misuse detection
        water_wall_data = {
            "ip_address": client_ip,
            "user_id": event_request.player_id,
            "endpoint": "/events",
            "method": "POST",
            "status_code": 200,
            "response_time_ms": 0,
            "request_size": len(str(event_request.dict())),
            "user_agent": request.headers.get("user-agent", ""),
            "headers": dict(request.headers),
            "geo_data": {}
        }
        
        water_alert = water_wall.monitor_request(water_wall_data)
        if water_alert:
            # Log security alert
            alert_data = {
                "event_id": event_id,
                "alert_type": water_alert.alert_type,
                "severity": water_alert.severity,
                "source_wall": "water_wall",
                "identifier": water_alert.identifier,
                "details": water_alert.details,
                "mitigation_action": water_alert.mitigation_action
            }
            event_logger.log_security_alert(alert_data)
        
        # 3. Ether Wall - Game anti-cheat
        ether_wall_data = {
            "user_id": event_request.player_id,
            "action_type": "game_action",
            "action_data": {
                "game_action": event_request.game_action,
                "coordinates": event_request.coordinates,
                "game_state": event_request.game_state
            },
            "client_hash": request.headers.get("x-client-hash", "unknown"),
            "session_id": str(uuid.uuid4()),
            "ip_address": client_ip,
            "game_state": event_request.game_state
        }
        
        is_valid, ether_alert = ether_wall.validate_game_action(ether_wall_data)
        if not is_valid and ether_alert:
            # Log security alert
            alert_data = {
                "event_id": event_id,
                "alert_type": ether_alert.alert_type,
                "severity": ether_alert.severity,
                "source_wall": "ether_wall",
                "identifier": ether_alert.identifier,
                "details": ether_alert.details,
                "mitigation_action": ether_alert.mitigation_action
            }
            event_logger.log_security_alert(alert_data)
        
        return {
            "message": "Event logged successfully",
            "event_id": event_id,
            "timestamp": time.time()
        }
        
    except Exception as e:
        logger.error(f"Error logging game event: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to log event"
        )

# Security wall status endpoint
@app.get("/security/status")
async def get_security_status(current_user: User = Depends(get_current_admin_user)):
    """Get status of all security walls (admin only)."""
    try:
        return {
            "air_wall": air_wall.get_traffic_summary(),
            "fire_wall": fire_wall.get_security_summary(),
            "earth_wall": earth_wall.get_integrity_summary(),
            "water_wall": water_wall.get_api_summary(),
            "ether_wall": ether_wall.get_anti_cheat_summary(),
            "event_logger": event_logger.get_event_summary(),
            "websocket_status": get_connection_stats()
        }
    except Exception as e:
        logger.error(f"Error getting security status: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get security status"
        )

# Security wall configuration endpoint
@app.post("/security/configure")
async def configure_security_wall(
    config: SecurityWallConfig,
    current_user: User = Depends(get_current_admin_user)
):
    """Configure security wall settings (admin only)."""
    try:
        # This would update the configuration of the specified security wall
        # For now, just return success
        return {
            "message": f"Configuration updated for {config.wall_name}",
            "wall_name": config.wall_name,
            "timestamp": time.time()
        }
    except Exception as e:
        logger.error(f"Error configuring security wall: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to configure security wall"
        )

# Admin-only system information endpoint
@app.get("/admin/system-info")
async def get_system_info(current_user: User = Depends(get_current_admin_user)):
    """Get system information (admin only)."""
    return {
        "system": "BlueWall Backend",
        "version": "2.0.0",
        "user": {
            "id": current_user.id,
            "username": current_user.username,
            "role": current_user.role
        },
        "security_walls": {
            "air_wall": "active",
            "fire_wall": "active",
            "earth_wall": "active",
            "water_wall": "active",
            "ether_wall": "active"
        },
        "timestamp": time.time()
    }

# Officer and admin monitoring endpoint
@app.get("/officer/monitoring")
async def get_monitoring_data(current_user: User = Depends(get_current_officer_user)):
    """Get monitoring data (officer and admin)."""
    return {
        "user": {
            "id": current_user.id,
            "username": current_user.username,
            "role": current_user.role
        },
        "monitoring_data": {
            "active_users": 0,  # Would query database
            "recent_events": 0,  # Would query database
            "security_alerts": 0,  # Would query database
            "system_health": "healthy"
        },
        "timestamp": time.time()
    }

# User profile endpoint
@app.get("/user/profile")
async def get_user_profile(current_user: User = Depends(get_current_user)):
    """Get current user profile."""
    return current_user.to_dict()

# Event query endpoint (admin only)
@app.get("/admin/events")
async def query_events(
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    current_user: User = Depends(get_current_admin_user)
):
    """Query events with filters (admin only)."""
    try:
        # This would query the events table with filters
        # For now, return mock data
        return {
            "events": [],
            "filters": {
                "event_type": event_type,
                "severity": severity,
                "limit": limit
            },
            "total": 0,
            "timestamp": time.time()
        }
    except Exception as e:
        logger.error(f"Error querying events: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to query events"
        )

# Security alerts endpoint (admin only)
@app.get("/admin/security-alerts")
async def get_security_alerts(
    status: Optional[str] = None,
    source_wall: Optional[str] = None,
    limit: int = 100,
    current_user: User = Depends(get_current_admin_user)
):
    """Get security alerts with filters (admin only)."""
    try:
        # This would query the security_alerts table with filters
        # For now, return mock data
        return {
            "alerts": [],
            "filters": {
                "status": status,
                "source_wall": source_wall,
                "limit": limit
            },
            "total": 0,
            "timestamp": time.time()
        }
    except Exception as e:
        logger.error(f"Error querying security alerts: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to query security alerts"
        )

# WebSocket endpoint for real-time security alerts
@app.websocket("/ws/security/alerts")
async def websocket_security_alerts(websocket: WebSocket):
    """
    WebSocket endpoint for real-time security alerts.
    
    This endpoint allows authenticated users with admin or officer roles
    to receive real-time security alerts from all security walls.
    
    Authentication is performed via query parameters containing JWT token.
    The connection is maintained and alerts are broadcasted in real-time.
    
    Features:
    - JWT token authentication via query parameter
    - Role-based access control (admin, officer only)
    - Real-time threat broadcasting
    - Automatic reconnection handling
    - Heartbeat monitoring for connection health
    
    Query Parameters:
        token: JWT access token for authentication
        
    WebSocket Messages:
        - Incoming: pong responses for heartbeat
        - Outgoing: security alerts, welcome message, heartbeat pings
    """
    try:
        # Accept the WebSocket connection
        await websocket.accept()
        
        # Get authentication token from query parameters
        token = websocket.query_params.get("token")
        if not token:
            await websocket.close(code=4001, reason="Authentication token required")
            return
        
        # Validate JWT token and get user
        try:
            # Decode and validate JWT token
            from auth.security import decode_access_token
            payload = decode_access_token(token)
            username = payload.get("sub")
            role = payload.get("role")
            
            if not username or not role:
                await websocket.close(code=4001, reason="Invalid token payload")
                return
            
            # Verify user exists and has appropriate role
            db = next(get_db())
            user = User.get_by_username(db, username)
            
            if not user or not user.is_active:
                await websocket.close(code=4001, reason="User not found or inactive")
                return
            
            if role not in ["admin", "officer"]:
                await websocket.close(code=4003, reason="Insufficient privileges")
                return
            
            # Register client with AlertManager
            client_id = await alert_manager.register_client(
                websocket, user.id, username, role
            )
            
            logger.info(f"WebSocket client connected: {username} ({role}) - Client ID: {client_id}")
            
            # Handle WebSocket communication
            try:
                while True:
                    # Wait for messages from client
                    data = await websocket.receive_text()
                    
                    try:
                        message = json.loads(data)
                        message_type = message.get("type")
                        
                        if message_type == "pong":
                            # Handle heartbeat response
                            if message.get("client_id") == client_id:
                                # Update heartbeat timestamp (handled by AlertManager)
                                pass
                        elif message_type == "ping":
                            # Send pong response
                            pong_message = {
                                "type": "pong",
                                "client_id": client_id,
                                "timestamp": time.time()
                            }
                            await websocket.send_text(json.dumps(pong_message))
                        else:
                            logger.debug(f"Received unknown message type: {message_type} from {username}")
                            
                    except json.JSONDecodeError:
                        logger.warning(f"Invalid JSON received from {username}: {data}")
                        continue
                        
            except WebSocketDisconnect:
                logger.info(f"WebSocket client disconnected: {username} ({client_id})")
            except Exception as e:
                logger.error(f"WebSocket error for {username}: {e}")
                await websocket.close(code=1011, reason="Internal server error")
            finally:
                # Unregister client
                await alert_manager.unregister_client(client_id)
                
        except Exception as e:
            logger.error(f"Authentication error in WebSocket: {e}")
            await websocket.close(code=4001, reason="Authentication failed")
            
    except WebSocketDisconnect:
        logger.info("WebSocket connection closed by client")
    except Exception as e:
        logger.error(f"WebSocket endpoint error: {e}")
        try:
            await websocket.close(code=1011, reason="Internal server error")
        except:
            pass

# Recent alerts endpoint (admin and officer)
@app.get("/alerts/recent")
async def get_recent_alerts(
    limit: int = 50,
    current_user: User = Depends(get_current_officer_user)
):
    """
    Get the most recent security alerts.
    
    This endpoint returns the last N security alerts from the database,
    accessible to users with admin or officer roles.
    
    Args:
        limit: Maximum number of alerts to return (default: 50, max: 100)
        
    Returns:
        dict: Recent alerts with metadata
        
    Raises:
        HTTPException: If limit is invalid or database error occurs
    """
    try:
        # Validate limit parameter
        if limit < 1 or limit > 100:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Limit must be between 1 and 100"
            )
        
        # Get recent alerts from database
        db = next(get_db())
        alerts = SecurityAlert.get_recent_alerts(db, limit=limit)
        
        # Convert to dictionary format
        alert_list = []
        for alert in alerts:
            alert_dict = alert.to_dict()
            # Add additional fields for frontend
            alert_dict["wall_display_name"] = alert.wall_name or alert.source_wall
            alert_dict["threat_level_display"] = alert.threat_level or alert.severity
            alert_list.append(alert_dict)
        
        return {
            "alerts": alert_list,
            "total": len(alert_list),
            "limit": limit,
            "timestamp": time.time(),
            "user": {
                "id": current_user.id,
                "username": current_user.username,
                "role": current_user.role
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting recent alerts: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get recent alerts"
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
