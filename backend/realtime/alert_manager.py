"""
Real-time Alert Manager for WebSocket Threat Broadcasting

This module manages WebSocket connections and broadcasts security alerts
to all connected clients in real-time. It provides a centralized way for
security walls to broadcast threats to authorized users.

Features:
- WebSocket connection pool management
- Client authentication and role-based access control
- Real-time alert broadcasting to all connected clients
- Graceful handling of disconnected clients
- Heartbeat monitoring for connection health
- Structured JSON alert format for frontend consumption

The AlertManager integrates with the Elemental Walls system to provide
instant notification of security threats to security officers and admins.
"""

import asyncio
import json
import logging
import time
import uuid
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
import websockets
from websockets.server import WebSocketServerProtocol
from websockets.exceptions import ConnectionClosed, WebSocketException

logger = logging.getLogger(__name__)

class ThreatLevel(str, Enum):
    """Threat level enumeration for security alerts."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SecurityAlert:
    """Structured security alert for WebSocket broadcasting."""
    alert_id: str
    wall_name: str
    threat_level: ThreatLevel
    timestamp: float
    details: Dict[str, Any]
    source_wall: str
    identifier: str
    alert_type: str
    severity: str
    mitigation_action: str

class WebSocketClient:
    """
    Represents a connected WebSocket client with authentication and metadata.
    
    Attributes:
        websocket: The WebSocket connection object
        user_id: ID of the authenticated user
        username: Username of the authenticated user
        role: User role (admin, officer)
        connected_at: Timestamp when connection was established
        last_heartbeat: Timestamp of last heartbeat response
        is_alive: Whether the connection is considered alive
    """
    
    def __init__(self, websocket: WebSocketServerProtocol, user_id: int, username: str, role: str):
        self.websocket = websocket
        self.user_id = user_id
        self.username = username
        self.role = role
        self.connected_at = time.time()
        self.last_heartbeat = time.time()
        self.is_alive = True
        self.client_id = str(uuid.uuid4())
    
    def __repr__(self) -> str:
        return f"<WebSocketClient(user_id={self.user_id}, username='{self.username}', role='{self.role}')>"
    
    async def send_alert(self, alert: SecurityAlert) -> bool:
        """
        Send a security alert to this client.
        
        Args:
            alert: SecurityAlert object to send
            
        Returns:
            bool: True if sent successfully, False otherwise
        """
        try:
            alert_data = asdict(alert)
            await self.websocket.send(json.dumps(alert_data))
            logger.debug(f"Alert sent to client {self.username} ({self.client_id})")
            return True
        except (ConnectionClosed, WebSocketException) as e:
            logger.warning(f"Failed to send alert to client {self.username}: {e}")
            self.is_alive = False
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending alert to client {self.username}: {e}")
            return False
    
    async def send_heartbeat(self) -> bool:
        """
        Send heartbeat ping to client and wait for pong response.
        
        Returns:
            bool: True if client responded, False otherwise
        """
        try:
            ping_message = {
                "type": "heartbeat",
                "timestamp": time.time(),
                "client_id": self.client_id
            }
            await self.websocket.send(json.dumps(ping_message))
            
            # Wait for pong response with timeout
            try:
                response = await asyncio.wait_for(self.websocket.recv(), timeout=5.0)
                pong_data = json.loads(response)
                if pong_data.get("type") == "pong" and pong_data.get("client_id") == self.client_id:
                    self.last_heartbeat = time.time()
                    return True
            except asyncio.TimeoutError:
                logger.warning(f"Heartbeat timeout for client {self.username}")
                return False
            except Exception as e:
                logger.warning(f"Heartbeat response error for client {self.username}: {e}")
                return False
                
        except (ConnectionClosed, WebSocketException) as e:
            logger.warning(f"Heartbeat failed for client {self.username}: {e}")
            self.is_alive = False
            return False
        except Exception as e:
            logger.error(f"Unexpected heartbeat error for client {self.username}: {e}")
            return False
        
        return False

class AlertManager:
    """
    Centralized alert manager for WebSocket threat broadcasting.
    
    This class manages all WebSocket connections and provides methods
    for security walls to broadcast alerts to connected clients.
    
    The manager maintains a connection pool, handles authentication,
    and ensures alerts are delivered to all authorized clients.
    """
    
    def __init__(self):
        """Initialize the AlertManager."""
        # Active WebSocket connections
        self.clients: Dict[str, WebSocketClient] = {}
        
        # Connection statistics
        self.total_connections = 0
        self.active_connections = 0
        self.alerts_sent = 0
        
        # Heartbeat configuration
        self.heartbeat_interval = 30  # seconds
        self.heartbeat_timeout = 60   # seconds
        
        # Cleanup task
        self.cleanup_task: Optional[asyncio.Task] = None
        self.is_running = False
        
        logger.info("AlertManager initialized")
    
    async def start(self):
        """Start the AlertManager background tasks."""
        if self.is_running:
            return
        
        self.is_running = True
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("AlertManager started")
    
    async def stop(self):
        """Stop the AlertManager and cleanup resources."""
        if not self.is_running:
            return
        
        self.is_running = False
        
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        
        # Close all connections
        await self._close_all_connections()
        logger.info("AlertManager stopped")
    
    async def register_client(self, websocket: WebSocketServerProtocol, user_id: int, username: str, role: str) -> str:
        """
        Register a new WebSocket client connection.
        
        Args:
            websocket: WebSocket connection object
            user_id: ID of the authenticated user
            username: Username of the authenticated user
            role: User role (admin, officer)
            
        Returns:
            str: Client ID for the new connection
            
        Raises:
            ValueError: If user role is not authorized for WebSocket access
        """
        # Verify user has appropriate role
        if role not in ["admin", "officer"]:
            raise ValueError(f"Role '{role}' not authorized for WebSocket access")
        
        # Create client object
        client = WebSocketClient(websocket, user_id, username, role)
        client_id = client.client_id
        
        # Store client
        self.clients[client_id] = client
        self.total_connections += 1
        self.active_connections += 1
        
        # Send welcome message
        welcome_message = {
            "type": "welcome",
            "client_id": client_id,
            "username": username,
            "role": role,
            "timestamp": time.time(),
            "message": "Connected to BlueWall Security Alert System"
        }
        
        try:
            await websocket.send(json.dumps(welcome_message))
            logger.info(f"New WebSocket client registered: {username} ({role}) - Client ID: {client_id}")
        except Exception as e:
            logger.error(f"Failed to send welcome message to {username}: {e}")
        
        return client_id
    
    async def unregister_client(self, client_id: str) -> bool:
        """
        Unregister a WebSocket client connection.
        
        Args:
            client_id: ID of the client to unregister
            
        Returns:
            bool: True if client was unregistered, False if not found
        """
        if client_id not in self.clients:
            return False
        
        client = self.clients[client_id]
        logger.info(f"Unregistering WebSocket client: {client.username} ({client_id})")
        
        # Remove from active clients
        del self.clients[client_id]
        self.active_connections -= 1
        
        return True
    
    async def broadcast_alert(self, alert_data: Dict[str, Any]) -> int:
        """
        Broadcast a security alert to all connected clients.
        
        This is the main method used by security walls to broadcast
        threats to all connected security officers and admins.
        
        Args:
            alert_data: Dictionary containing alert information with keys:
                - wall_name: Name of the security wall (air_wall, fire_wall, etc.)
                - threat_level: Threat level (low, medium, high, critical)
                - details: Additional alert details
                - source_wall: Source security wall identifier
                - identifier: Target identifier (IP, user, etc.)
                - alert_type: Type of alert
                - severity: Alert severity
                - mitigation_action: Recommended mitigation action
                
        Returns:
            int: Number of clients that received the alert successfully
        """
        # Create structured alert
        alert = SecurityAlert(
            alert_id=str(uuid.uuid4()),
            wall_name=alert_data.get("wall_name", "unknown"),
            threat_level=ThreatLevel(alert_data.get("threat_level", "medium")),
            timestamp=time.time(),
            details=alert_data.get("details", {}),
            source_wall=alert_data.get("source_wall", "unknown"),
            identifier=alert_data.get("identifier", "unknown"),
            alert_type=alert_data.get("alert_type", "security_threat"),
            severity=alert_data.get("severity", "medium"),
            mitigation_action=alert_data.get("mitigation_action", "investigate")
        )
        
        # Track alert
        self.alerts_sent += 1
        
        # Send to all connected clients
        successful_sends = 0
        failed_clients = []
        
        for client_id, client in list(self.clients.items()):
            if await client.send_alert(alert):
                successful_sends += 1
            else:
                failed_clients.append(client_id)
        
        # Remove failed clients
        for client_id in failed_clients:
            await self.unregister_client(client_id)
        
        logger.info(f"Alert broadcasted to {successful_sends}/{len(self.clients)} clients. "
                   f"Wall: {alert.wall_name}, Level: {alert.threat_level}, "
                   f"Type: {alert.alert_type}")
        
        return successful_sends
    
    async def send_to_user(self, user_id: int, alert_data: Dict[str, Any]) -> bool:
        """
        Send a security alert to a specific user.
        
        Args:
            user_id: ID of the user to send alert to
            alert_data: Alert data dictionary
            
        Returns:
            bool: True if sent successfully, False otherwise
        """
        # Find client by user ID
        target_client = None
        for client in self.clients.values():
            if client.user_id == user_id:
                target_client = client
                break
        
        if not target_client:
            logger.warning(f"No WebSocket client found for user ID: {user_id}")
            return False
        
        # Create and send alert
        alert = SecurityAlert(
            alert_id=str(uuid.uuid4()),
            wall_name=alert_data.get("wall_name", "unknown"),
            threat_level=ThreatLevel(alert_data.get("threat_level", "medium")),
            timestamp=time.time(),
            details=alert_data.get("details", {}),
            source_wall=alert_data.get("source_wall", "unknown"),
            identifier=alert_data.get("identifier", "unknown"),
            alert_type=alert_data.get("alert_type", "security_threat"),
            severity=alert_data.get("severity", "medium"),
            mitigation_action=alert_data.get("mitigation_action", "investigate")
        )
        
        return await target_client.send_alert(alert)
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """
        Get connection statistics for monitoring.
        
        Returns:
            dict: Dictionary containing connection statistics
        """
        return {
            "total_connections": self.total_connections,
            "active_connections": self.active_connections,
            "alerts_sent": self.alerts_sent,
            "clients": [
                {
                    "client_id": client.client_id,
                    "user_id": client.user_id,
                    "username": client.username,
                    "role": client.role,
                    "connected_at": client.connected_at,
                    "last_heartbeat": client.last_heartbeat,
                    "is_alive": client.is_alive
                }
                for client in self.clients.values()
            ]
        }
    
    async def _cleanup_loop(self):
        """Background task to cleanup dead connections and send heartbeats."""
        while self.is_running:
            try:
                await asyncio.sleep(self.heartbeat_interval)
                await self._perform_cleanup()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
    
    async def _perform_cleanup(self):
        """Perform cleanup of dead connections and heartbeat monitoring."""
        current_time = time.time()
        dead_clients = []
        
        # Check each client
        for client_id, client in self.clients.items():
            # Check if client is marked as dead
            if not client.is_alive:
                dead_clients.append(client_id)
                continue
            
            # Check heartbeat timeout
            if current_time - client.last_heartbeat > self.heartbeat_timeout:
                logger.warning(f"Client {client.username} heartbeat timeout, marking as dead")
                client.is_alive = False
                dead_clients.append(client_id)
                continue
            
            # Send heartbeat
            if not await client.send_heartbeat():
                dead_clients.append(client_id)
        
        # Remove dead clients
        for client_id in dead_clients:
            await self.unregister_client(client_id)
        
        if dead_clients:
            logger.info(f"Cleaned up {len(dead_clients)} dead connections")
    
    async def _close_all_connections(self):
        """Close all active WebSocket connections."""
        for client_id, client in list(self.clients.items()):
            try:
                await client.websocket.close()
            except Exception as e:
                logger.warning(f"Error closing connection for {client.username}: {e}")
        
        self.clients.clear()
        self.active_connections = 0

# Global instance of AlertManager
alert_manager = AlertManager()

# Convenience functions for external modules
async def broadcast_alert(alert_data: Dict[str, Any]) -> int:
    """
    Convenience function to broadcast a security alert.
    
    This function is used by security wall modules to broadcast
    threats without needing to import the AlertManager class.
    
    Args:
        alert_data: Alert data dictionary
        
    Returns:
        int: Number of clients that received the alert
    """
    return await alert_manager.broadcast_alert(alert_data)

async def send_to_user(user_id: int, alert_data: Dict[str, Any]) -> bool:
    """
    Convenience function to send alert to specific user.
    
    Args:
        user_id: ID of the user to send alert to
        alert_data: Alert data dictionary
        
    Returns:
        bool: True if sent successfully
    """
    return await alert_manager.send_to_user(user_id, alert_data)

def get_connection_stats() -> Dict[str, Any]:
    """
    Get connection statistics.
    
    Returns:
        dict: Connection statistics
    """
    return alert_manager.get_connection_stats()
