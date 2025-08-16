"""
Real-time Module for BlueWall Backend

This module provides real-time functionality including:
- WebSocket threat broadcasting
- Live security alert streaming
- Real-time connection management
"""

from .alert_manager import (
    AlertManager,
    WebSocketClient,
    SecurityAlert,
    ThreatLevel,
    alert_manager,
    broadcast_alert,
    send_to_user,
    get_connection_stats
)

__all__ = [
    "AlertManager",
    "WebSocketClient", 
    "SecurityAlert",
    "ThreatLevel",
    "alert_manager",
    "broadcast_alert",
    "send_to_user",
    "get_connection_stats"
]
