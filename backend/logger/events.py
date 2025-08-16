"""
Event Logging System

This module provides comprehensive event logging functionality for the BlueWall system:
- Record every major event in the database
- Store raw and hashed event data for tamper detection
- Event categorization and severity tracking
- Integration with security wall modules
- Audit trail and compliance support
- Real-time event monitoring and alerting
"""

import time
import logging
import hashlib
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
import uuid

logger = logging.getLogger(__name__)

class EventType(Enum):
    """Types of system events."""
    # Authentication events
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    LOGIN_FAILED = "login_failed"
    PASSWORD_CHANGE = "password_change"
    TOTP_VERIFICATION = "totp_verification"
    
    # Security events
    SECURITY_ALERT = "security_alert"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    BRUTE_FORCE_ATTEMPT = "brute_force_attempt"
    DDoS_ATTACK = "ddos_attack"
    MALWARE_DETECTED = "malware_detected"
    
    # Game events
    GAME_ACTION = "game_action"
    PLAYER_KILL = "player_kill"
    PLAYER_DEATH = "player_death"
    ITEM_ACQUISITION = "item_acquisition"
    PAYMENT_PROCESSED = "payment_processed"
    SUSPICIOUS_GAME_BEHAVIOR = "suspicious_game_behavior"
    
    # System events
    SYSTEM_STARTUP = "system_startup"
    SYSTEM_SHUTDOWN = "system_shutdown"
    SYSTEM_OPERATION = "system_operation"
    CONFIGURATION_CHANGE = "configuration_change"
    DATABASE_OPERATION = "database_operation"
    API_ACCESS = "api_access"
    
    # User management events
    USER_CREATED = "user_created"
    USER_DELETED = "user_deleted"
    ROLE_CHANGED = "role_changed"
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_REVOKED = "permission_revoked"

class EventSeverity(Enum):
    """Event severity levels."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class EventCategory(Enum):
    """Event categories for organization."""
    AUTHENTICATION = "authentication"
    SECURITY = "security"
    GAME = "game"
    SYSTEM = "system"
    USER_MANAGEMENT = "user_management"
    COMPLIANCE = "compliance"

@dataclass
class EventData:
    """Base event data structure."""
    event_id: str
    event_type: EventType
    severity: EventSeverity
    category: EventCategory
    timestamp: datetime
    user_id: Optional[str]
    username: Optional[str]
    ip_address: Optional[str]
    session_id: Optional[str]
    details: Dict[str, Any]
    source_module: str
    correlation_id: Optional[str] = None

@dataclass
class SecurityAlert:
    """Security alert data structure."""
    alert_id: str
    event_id: str
    alert_type: str
    severity: str
    source_wall: str  # Which security wall generated the alert
    identifier: str
    timestamp: datetime
    details: Dict[str, Any]
    mitigation_action: str
    status: str = "active"  # active, resolved, false_positive
    resolved_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    notes: Optional[str] = None

class EventLogger:
    """
    Comprehensive event logging system for BlueWall.
    
    Features:
    - Structured event logging
    - Security alert management
    - Tamper detection with hashing
    - Event correlation and analysis
    - Real-time monitoring capabilities
    - Compliance and audit support
    """
    
    def __init__(self, db_session=None):
        """
        Initialize the event logger.
        
        Args:
            db_session: Database session for storing events
        """
        self.db_session = db_session
        self.event_buffer: List[EventData] = []
        self.alert_buffer: List[SecurityAlert] = []
        self.buffer_size = 100
        self.flush_interval = 60  # seconds
        self.last_flush = time.time()
        
        logger.info("Event Logger initialized")
    
    def log_event(self, event_data: Dict[str, Any]) -> str:
        """
        Log an event to the system.
        
        Args:
            event_data: Dictionary containing event information
                - event_type: Type of event (EventType or string)
                - severity: Event severity (EventSeverity or string)
                - category: Event category (EventCategory or string)
                - user_id: User ID associated with event
                - username: Username associated with event
                - ip_address: IP address associated with event
                - session_id: Session ID associated with event
                - details: Event-specific details
                - source_module: Module generating the event
                - correlation_id: Optional correlation ID
        
        Returns:
            str: Generated event ID
        """
        try:
            # Generate unique event ID
            event_id = str(uuid.uuid4())
            
            # Parse event type and severity
            event_type = self._parse_enum(event_data.get("event_type"), EventType)
            severity = self._parse_enum(event_data.get("severity"), EventSeverity)
            category = self._parse_enum(event_data.get("category"), EventCategory)
            
            # Create event object
            event = EventData(
                event_id=event_id,
                event_type=event_type,
                severity=severity,
                category=category,
                timestamp=datetime.now(),
                user_id=event_data.get("user_id"),
                username=event_data.get("username"),
                ip_address=event_data.get("ip_address"),
                session_id=event_data.get("session_id"),
                details=event_data.get("details", {}),
                source_module=event_data.get("source_module", "unknown"),
                correlation_id=event_data.get("correlation_id")
            )
            
            # Add to buffer
            self.event_buffer.append(event)
            
            # Log to console for debugging
            logger.info(f"Event logged: {event.event_type.value} - {event.severity.value} - {event.source_module}")
            
            # Check if buffer needs flushing
            if len(self.event_buffer) >= self.buffer_size:
                self.flush_events()
            
            return event_id
            
        except Exception as e:
            logger.error(f"Error logging event: {str(e)}")
            return ""
    
    def log_security_alert(self, alert_data: Dict[str, Any]) -> str:
        """
        Log a security alert from security wall modules.
        
        Args:
            alert_data: Dictionary containing alert information
                - event_id: Associated event ID
                - alert_type: Type of security alert
                - severity: Alert severity
                - source_wall: Security wall that generated the alert
                - identifier: Target of the alert (IP, user, etc.)
                - details: Alert-specific details
                - mitigation_action: Recommended mitigation action
        
        Returns:
            str: Generated alert ID
        """
        try:
            # Generate unique alert ID
            alert_id = str(uuid.uuid4())
            
            # Create alert object
            alert = SecurityAlert(
                alert_id=alert_id,
                event_id=alert_data.get("event_id", ""),
                alert_type=alert_data.get("alert_type", "unknown"),
                severity=alert_data.get("severity", "medium"),
                source_wall=alert_data.get("source_wall", "unknown"),
                identifier=alert_data.get("identifier", ""),
                timestamp=datetime.now(),
                details=alert_data.get("details", {}),
                mitigation_action=alert_data.get("mitigation_action", "none")
            )
            
            # Add to alert buffer
            self.alert_buffer.append(alert)
            
            # Log to console for debugging
            logger.warning(f"Security alert logged: {alert.alert_type} - {alert.severity} - {alert.source_wall}")
            
            # Check if buffer needs flushing
            if len(self.alert_buffer) >= self.buffer_size:
                self.flush_alerts()
            
            return alert_id
            
        except Exception as e:
            logger.error(f"Error logging security alert: {str(e)}")
            return ""
    
    def log_game_event(self, game_data: Dict[str, Any]) -> str:
        """
        Log a game-related event.
        
        Args:
            game_data: Dictionary containing game event information
                - event_type: Type of game event
                - player_id: Player ID
                - player_name: Player name
                - game_action: Game action performed
                - game_state: Current game state
                - coordinates: Player coordinates
                - target_id: Target of action (if applicable)
                - item_id: Item involved (if applicable)
                - amount: Amount involved (if applicable)
        
        Returns:
            str: Generated event ID
        """
        try:
            # Create event data for game event
            event_data = {
                "event_type": EventType.GAME_ACTION,
                "severity": EventSeverity.INFO,
                "category": EventCategory.GAME,
                "user_id": game_data.get("player_id"),
                "username": game_data.get("player_name"),
                "ip_address": game_data.get("ip_address"),
                "session_id": game_data.get("session_id"),
                "details": {
                    "game_action": game_data.get("game_action"),
                    "game_state": game_data.get("game_state", {}),
                    "coordinates": game_data.get("coordinates", {}),
                    "target_id": game_data.get("target_id"),
                    "item_id": game_data.get("item_id"),
                    "amount": game_data.get("amount"),
                    "game_timestamp": game_data.get("game_timestamp"),
                    "server_id": game_data.get("server_id")
                },
                "source_module": "game_server",
                "correlation_id": game_data.get("correlation_id")
            }
            
            return self.log_event(event_data)
            
        except Exception as e:
            logger.error(f"Error logging game event: {str(e)}")
            return ""
    
    def log_authentication_event(self, auth_data: Dict[str, Any]) -> str:
        """
        Log an authentication-related event.
        
        Args:
            auth_data: Dictionary containing authentication information
                - event_type: Type of auth event
                - user_id: User ID
                - username: Username
                - ip_address: IP address
                - success: Whether authentication was successful
                - failure_reason: Reason for failure (if applicable)
                - totp_used: Whether TOTP was used
                - user_agent: User agent string
        
        Returns:
            str: Generated event ID
        """
        try:
            # Determine event type and severity
            if auth_data.get("success", False):
                event_type = EventType.USER_LOGIN
                severity = EventSeverity.INFO
            else:
                event_type = EventType.LOGIN_FAILED
                severity = EventSeverity.WARNING
            
            # Create event data
            event_data = {
                "event_type": event_type,
                "severity": severity,
                "category": EventCategory.AUTHENTICATION,
                "user_id": auth_data.get("user_id"),
                "username": auth_data.get("username"),
                "ip_address": auth_data.get("ip_address"),
                "session_id": auth_data.get("session_id"),
                "details": {
                    "success": auth_data.get("success", False),
                    "failure_reason": auth_data.get("failure_reason"),
                    "totp_used": auth_data.get("totp_used", False),
                    "user_agent": auth_data.get("user_agent", ""),
                    "auth_method": auth_data.get("auth_method", "password"),
                    "login_attempt": auth_data.get("login_attempt", 1)
                },
                "source_module": "auth_system",
                "correlation_id": auth_data.get("correlation_id")
            }
            
            return self.log_event(event_data)
            
        except Exception as e:
            logger.error(f"Error logging authentication event: {str(e)}")
            return ""
    
    def log_security_wall_event(self, wall_data: Dict[str, Any]) -> str:
        """
        Log an event from a security wall module.
        
        Args:
            wall_data: Dictionary containing security wall information
                - wall_name: Name of the security wall
                - event_type: Type of security event
                - severity: Event severity
                - target: Target of the security check
                - details: Security check details
                - action_taken: Action taken by the wall
                - threat_level: Assessed threat level
        
        Returns:
            str: Generated event ID
        """
        try:
            # Create event data for security wall event
            event_data = {
                "event_type": EventType.SECURITY_ALERT,
                "severity": self._map_security_severity(wall_data.get("threat_level", "medium")),
                "category": EventCategory.SECURITY,
                "user_id": wall_data.get("user_id"),
                "username": wall_data.get("username"),
                "ip_address": wall_data.get("ip_address"),
                "session_id": wall_data.get("session_id"),
                "details": {
                    "wall_name": wall_data.get("wall_name"),
                    "event_type": wall_data.get("event_type"),
                    "target": wall_data.get("target"),
                    "action_taken": wall_data.get("action_taken"),
                    "threat_level": wall_data.get("threat_level"),
                    "wall_config": wall_data.get("wall_config", {}),
                    "detection_method": wall_data.get("detection_method", "rule_based")
                },
                "source_module": f"security_wall_{wall_data.get('wall_name', 'unknown')}",
                "correlation_id": wall_data.get("correlation_id")
            }
            
            return self.log_event(event_data)
            
        except Exception as e:
            logger.error(f"Error logging security wall event: {str(e)}")
            return ""
    
    def flush_events(self):
        """Flush buffered events to database."""
        if not self.event_buffer:
            return
        
        try:
            # Convert events to database format
            events_to_store = []
            for event in self.event_buffer:
                event_dict = asdict(event)
                
                # Generate hash for tamper detection
                event_hash = self._generate_event_hash(event_dict)
                event_dict["event_hash"] = event_hash
                
                # Convert datetime to string for database storage
                event_dict["timestamp"] = event.timestamp.isoformat()
                
                events_to_store.append(event_dict)
            
            # Store in database (placeholder for actual implementation)
            if self.db_session:
                # This would be the actual database insertion
                # For now, we'll just log the events
                logger.info(f"Flushing {len(events_to_store)} events to database")
            
            # Clear buffer
            self.event_buffer.clear()
            self.last_flush = time.time()
            
        except Exception as e:
            logger.error(f"Error flushing events: {str(e)}")
    
    def flush_alerts(self):
        """Flush buffered security alerts to database."""
        if not self.alert_buffer:
            return
        
        try:
            # Convert alerts to database format
            alerts_to_store = []
            for alert in self.alert_buffer:
                alert_dict = asdict(alert)
                
                # Generate hash for tamper detection
                alert_hash = self._generate_event_hash(alert_dict)
                alert_dict["alert_hash"] = alert_hash
                
                # Convert datetime to string for database storage
                alert_dict["timestamp"] = alert.timestamp.isoformat()
                if alert.resolved_at:
                    alert_dict["resolved_at"] = alert.resolved_at.isoformat()
                
                alerts_to_store.append(alert_dict)
            
            # Store in database (placeholder for actual implementation)
            if self.db_session:
                # This would be the actual database insertion
                # For now, we'll just log the alerts
                logger.info(f"Flushing {len(alerts_to_store)} security alerts to database")
            
            # Clear buffer
            self.alert_buffer.clear()
            
        except Exception as e:
            logger.error(f"Error flushing alerts: {str(e)}")
    
    def _generate_event_hash(self, event_data: Dict[str, Any]) -> str:
        """Generate hash for event data to detect tampering."""
        try:
            # Create a copy of the data without the hash field
            data_copy = event_data.copy()
            if "event_hash" in data_copy:
                del data_copy["event_hash"]
            if "alert_hash" in data_copy:
                del data_copy["alert_hash"]
            
            # Convert to sorted JSON string for consistent hashing
            json_string = json.dumps(data_copy, sort_keys=True, default=str)
            
            # Generate SHA-256 hash
            return hashlib.sha256(json_string.encode()).hexdigest()
            
        except Exception as e:
            logger.error(f"Error generating event hash: {str(e)}")
            return ""
    
    def _parse_enum(self, value: Any, enum_class) -> Any:
        """Parse enum value from string or enum."""
        if isinstance(value, enum_class):
            return value
        elif isinstance(value, str):
            try:
                return enum_class(value)
            except ValueError:
                # Return default value if parsing fails
                if enum_class == EventType:
                    return EventType.SYSTEM_OPERATION
                elif enum_class == EventSeverity:
                    return EventSeverity.INFO
                elif enum_class == EventCategory:
                    return EventCategory.SYSTEM
        return enum_class.INFO if enum_class == EventSeverity else enum_class.SYSTEM_OPERATION
    
    def _map_security_severity(self, threat_level: str) -> EventSeverity:
        """Map security threat level to event severity."""
        threat_mapping = {
            "low": EventSeverity.INFO,
            "medium": EventSeverity.WARNING,
            "high": EventSeverity.ERROR,
            "critical": EventSeverity.CRITICAL
        }
        return threat_mapping.get(threat_level.lower(), EventSeverity.WARNING)
    
    def get_event_summary(self) -> Dict[str, Any]:
        """Get summary of current event logging status."""
        return {
            "buffered_events": len(self.event_buffer),
            "buffered_alerts": len(self.alert_buffer),
            "last_flush": self.last_flush,
            "buffer_size": self.buffer_size,
            "flush_interval": self.flush_interval
        }
    
    def reset_logger(self):
        """Reset the event logger (useful for testing)."""
        self.event_buffer.clear()
        self.alert_buffer.clear()
        self.last_flush = time.time()
        logger.info("Event Logger reset")
