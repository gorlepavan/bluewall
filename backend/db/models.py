"""
Database Models

This module defines the database models for the BlueWall backend application
using SQLAlchemy ORM. It includes the User model with role-based access control
and TOTP authentication support.

Features:
- User model with role-based permissions
- Secure password hashing storage
- TOTP secret storage for two-factor authentication
- Timestamp tracking for audit purposes
- Event logging and security alert models
"""

from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, Float, JSON
from sqlalchemy.sql import func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from typing import Optional
import logging
from datetime import datetime

# Import Base from session module
from .session import Base

# Configure logging
logger = logging.getLogger(__name__)

class User(Base):
    """
    User model representing system users with role-based access control.
    
    This model stores user authentication information including:
    - Username and password hash for basic authentication
    - Role for access control (admin, officer)
    - TOTP secret for two-factor authentication
    - Timestamps for audit and security purposes
    
    Attributes:
        id: Unique identifier for the user
        username: Unique username for login
        password_hash: Bcrypt hashed password
        role: User role (admin, officer)
        totp_secret: Secret key for TOTP generation
        is_active: Whether the user account is active
        created_at: Timestamp when user was created
        updated_at: Timestamp when user was last updated
        last_login: Timestamp of last successful login
    """
    
    __tablename__ = "users"
    
    # Primary key
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    
    # User authentication fields
    username = Column(String(50), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    
    # Role and access control
    role = Column(String(20), nullable=False, default="officer")
    
    # Two-factor authentication
    totp_secret = Column(String(32), nullable=False)
    
    # Account status
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    last_login = Column(DateTime(timezone=True), nullable=True)
    
    def __repr__(self) -> str:
        """String representation of the User object."""
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}')>"
    
    def to_dict(self) -> dict:
        """
        Convert User object to dictionary representation.
        
        Excludes sensitive information like password_hash and totp_secret.
        
        Returns:
            dict: Dictionary representation of user data
        """
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None
        }
    
    def has_role(self, required_role: str) -> bool:
        """
        Check if user has the required role or higher privileges.
        
        Role hierarchy: admin > officer
        
        Args:
            required_role: The role to check against
            
        Returns:
            bool: True if user has required role or higher, False otherwise
            
        Example:
            user.has_role("officer")  # Returns True for both admin and officer
            user.has_role("admin")    # Returns True only for admin
        """
        role_hierarchy = {
            "officer": 1,
            "admin": 2
        }
        
        user_level = role_hierarchy.get(self.role, 0)
        required_level = role_hierarchy.get(required_role, 0)
        
        return user_level >= required_level
    
    def is_admin(self) -> bool:
        """
        Check if user has admin privileges.
        
        Returns:
            bool: True if user is admin, False otherwise
        """
        return self.role == "admin"
    
    def is_officer(self) -> bool:
        """
        Check if user has officer privileges.
        
        Returns:
            bool: True if user is officer or admin, False otherwise
        """
        return self.role in ["officer", "admin"]
    
    def update_last_login(self) -> None:
        """
        Update the last_login timestamp to current time.
        
        This method should be called after successful authentication.
        """
        from sqlalchemy import func
        self.last_login = func.now()
        logger.info(f"Updated last login for user: {self.username}")
    
    @classmethod
    def get_by_username(cls, db, username: str) -> Optional['User']:
        """
        Get user by username.
        
        Args:
            db: Database session
            username: Username to search for
            
        Returns:
            User: User object if found, None otherwise
        """
        return db.query(cls).filter(cls.username == username).first()
    
    @classmethod
    def get_by_id(cls, db, user_id: int) -> Optional['User']:
        """
        Get user by ID.
        
        Args:
            db: Database session
            user_id: User ID to search for
            
        Returns:
            User: User object if found, None otherwise
        """
        return db.query(cls).filter(cls.id == user_id).first()
    
    @classmethod
    def get_active_users(cls, db) -> list['User']:
        """
        Get all active users.
        
        Args:
            db: Database session
            
        Returns:
            list[User]: List of active users
        """
        return db.query(cls).filter(cls.is_active == True).all()
    
    @classmethod
    def get_users_by_role(cls, db, role: str) -> list['User']:
        """
        Get all users with a specific role.
        
        Args:
            db: Database session
            role: Role to filter by
            
        Returns:
            list[User]: List of users with the specified role
        """
        return db.query(cls).filter(cls.role == role, cls.is_active == True).all()


class Event(Base):
    """
    Event model for comprehensive system event logging.
    
    This model stores all major system events including:
    - Authentication events (login, logout, failures)
    - Security events (alerts, suspicious activity)
    - Game events (player actions, kills, payments)
    - System events (startup, shutdown, configuration changes)
    - User management events (creation, deletion, role changes)
    
    Attributes:
        id: Unique identifier for the event
        event_id: UUID for the event
        event_type: Type of event (login, security_alert, game_action, etc.)
        severity: Event severity level (debug, info, warning, error, critical)
        category: Event category (authentication, security, game, system, etc.)
        timestamp: When the event occurred
        user_id: Associated user ID (if applicable)
        username: Associated username (if applicable)
        ip_address: IP address associated with event
        session_id: Session ID associated with event
        details: JSON details of the event
        source_module: Module that generated the event
        correlation_id: Optional correlation ID for related events
        event_hash: Hash of event data for tamper detection
    """
    
    __tablename__ = "events"
    
    # Primary key
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    
    # Event identification
    event_id = Column(String(36), unique=True, index=True, nullable=False)  # UUID
    event_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    category = Column(String(30), nullable=False, index=True)
    
    # Timestamp
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    
    # Associated entities
    user_id = Column(Integer, nullable=True, index=True)
    username = Column(String(50), nullable=True, index=True)
    ip_address = Column(String(45), nullable=True, index=True)  # IPv6 compatible
    session_id = Column(String(100), nullable=True, index=True)
    
    # Event details
    details = Column(JSON, nullable=False, default={})
    source_module = Column(String(100), nullable=False, index=True)
    correlation_id = Column(String(100), nullable=True, index=True)
    
    # Tamper detection
    event_hash = Column(String(64), nullable=False, index=True)  # SHA-256 hash
    
    def __repr__(self) -> str:
        """String representation of the Event object."""
        return f"<Event(id={self.id}, type='{self.event_type}', severity='{self.severity}', timestamp='{self.timestamp}')>"
    
    def to_dict(self) -> dict:
        """
        Convert Event object to dictionary representation.
        
        Returns:
            dict: Dictionary representation of event data
        """
        return {
            "id": self.id,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "severity": self.severity,
            "category": self.category,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "user_id": self.user_id,
            "username": self.username,
            "ip_address": self.ip_address,
            "session_id": self.session_id,
            "details": self.details,
            "source_module": self.source_module,
            "correlation_id": self.correlation_id,
            "event_hash": self.event_hash
        }
    
    @classmethod
    def get_by_event_id(cls, db, event_id: str) -> Optional['Event']:
        """
        Get event by event ID.
        
        Args:
            db: Database session
            event_id: Event UUID to search for
            
        Returns:
            Event: Event object if found, None otherwise
        """
        return db.query(cls).filter(cls.event_id == event_id).first()
    
    @classmethod
    def get_events_by_user(cls, db, user_id: int, limit: int = 100) -> list['Event']:
        """
        Get events for a specific user.
        
        Args:
            db: Database session
            user_id: User ID to filter by
            limit: Maximum number of events to return
            
        Returns:
            list[Event]: List of events for the user
        """
        return db.query(cls).filter(cls.user_id == user_id).order_by(cls.timestamp.desc()).limit(limit).all()
    
    @classmethod
    def get_events_by_type(cls, db, event_type: str, limit: int = 100) -> list['Event']:
        """
        Get events by type.
        
        Args:
            db: Database session
            event_type: Event type to filter by
            limit: Maximum number of events to return
            
        Returns:
            list[Event]: List of events of the specified type
        """
        return db.query(cls).filter(cls.event_type == event_type).order_by(cls.timestamp.desc()).limit(limit).all()
    
    @classmethod
    def get_events_by_severity(cls, db, severity: str, limit: int = 100) -> list['Event']:
        """
        Get events by severity level.
        
        Args:
            db: Database session
            severity: Severity level to filter by
            limit: Maximum number of events to return
            
        Returns:
            list[Event]: List of events with the specified severity
        """
        return db.query(cls).filter(cls.severity == severity).order_by(cls.timestamp.desc()).limit(limit).all()
    
    @classmethod
    def get_events_in_timerange(cls, db, start_time: datetime, end_time: datetime, limit: int = 1000) -> list['Event']:
        """
        Get events within a time range.
        
        Args:
            db: Database session
            start_time: Start of time range
            end_time: End of time range
            limit: Maximum number of events to return
            
        Returns:
            list[Event]: List of events within the time range
        """
        return db.query(cls).filter(
            cls.timestamp >= start_time,
            cls.timestamp <= end_time
        ).order_by(cls.timestamp.desc()).limit(limit).all()


class SecurityAlert(Base):
    """
    Security Alert model for storing security alerts from security wall modules.
    
    This model stores security alerts generated by the various security walls:
    - Air Wall (DDoS, rate limiting, packet floods)
    - Fire Wall (brute force, JWT replay, authentication attacks)
    - Earth Wall (data integrity, schema tampering, unauthorized changes)
    - Water Wall (API misuse, IP blacklisting, geographic abuse)
    - Ether Wall (game cheating, memory injection, client modification)
    
    Attributes:
        id: Unique identifier for the alert
        alert_id: UUID for the alert
        event_id: Associated event ID
        alert_type: Type of security alert
        severity: Alert severity level
        threat_level: Threat level for WebSocket broadcasting (low, medium, high, critical)
        wall_name: Display name of the security wall for frontend
        source_wall: Security wall that generated the alert
        identifier: Target of the alert (IP, user, etc.)
        timestamp: When the alert was generated
        details: JSON details of the alert
        mitigation_action: Recommended mitigation action
        status: Alert status (active, resolved, false_positive)
        resolved_by: User who resolved the alert
        resolved_at: When the alert was resolved
        notes: Additional notes about the alert
        alert_hash: Hash of alert data for tamper detection
    """
    
    __tablename__ = "security_alerts"
    
    # Primary key
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    
    # Alert identification
    alert_id = Column(String(36), unique=True, index=True, nullable=False)  # UUID
    event_id = Column(String(36), nullable=True, index=True)  # Associated event
    
    # Alert details
    alert_type = Column(String(100), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    threat_level = Column(String(20), nullable=False, default="medium", index=True)  # low, medium, high, critical
    wall_name = Column(String(50), nullable=False, index=True)  # Display name for frontend
    source_wall = Column(String(50), nullable=False, index=True)  # Which security wall
    identifier = Column(String(255), nullable=False, index=True)  # Target (IP, user, etc.)
    
    # Timestamps
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    
    # Alert content
    details = Column(JSON, nullable=False, default={})
    mitigation_action = Column(String(100), nullable=False)
    
    # Status tracking
    status = Column(String(20), nullable=False, default="active", index=True)
    resolved_by = Column(String(50), nullable=True)
    notes = Column(Text, nullable=True)
    
    # Tamper detection
    alert_hash = Column(String(64), nullable=False, index=True)  # SHA-256 hash
    
    def __repr__(self) -> str:
        """String representation of the SecurityAlert object."""
        return f"<SecurityAlert(id={self.id}, type='{self.alert_type}', severity='{self.severity}', source='{self.source_wall}')>"
    
    def to_dict(self) -> dict:
        """
        Convert SecurityAlert object to dictionary representation.
        
        Returns:
            dict: Dictionary representation of alert data
        """
        return {
            "id": self.id,
            "alert_id": self.alert_id,
            "event_id": self.event_id,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "threat_level": self.threat_level,
            "wall_name": self.wall_name,
            "source_wall": self.source_wall,
            "identifier": self.identifier,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "details": self.details,
            "mitigation_action": self.mitigation_action,
            "status": self.status,
            "resolved_by": self.resolved_by,
            "notes": self.notes,
            "alert_hash": self.alert_hash
        }
    
    def resolve(self, resolved_by: str, notes: str = None) -> None:
        """
        Mark alert as resolved.
        
        Args:
            resolved_by: Username of person resolving the alert
            notes: Optional notes about the resolution
        """
        from sqlalchemy import func
        self.status = "resolved"
        self.resolved_by = resolved_by
        self.resolved_at = func.now()
        if notes:
            self.notes = notes
        logger.info(f"Security alert {self.alert_id} resolved by {resolved_by}")
    
    def mark_false_positive(self, marked_by: str, notes: str = None) -> None:
        """
        Mark alert as false positive.
        
        Args:
            marked_by: Username of person marking as false positive
            notes: Optional notes about why it's a false positive
        """
        from sqlalchemy import func
        self.status = "false_positive"
        self.resolved_by = marked_by
        self.resolved_at = func.now()
        if notes:
            self.notes = notes
        logger.info(f"Security alert {self.alert_id} marked as false positive by {marked_by}")
    
    @classmethod
    def get_by_alert_id(cls, db, alert_id: str) -> Optional['SecurityAlert']:
        """
        Get security alert by alert ID.
        
        Args:
            db: Database session
            alert_id: Alert UUID to search for
            
        Returns:
            SecurityAlert: Alert object if found, None otherwise
        """
        return db.query(cls).filter(cls.alert_id == alert_id).first()
    
    @classmethod
    def get_active_alerts(cls, db, limit: int = 100) -> list['SecurityAlert']:
        """
        Get all active security alerts.
        
        Args:
            db: Database session
            limit: Maximum number of alerts to return
            
        Returns:
            list[SecurityAlert]: List of active alerts
        """
        return db.query(cls).filter(cls.status == "active").order_by(cls.timestamp.desc()).limit(limit).all()
    
    @classmethod
    def get_alerts_by_source_wall(cls, db, source_wall: str, limit: int = 100) -> list['SecurityAlert']:
        """
        Get alerts from a specific security wall.
        
        Args:
            db: Database session
            source_wall: Security wall name to filter by
            limit: Maximum number of alerts to return
            
        Returns:
            list[SecurityAlert]: List of alerts from the specified wall
        """
        return db.query(cls).filter(cls.source_wall == source_wall).order_by(cls.timestamp.desc()).limit(limit).all()
    
    @classmethod
    def get_alerts_by_severity(cls, db, severity: str, limit: int = 100) -> list['SecurityAlert']:
        """
        Get alerts by severity level.
        
        Args:
            db: Database session
            severity: Severity level to filter by
            limit: Maximum number of alerts to return
            
        Returns:
            list[SecurityAlert]: List of alerts with the specified severity
        """
        return db.query(cls).filter(cls.severity == severity).order_by(cls.timestamp.desc()).limit(limit).all()
    
    @classmethod
    def get_alerts_by_identifier(cls, db, identifier: str, limit: int = 100) -> list['SecurityAlert']:
        """
        Get alerts for a specific identifier (IP, user, etc.).
        
        Args:
            db: Database session
            identifier: Identifier to filter by
            limit: Maximum number of alerts to return
            
        Returns:
            list[SecurityAlert]: List of alerts for the specified identifier
        """
        return db.query(cls).filter(cls.identifier == identifier).order_by(cls.timestamp.desc()).limit(limit).all()
    
    @classmethod
    def get_alerts_in_timerange(cls, db, start_time: datetime, end_time: datetime, limit: int = 1000) -> list['SecurityAlert']:
        """
        Get alerts within a time range.
        
        Args:
            db: Database session
            start_time: Start of time range
            end_time: End of time range
            limit: Maximum number of alerts to return
            
        Returns:
            list[SecurityAlert]: List of alerts within the time range
        """
        return db.query(cls).filter(
            cls.timestamp >= start_time,
            cls.timestamp <= end_time
        ).order_by(cls.timestamp.desc()).limit(limit).all()
    
    @classmethod
    def get_recent_alerts(cls, db, limit: int = 50) -> list['SecurityAlert']:
        """
        Get the most recent security alerts.
        
        Args:
            db: Database session
            limit: Maximum number of alerts to return (default: 50)
            
        Returns:
            list[SecurityAlert]: List of recent alerts ordered by timestamp
        """
        return db.query(cls).order_by(cls.timestamp.desc()).limit(limit).all()


# Additional models can be added here as the application grows
# For example:
# class AuditLog(Base):
#     __tablename__ = "audit_logs"
#     id = Column(Integer, primary_key=True, index=True)
#     user_id = Column(Integer, ForeignKey("users.id"))
#     action = Column(String(100), nullable=False)
#     timestamp = Column(DateTime(timezone=True), server_default=func.now())
#     details = Column(Text, nullable=True)
