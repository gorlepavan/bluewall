"""
Enhanced Alert Manager - BlueWall Security

This module provides enhanced WebSocket alert management for:
- Anti-cheat detection alerts
- Anti-reverse-engineering alerts
- High-severity threat visualization
- Flashing globe markers for critical threats
- Real-time threat correlation
- Admin and officer monitoring
- Cinematic dashboard visualization
"""

import asyncio
import json
import logging
import time
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclass import dataclass
from datetime import datetime, timedelta
from enum import Enum
import websockets
from websockets.server import WebSocketServerProtocol
import secrets
from collections import defaultdict

logger = logging.getLogger(__name__)

class ThreatCategory(Enum):
    """Categories of security threats."""
    ANTI_CHEAT = "anti_cheat"
    ANTI_REVERSE_ENGINEERING = "anti_reverse_engineering"
    NETWORK_ATTACK = "network_attack"
    AUTHENTICATION_ATTACK = "authentication_attack"
    DATA_BREACH = "data_breach"
    SYSTEM_COMPROMISE = "system_compromise"

class AlertSeverity(Enum):
    """Alert severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class GlobeMarkerType(Enum):
    """Types of globe markers for visualization."""
    NORMAL = "normal"
    FLASHING = "flashing"
    PULSING = "pulsing"
    ROTATING = "rotating"
    EXPLOSION = "explosion"

@dataclass
class EnhancedAlert:
    """Enhanced security alert with visualization data."""
    alert_id: str
    timestamp: datetime
    threat_category: ThreatCategory
    severity: AlertSeverity
    source_wall: str
    identifier: str
    title: str
    description: str
    details: Dict
    mitigation_action: str
    confidence_score: float
    location_data: Optional[Dict] = None
    globe_marker: Optional[GlobeMarkerType] = None
    visual_effects: Optional[Dict] = None
    related_alerts: List[str] = None
    escalation_level: int = 0

@dataclass
class GlobeMarker:
    """3D globe marker for threat visualization."""
    marker_id: str
    alert_id: str
    latitude: float
    longitude: float
    marker_type: GlobeMarkerType
    color: str
    size: float
    intensity: float
    animation_speed: float
    is_active: bool
    created: datetime
    expires: Optional[datetime] = None

@dataclass
class AlertCorrelation:
    """Correlation between multiple alerts."""
    correlation_id: str
    alert_ids: List[str]
    correlation_type: str
    confidence: float
    pattern_description: str
    threat_level: AlertSeverity
    created: datetime

class EnhancedAlertManager:
    """
    Enhanced alert manager for comprehensive threat monitoring.
    
    Features:
    - Multi-category threat detection
    - Real-time alert correlation
    - 3D globe visualization
    - Cinematic threat effects
    - Admin dashboard integration
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize enhanced alert manager."""
        self.config = config or self._get_default_config()
        
        # WebSocket connections
        self.connected_clients: Set[WebSocketServerProtocol] = set()
        self.admin_clients: Set[WebSocketServerProtocol] = set()
        self.officer_clients: Set[WebSocketServerProtocol] = set()
        
        # Alert management
        self.active_alerts: Dict[str, EnhancedAlert] = {}
        self.alert_history: List[EnhancedAlert] = []
        self.alert_counter = 0
        
        # Globe markers
        self.globe_markers: Dict[str, GlobeMarker] = {}
        self.marker_counter = 0
        
        # Alert correlation
        self.alert_correlations: List[AlertCorrelation] = []
        self.correlation_patterns: Dict[str, List[str]] = defaultdict(list)
        
        # Threat tracking
        self.threat_levels: Dict[str, float] = {}
        self.escalation_timers: Dict[str, float] = {}
        
        # Performance tracking
        self.alert_stats = {
            "total_alerts": 0,
            "active_alerts": 0,
            "correlations_found": 0,
            "globe_markers": 0
        }
        
        logger.info("Enhanced Alert Manager initialized")
    
    def _get_default_config(self) -> Dict:
        """Get default configuration for enhanced alert manager."""
        return {
            # Alert settings
            "max_active_alerts": 1000,
            "alert_history_size": 10000,
            "alert_cleanup_interval": 300.0,  # 5 minutes
            
            # Globe marker settings
            "max_globe_markers": 500,
            "marker_lifetime": 3600.0,  # 1 hour
            "flashing_interval": 0.5,  # seconds
            "pulsing_interval": 1.0,  # seconds
            
            # Correlation settings
            "correlation_window": 300.0,  # 5 minutes
            "correlation_threshold": 0.7,
            "max_correlation_alerts": 10,
            
            # Visualization settings
            "enable_3d_effects": True,
            "enable_cinematic_effects": True,
            "effect_intensity": 0.8,
            
            # Performance settings
            "max_clients": 1000,
            "heartbeat_interval": 30.0,  # seconds
            "cleanup_interval": 60.0,  # seconds
        }
    
    async def register_client(self, websocket: WebSocketServerProtocol, client_type: str = "user"):
        """Register a new WebSocket client."""
        try:
            self.connected_clients.add(websocket)
            
            if client_type == "admin":
                self.admin_clients.add(websocket)
                logger.info("Admin client connected")
            elif client_type == "officer":
                self.officer_clients.add(websocket)
                logger.info("Security officer client connected")
            else:
                logger.info("Regular client connected")
            
            # Send current system status
            await self._send_system_status(websocket)
            
        except Exception as e:
            logger.error(f"Error registering client: {e}")
    
    async def unregister_client(self, websocket: WebSocketServerProtocol):
        """Unregister a WebSocket client."""
        try:
            self.connected_clients.discard(websocket)
            self.admin_clients.discard(websocket)
            self.officer_clients.discard(websocket)
            
            logger.info("Client disconnected")
            
        except Exception as e:
            logger.error(f"Error unregistering client: {e}")
    
    async def broadcast_enhanced_alert(self, alert_data: Dict, source_wall: str):
        """
        Broadcast enhanced security alert to all connected clients.
        
        Args:
            alert_data: Alert data from security walls
            source_wall: Source security wall name
        """
        try:
            # Create enhanced alert
            enhanced_alert = self._create_enhanced_alert(alert_data, source_wall)
            if not enhanced_alert:
                return
            
            # Store alert
            self.active_alerts[enhanced_alert.alert_id] = enhanced_alert
            self.alert_history.append(enhanced_alert)
            self.alert_counter += 1
            
            # Create globe marker if location data available
            if enhanced_alert.location_data:
                globe_marker = self._create_globe_marker(enhanced_alert)
                if globe_marker:
                    self.globe_markers[globe_marker.marker_id] = globe_marker
            
            # Check for alert correlations
            correlations = self._check_alert_correlations(enhanced_alert)
            if correlations:
                enhanced_alert.related_alerts = [c.correlation_id for c in correlations]
                self.alert_correlations.extend(correlations)
            
            # Update threat levels
            self._update_threat_levels(enhanced_alert)
            
            # Prepare alert message
            alert_message = self._prepare_alert_message(enhanced_alert)
            
            # Broadcast to appropriate clients
            await self._broadcast_alert_message(alert_message, enhanced_alert.severity)
            
            # Update statistics
            self._update_alert_stats()
            
            # Cleanup old data
            self._cleanup_old_data()
            
            logger.info(f"Enhanced alert broadcasted: {enhanced_alert.alert_id}")
            
        except Exception as e:
            logger.error(f"Error broadcasting enhanced alert: {e}")
    
    def _create_enhanced_alert(self, alert_data: Dict, source_wall: str) -> Optional[EnhancedAlert]:
        """Create enhanced alert from security wall data."""
        try:
            # Extract basic alert information
            alert_type = alert_data.get("alert_type", "unknown")
            severity = alert_data.get("severity", "medium")
            identifier = alert_data.get("identifier", "unknown")
            
            # Determine threat category
            threat_category = self._determine_threat_category(alert_type, source_wall)
            
            # Determine alert severity
            alert_severity = self._determine_alert_severity(severity)
            
            # Generate alert ID
            alert_id = f"alert_{self.alert_counter}_{secrets.token_hex(8)}"
            
            # Create title and description
            title = self._generate_alert_title(alert_type, source_wall)
            description = self._generate_alert_description(alert_data, source_wall)
            
            # Determine globe marker type based on severity
            globe_marker_type = self._determine_globe_marker_type(alert_severity)
            
            # Create visual effects
            visual_effects = self._create_visual_effects(alert_severity, threat_category)
            
            # Create enhanced alert
            enhanced_alert = EnhancedAlert(
                alert_id=alert_id,
                timestamp=datetime.now(),
                threat_category=threat_category,
                severity=alert_severity,
                source_wall=source_wall,
                identifier=identifier,
                title=title,
                description=description,
                details=alert_data.get("details", {}),
                mitigation_action=alert_data.get("mitigation_action", "investigate"),
                confidence_score=alert_data.get("confidence_score", 0.5),
                location_data=alert_data.get("location_data"),
                globe_marker=globe_marker_type,
                visual_effects=visual_effects,
                related_alerts=[],
                escalation_level=0
            )
            
            return enhanced_alert
            
        except Exception as e:
            logger.error(f"Error creating enhanced alert: {e}")
            return None
    
    def _determine_threat_category(self, alert_type: str, source_wall: str) -> ThreatCategory:
        """Determine threat category based on alert type and source wall."""
        # Anti-cheat threats
        if any(keyword in alert_type.lower() for keyword in ["cheat", "hack", "speed", "teleport", "aimbot"]):
            return ThreatCategory.ANTI_CHEAT
        
        # Anti-reverse-engineering threats
        if any(keyword in alert_type.lower() for keyword in ["reverse", "memory", "injection", "integrity", "tampering"]):
            return ThreatCategory.ANTI_REVERSE_ENGINEERING
        
        # Network attacks
        if any(keyword in alert_type.lower() for keyword in ["ddos", "flood", "brute", "network"]):
            return ThreatCategory.NETWORK_ATTACK
        
        # Authentication attacks
        if any(keyword in alert_type.lower() for keyword in ["auth", "login", "session", "jwt"]):
            return ThreatCategory.AUTHENTICATION_ATTACK
        
        # Data breaches
        if any(keyword in alert_type.lower() for keyword in ["data", "breach", "leak", "exfiltration"]):
            return ThreatCategory.DATA_BREACH
        
        # Default to system compromise
        return ThreatCategory.SYSTEM_COMPROMISE
    
    def _determine_alert_severity(self, severity: str) -> AlertSeverity:
        """Determine alert severity level."""
        severity_mapping = {
            "low": AlertSeverity.LOW,
            "medium": AlertSeverity.MEDIUM,
            "high": AlertSeverity.HIGH,
            "critical": AlertSeverity.CRITICAL
        }
        
        return severity_mapping.get(severity.lower(), AlertSeverity.MEDIUM)
    
    def _generate_alert_title(self, alert_type: str, source_wall: str) -> str:
        """Generate human-readable alert title."""
        # Convert alert type to readable format
        title_parts = alert_type.replace("_", " ").title().split()
        
        # Add source wall context
        wall_names = {
            "air_wall": "Network",
            "fire_wall": "Authentication",
            "earth_wall": "Data",
            "water_wall": "API",
            "ether_wall": "Game",
            "anti_reverse_engineering": "Reverse Engineering",
            "enhanced_anti_cheat": "Anti-Cheat"
        }
        
        wall_name = wall_names.get(source_wall, source_wall.replace("_", " ").title())
        
        return f"{' '.join(title_parts)} - {wall_name} Threat"
    
    def _generate_alert_description(self, alert_data: Dict, source_wall: str) -> str:
        """Generate detailed alert description."""
        details = alert_data.get("details", {})
        mitigation = alert_data.get("mitigation_action", "investigate")
        
        description_parts = []
        
        # Add threat details
        if "identifier" in alert_data:
            description_parts.append(f"Target: {alert_data['identifier']}")
        
        if "confidence_score" in alert_data:
            confidence = alert_data["confidence_score"]
            description_parts.append(f"Confidence: {confidence:.1%}")
        
        # Add specific details
        for key, value in details.items():
            if isinstance(value, (int, float)):
                description_parts.append(f"{key.replace('_', ' ').title()}: {value}")
            elif isinstance(value, str) and len(value) < 100:
                description_parts.append(f"{key.replace('_', ' ').title()}: {value}")
        
        description_parts.append(f"Action Required: {mitigation.replace('_', ' ').title()}")
        
        return ". ".join(description_parts)
    
    def _determine_globe_marker_type(self, severity: AlertSeverity) -> GlobeMarkerType:
        """Determine globe marker type based on alert severity."""
        if severity == AlertSeverity.CRITICAL:
            return GlobeMarkerType.EXPLOSION
        elif severity == AlertSeverity.HIGH:
            return GlobeMarkerType.FLASHING
        elif severity == AlertSeverity.MEDIUM:
            return GlobeMarkerType.PULSING
        else:
            return GlobeMarkerType.NORMAL
    
    def _create_visual_effects(self, severity: AlertSeverity, threat_category: ThreatCategory) -> Dict:
        """Create visual effects for the alert."""
        effects = {
            "enable_3d": self.config["enable_3d_effects"],
            "enable_cinematic": self.config["enable_cinematic_effects"],
            "intensity": self.config["effect_intensity"]
        }
        
        # Add severity-specific effects
        if severity == AlertSeverity.CRITICAL:
            effects.update({
                "screen_shake": True,
                "red_flash": True,
                "sound_alert": "critical_threat",
                "animation_speed": 2.0
            })
        elif severity == AlertSeverity.HIGH:
            effects.update({
                "orange_flash": True,
                "sound_alert": "high_threat",
                "animation_speed": 1.5
            })
        elif severity == AlertSeverity.MEDIUM:
            effects.update({
                "yellow_flash": True,
                "sound_alert": "medium_threat",
                "animation_speed": 1.0
            })
        
        # Add category-specific effects
        if threat_category == ThreatCategory.ANTI_CHEAT:
            effects["color_scheme"] = "red_orange"
            effects["particle_effect"] = "cheat_detection"
        elif threat_category == ThreatCategory.ANTI_REVERSE_ENGINEERING:
            effects["color_scheme"] = "purple_blue"
            effects["particle_effect"] = "reverse_engineering"
        
        return effects
    
    def _create_globe_marker(self, alert: EnhancedAlert) -> Optional[GlobeMarker]:
        """Create globe marker for alert visualization."""
        try:
            if not alert.location_data:
                return None
            
            # Extract location data
            lat = alert.location_data.get("latitude", 0.0)
            lon = alert.location_data.get("longitude", 0.0)
            
            # Generate marker ID
            marker_id = f"marker_{self.marker_counter}_{secrets.token_hex(8)}"
            self.marker_counter += 1
            
            # Determine marker properties based on severity
            if alert.severity == AlertSeverity.CRITICAL:
                color = "#FF0000"  # Red
                size = 2.0
                intensity = 1.0
                animation_speed = 2.0
            elif alert.severity == AlertSeverity.HIGH:
                color = "#FF6600"  # Orange
                size = 1.5
                intensity = 0.8
                animation_speed = 1.5
            elif alert.severity == AlertSeverity.MEDIUM:
                color = "#FFCC00"  # Yellow
                size = 1.2
                intensity = 0.6
                animation_speed = 1.0
            else:
                color = "#00CC00"  # Green
                size = 1.0
                intensity = 0.4
                animation_speed = 0.8
            
            # Create globe marker
            globe_marker = GlobeMarker(
                marker_id=marker_id,
                alert_id=alert.alert_id,
                latitude=lat,
                longitude=lon,
                marker_type=alert.globe_marker or GlobeMarkerType.NORMAL,
                color=color,
                size=size,
                intensity=intensity,
                animation_speed=animation_speed,
                is_active=True,
                created=datetime.now(),
                expires=datetime.now() + timedelta(seconds=self.config["marker_lifetime"])
            )
            
            return globe_marker
            
        except Exception as e:
            logger.error(f"Error creating globe marker: {e}")
            return None
    
    def _check_alert_correlations(self, alert: EnhancedAlert) -> List[AlertCorrelation]:
        """Check for correlations with existing alerts."""
        try:
            correlations = []
            current_time = time.time()
            correlation_window = self.config["correlation_window"]
            
            # Get recent alerts
            recent_alerts = [
                a for a in self.active_alerts.values()
                if current_time - a.timestamp.timestamp() <= correlation_window
            ]
            
            # Check for correlations
            for recent_alert in recent_alerts:
                if recent_alert.alert_id == alert.alert_id:
                    continue
                
                # Check identifier correlation
                if recent_alert.identifier == alert.identifier:
                    correlation = AlertCorrelation(
                        correlation_id=f"corr_{secrets.token_hex(8)}",
                        alert_ids=[recent_alert.alert_id, alert.alert_id],
                        correlation_type="same_target",
                        confidence=0.8,
                        pattern_description="Multiple threats targeting same entity",
                        threat_level=max(recent_alert.severity, alert.severity),
                        created=datetime.now()
                    )
                    correlations.append(correlation)
                
                # Check location correlation
                if (alert.location_data and recent_alert.location_data and
                    self._calculate_location_distance(
                        alert.location_data, recent_alert.location_data
                    ) < 100):  # Within 100km
                    correlation = AlertCorrelation(
                        correlation_id=f"corr_{secrets.token_hex(8)}",
                        alert_ids=[recent_alert.alert_id, alert.alert_id],
                        correlation_type="geographic",
                        confidence=0.7,
                        pattern_description="Threats in same geographic area",
                        threat_level=max(recent_alert.severity, alert.severity),
                        created=datetime.now()
                    )
                    correlations.append(correlation)
                
                # Check time correlation
                time_diff = abs((alert.timestamp - recent_alert.timestamp).total_seconds())
                if time_diff < 60:  # Within 1 minute
                    correlation = AlertCorrelation(
                        correlation_id=f"corr_{secrets.token_hex(8)}",
                        alert_ids=[recent_alert.alert_id, alert.alert_id],
                        correlation_type="temporal",
                        confidence=0.6,
                        pattern_description="Threats occurring simultaneously",
                        threat_level=max(recent_alert.severity, alert.severity),
                        created=datetime.now()
                    )
                    correlations.append(correlation)
            
            return correlations
            
        except Exception as e:
            logger.error(f"Error checking alert correlations: {e}")
            return []
    
    def _calculate_location_distance(self, loc1: Dict, loc2: Dict) -> float:
        """Calculate distance between two locations (simplified)."""
        try:
            lat1, lon1 = loc1.get("latitude", 0), loc1.get("longitude", 0)
            lat2, lon2 = loc2.get("latitude", 0), loc2.get("longitude", 0)
            
            # Simple distance calculation (not accurate for real-world use)
            return ((lat2 - lat1) ** 2 + (lon2 - lon1) ** 2) ** 0.5 * 111000  # Rough km conversion
            
        except Exception:
            return float('inf')
    
    def _update_threat_levels(self, alert: EnhancedAlert):
        """Update threat levels for entities."""
        try:
            identifier = alert.identifier
            
            # Calculate threat score
            severity_scores = {
                AlertSeverity.LOW: 1,
                AlertSeverity.MEDIUM: 3,
                AlertSeverity.HIGH: 7,
                AlertSeverity.CRITICAL: 10
            }
            
            threat_score = severity_scores.get(alert.severity, 1)
            
            # Update cumulative threat level
            if identifier not in self.threat_levels:
                self.threat_levels[identifier] = 0
            
            self.threat_levels[identifier] += threat_score
            
            # Set escalation timer
            self.escalation_timers[identifier] = time.time()
            
        except Exception as e:
            logger.error(f"Error updating threat levels: {e}")
    
    def _prepare_alert_message(self, alert: EnhancedAlert) -> Dict:
        """Prepare alert message for WebSocket transmission."""
        try:
            message = {
                "type": "enhanced_alert",
                "alert_id": alert.alert_id,
                "timestamp": alert.timestamp.isoformat(),
                "threat_category": alert.threat_category.value,
                "severity": alert.severity.value,
                "source_wall": alert.source_wall,
                "identifier": alert.identifier,
                "title": alert.title,
                "description": alert.description,
                "details": alert.details,
                "mitigation_action": alert.mitigation_action,
                "confidence_score": alert.confidence_score,
                "globe_marker": {
                    "type": alert.globe_marker.value if alert.globe_marker else "normal",
                    "location": alert.location_data,
                    "visual_effects": alert.visual_effects
                } if alert.globe_marker else None,
                "related_alerts": alert.related_alerts,
                "escalation_level": alert.escalation_level
            }
            
            return message
            
        except Exception as e:
            logger.error(f"Error preparing alert message: {e}")
            return {}
    
    async def _broadcast_alert_message(self, message: Dict, severity: AlertSeverity):
        """Broadcast alert message to appropriate clients."""
        try:
            # Convert message to JSON
            json_message = json.dumps(message)
            
            # Determine which clients to notify based on severity
            if severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
                # High severity: notify all clients
                clients_to_notify = self.connected_clients.copy()
            else:
                # Lower severity: notify only admin and officer clients
                clients_to_notify = self.admin_clients.union(self.officer_clients)
            
            # Broadcast message
            if clients_to_notify:
                await asyncio.gather(
                    *[self._send_message(client, json_message) for client in clients_to_notify],
                    return_exceptions=True
                )
            
            logger.debug(f"Alert message broadcasted to {len(clients_to_notify)} clients")
            
        except Exception as e:
            logger.error(f"Error broadcasting alert message: {e}")
    
    async def _send_message(self, websocket: WebSocketServerProtocol, message: str):
        """Send message to a specific WebSocket client."""
        try:
            if websocket.open:
                await websocket.send(message)
        except Exception as e:
            logger.warning(f"Error sending message to client: {e}")
            # Remove disconnected client
            await self.unregister_client(websocket)
    
    async def _send_system_status(self, websocket: WebSocketServerProtocol):
        """Send current system status to client."""
        try:
            status_message = {
                "type": "system_status",
                "timestamp": datetime.now().isoformat(),
                "active_alerts": len(self.active_alerts),
                "total_alerts": self.alert_counter,
                "globe_markers": len(self.globe_markers),
                "correlations": len(self.alert_correlations),
                "threat_levels": len(self.threat_levels)
            }
            
            await self._send_message(websocket, json.dumps(status_message))
            
        except Exception as e:
            logger.error(f"Error sending system status: {e}")
    
    def _update_alert_stats(self):
        """Update alert statistics."""
        self.alert_stats.update({
            "total_alerts": self.alert_counter,
            "active_alerts": len(self.active_alerts),
            "correlations_found": len(self.alert_correlations),
            "globe_markers": len(self.globe_markers)
        })
    
    def _cleanup_old_data(self):
        """Clean up old alerts and markers."""
        try:
            current_time = time.time()
            
            # Clean up expired globe markers
            expired_markers = [
                marker_id for marker_id, marker in self.globe_markers.items()
                if marker.expires and marker.expires.timestamp() < current_time
            ]
            
            for marker_id in expired_markers:
                del self.globe_markers[marker_id]
            
            # Clean up old alerts (keep only recent ones)
            max_alerts = self.config["max_active_alerts"]
            if len(self.active_alerts) > max_alerts:
                # Remove oldest alerts
                sorted_alerts = sorted(
                    self.active_alerts.items(),
                    key=lambda x: x[1].timestamp
                )
                
                alerts_to_remove = len(self.active_alerts) - max_alerts
                for i in range(alerts_to_remove):
                    del self.active_alerts[sorted_alerts[i][0]]
            
            # Clean up old alert history
            max_history = self.config["alert_history_size"]
            if len(self.alert_history) > max_history:
                self.alert_history = self.alert_history[-max_history:]
            
            logger.debug(f"Cleanup completed: removed {len(expired_markers)} expired markers")
            
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
    
    def get_enhanced_alert_summary(self) -> Dict:
        """Get summary of enhanced alert system status."""
        return {
            "alert_stats": self.alert_stats,
            "threat_levels": len(self.threat_levels),
            "active_correlations": len(self.alert_correlations),
            "globe_markers": len(self.globe_markers),
            "connected_clients": len(self.connected_clients),
            "admin_clients": len(self.admin_clients),
            "officer_clients": len(self.officer_clients),
            "config": self.config
        }
