"""
Security Walls Integration

This module demonstrates how to integrate all five security wall modules
for comprehensive threat detection and monitoring.
"""

import time
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

# Import all security wall modules
from .air_wall import AirWall
from .fire_wall import FireWall
from .earth_wall import EarthWall
from .water_wall import WaterWall
from .ether_wall import EtherWall

logger = logging.getLogger(__name__)

class SecurityWallsManager:
    """
    Manager class for coordinating all security wall modules.
    
    This class provides a unified interface for:
    - Initializing all security walls
    - Coordinating threat detection across modules
    - Managing alerts and responses
    - Providing unified security status
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the security walls manager.
        
        Args:
            config: Configuration dictionary for all security walls
        """
        self.config = config or {}
        
        # Initialize all security walls
        self.air_wall = AirWall(self.config.get("air_wall", {}))
        self.fire_wall = FireWall(self.config.get("fire_wall", {}))
        self.earth_wall = EarthWall(self.config.get("earth_wall", {}))
        self.water_wall = WaterWall(self.config.get("water_wall", {}))
        self.ether_wall = EtherWall(self.config.get("ether_wall", {}))
        
        # Track all alerts
        self.all_alerts: List[Dict] = []
        
        logger.info("Security Walls Manager initialized with all modules")
    
    def analyze_request(self, request_data: Dict[str, Any]) -> List[Dict]:
        """
        Analyze a request through all security walls.
        
        Args:
            request_data: Dictionary containing request information
            
        Returns:
            List of alerts from all security walls
        """
        alerts = []
        
        try:
            # 1. Air Wall - Network traffic analysis
            air_alert = self.air_wall.analyze_request(request_data)
            if air_alert:
                alert_info = {
                    "source_wall": "air_wall",
                    "alert_type": air_alert.alert_type,
                    "severity": air_alert.severity,
                    "identifier": air_alert.identifier,
                    "timestamp": air_alert.timestamp,
                    "details": air_alert.details,
                    "mitigation_action": air_alert.mitigation_action
                }
                alerts.append(alert_info)
                self.all_alerts.append(alert_info)
            
            # 2. Water Wall - API misuse detection
            water_alert = self.water_wall.monitor_request(request_data)
            if water_alert:
                alert_info = {
                    "source_wall": "water_wall",
                    "alert_type": water_alert.alert_type,
                    "severity": water_alert.severity,
                    "identifier": water_alert.identifier,
                    "timestamp": water_alert.timestamp,
                    "details": water_alert.details,
                    "mitigation_action": water_alert.mitigation_action
                }
                alerts.append(alert_info)
                self.all_alerts.append(alert_info)
            
            # 3. Fire Wall - Authentication security (if applicable)
            if "username" in request_data and "ip_address" in request_data:
                fire_alert = self.fire_wall.record_login_attempt(request_data)
                if fire_alert:
                    alert_info = {
                        "source_wall": "fire_wall",
                        "alert_type": fire_alert.alert_type,
                        "severity": fire_alert.severity,
                        "identifier": fire_alert.identifier,
                        "timestamp": fire_alert.timestamp,
                        "details": fire_alert.details,
                        "mitigation_action": fire_alert.mitigation_action
                    }
                    alerts.append(alert_info)
                    self.all_alerts.append(alert_info)
            
            # 4. Earth Wall - Database operations (if applicable)
            if "operation_type" in request_data:
                earth_alert = self.earth_wall.monitor_operation(request_data)
                if earth_alert:
                    alert_info = {
                        "source_wall": "earth_wall",
                        "alert_type": earth_alert.alert_type,
                        "severity": earth_alert.severity,
                        "identifier": earth_alert.identifier,
                        "timestamp": earth_alert.timestamp,
                        "details": earth_alert.details,
                        "mitigation_action": earth_alert.mitigation_action
                    }
                    alerts.append(alert_info)
                    self.all_alerts.append(alert_info)
            
            # 5. Ether Wall - Game actions (if applicable)
            if "game_action" in request_data:
                is_valid, ether_alert = self.ether_wall.validate_game_action(request_data)
                if not is_valid and ether_alert:
                    alert_info = {
                        "source_wall": "ether_wall",
                        "alert_type": ether_alert.alert_type,
                        "severity": ether_alert.severity,
                        "identifier": ether_alert.identifier,
                        "timestamp": ether_alert.timestamp,
                        "details": ether_alert.details,
                        "mitigation_action": ether_alert.mitigation_action
                    }
                    alerts.append(alert_info)
                    self.all_alerts.append(alert_info)
            
        except Exception as e:
            logger.error(f"Error in security walls analysis: {str(e)}")
        
        return alerts
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get comprehensive security status from all walls."""
        return {
            "air_wall": self.air_wall.get_traffic_summary(),
            "fire_wall": self.fire_wall.get_security_summary(),
            "earth_wall": self.earth_wall.get_integrity_summary(),
            "water_wall": self.water_wall.get_api_summary(),
            "ether_wall": self.ether_wall.get_anti_cheat_summary(),
            "total_alerts": len(self.all_alerts),
            "timestamp": datetime.now().isoformat()
        }
    
    def get_recent_alerts(self, limit: int = 50) -> List[Dict]:
        """Get recent security alerts from all walls."""
        return self.all_alerts[-limit:] if self.all_alerts else []
    
    def reset_all_walls(self):
        """Reset all security walls (useful for testing)."""
        self.air_wall.reset_traffic_data()
        self.fire_wall.reset_security_data()
        self.earth_wall.reset_integrity_data()
        self.water_wall.reset_api_data()
        self.ether_wall.reset_anti_cheat_data()
        self.all_alerts.clear()
        logger.info("All security walls reset")


# Example usage and testing
def example_integration():
    """Example of how to use the SecurityWallsManager."""
    
    # Initialize manager
    manager = SecurityWallsManager()
    
    # Example request data
    request_data = {
        "ip_address": "192.168.1.100",
        "user_id": "user123",
        "username": "testuser",
        "endpoint": "/api/game/action",
        "method": "POST",
        "status_code": 200,
        "response_time_ms": 150,
        "request_size": 1024,
        "user_agent": "GameClient/1.0",
        "headers": {"content-type": "application/json"},
        "geo_data": {"country": "US", "region": "CA"},
        "game_action": "player_move",
        "coordinates": {"x": 100, "y": 200, "z": 50}
    }
    
    # Analyze through all security walls
    alerts = manager.analyze_request(request_data)
    
    if alerts:
        logger.info(f"Security alerts detected: {len(alerts)}")
        for alert in alerts:
            logger.info(f"- {alert['source_wall']}: {alert['alert_type']} ({alert['severity']})")
    else:
        logger.info("No security alerts detected")
    
    # Get security status
    status = manager.get_security_status()
    logger.info(f"Security status: {status['total_alerts']} total alerts")
    
    return manager


if __name__ == "__main__":
    # Run example integration
    manager = example_integration()
