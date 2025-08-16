"""
BlueWall Security Integration Example

This example demonstrates how to integrate all security modules:
- Anti-Reverse-Engineering
- Enhanced Anti-Cheat
- Secure Transmission
- Enhanced Alert Manager

Usage: Run this script to see the security system in action
"""

import asyncio
import json
import time
import logging
from typing import Dict, Any
from datetime import datetime

# Import security modules
from security_walls.anti_reverse_engineering import AntiReverseEngineering, PlatformType
from security_walls.enhanced_anti_cheat import EnhancedAntiCheat
from security_walls.secure_transmission import SecureTransmission, EventType, EncryptionLevel
from realtime.enhanced_alert_manager import EnhancedAlertManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BlueWallSecurityDemo:
    """Demonstration of BlueWall security integration."""
    
    def __init__(self):
        """Initialize all security modules."""
        logger.info("Initializing BlueWall Security Demo...")
        
        # Initialize security modules
        self.anti_re = AntiReverseEngineering()
        self.anti_cheat = EnhancedAntiCheat()
        self.secure_transmission = SecureTransmission()
        self.alert_manager = EnhancedAlertManager()
        
        # Demo data
        self.demo_client_id = "demo_client_123"
        self.demo_session_id = "demo_session_456"
        self.demo_user_id = "demo_user_789"
        
        logger.info("BlueWall Security Demo initialized successfully")
    
    def demonstrate_anti_reverse_engineering(self):
        """Demonstrate anti-reverse-engineering capabilities."""
        logger.info("\n=== Anti-Reverse-Engineering Demo ===")
        
        # Simulate client code integrity check
        client_data = {
            "client_id": self.demo_client_id,
            "platform": "windows",
            "version": "1.0.0",
            "executable_sections": [
                {
                    "name": "text",
                    "expected_hash": "abc123def456",
                    "actual_hash": "abc123def456"  # Valid hash
                },
                {
                    "name": "data",
                    "expected_hash": "def456ghi789",
                    "actual_hash": "def456ghi789"  # Valid hash
                }
            ]
        }
        
        # Verify code integrity
        is_valid, alert = self.anti_re.verify_code_integrity(client_data)
        logger.info(f"Code integrity check: {'PASSED' if is_valid else 'FAILED'}")
        
        if alert:
            logger.warning(f"Code integrity alert: {alert.alert_type}")
        
        # Generate session key
        platform = PlatformType.WINDOWS
        session_key = self.anti_re.generate_session_key(self.demo_client_id, platform)
        logger.info(f"Generated session key: {session_key['key_id']}")
        
        # Test decoy endpoint
        decoy_endpoint = "/decoy/api_test"
        is_decoy, response = self.anti_re.check_decoy_endpoint(decoy_endpoint, client_data)
        if is_decoy:
            logger.info(f"Decoy endpoint triggered: {decoy_endpoint}")
        
        # Test honeytoken access
        honeytoken_triggered = self.anti_re.check_honeytoken_access("honeytoken_0_abc123", self.demo_client_id)
        if honeytoken_triggered:
            logger.warning("Honeytoken triggered!")
        
        # Get anti-RE summary
        summary = self.anti_re.get_anti_re_summary()
        logger.info(f"Anti-RE Summary: {summary}")
    
    def demonstrate_enhanced_anti_cheat(self):
        """Demonstrate enhanced anti-cheat capabilities."""
        logger.info("\n=== Enhanced Anti-Cheat Demo ===")
        
        # Simulate game state validation
        client_state = {
            "position": {"x": 100.0, "y": 50.0, "z": 25.0},
            "inventory": {"sword": 1, "shield": 1, "potion": 5},
            "resources": {"gold": 1000, "experience": 5000},
            "abilities": ["attack", "defend", "heal"],
            "health": 100.0,
            "stamina": 80.0,
            "experience": 5000.0,
            "level": 10,
            "session_id": self.demo_session_id,
            "client_hash": "client_hash_123"
        }
        
        # Validate game state
        is_valid, alert = self.anti_cheat.validate_game_state(client_state, self.demo_user_id)
        logger.info(f"Game state validation: {'PASSED' if is_valid else 'FAILED'}")
        
        if alert:
            logger.warning(f"Game state alert: {alert.alert_type}")
        
        # Simulate memory validation
        memory_data = {
            "memory_segments": [
                {
                    "name": "code_segment",
                    "expected_hash": "memory_hash_123",
                    "actual_hash": "memory_hash_123",
                    "size": 1024
                }
            ]
        }
        
        is_valid, alert = self.anti_cheat.validate_memory_segments(memory_data, self.demo_user_id)
        logger.info(f"Memory validation: {'PASSED' if is_valid else 'FAILED'}")
        
        if alert:
            logger.warning(f"Memory alert: {alert.alert_type}")
        
        # Simulate asset verification
        assets_data = {
            "player_model_001": {
                "hash": "abc123",
                "size": 1024
            }
        }
        
        is_valid, alert = self.anti_cheat.verify_asset_signatures(assets_data, self.demo_user_id)
        logger.info(f"Asset verification: {'PASSED' if is_valid else 'FAILED'}")
        
        if alert:
            logger.warning(f"Asset alert: {alert.alert_type}")
        
        # Generate sanity check
        sanity_check = self.anti_cheat.generate_sanity_check(self.demo_user_id)
        if sanity_check:
            logger.info(f"Generated sanity check: {sanity_check.challenge_type}")
            
            # Simulate response
            if sanity_check.challenge_type == "math":
                response = str(sanity_check.challenge_data["a"] + sanity_check.challenge_data["b"])
            else:
                response = "test_response"
            
            is_valid, alert = self.anti_cheat.validate_sanity_check_response(
                sanity_check.challenge_id, response, self.demo_user_id
            )
            logger.info(f"Sanity check response: {'PASSED' if is_valid else 'FAILED'}")
        
        # Get anti-cheat summary
        summary = self.anti_cheat.get_enhanced_anti_cheat_summary()
        logger.info(f"Enhanced Anti-Cheat Summary: {summary}")
    
    def demonstrate_secure_transmission(self):
        """Demonstrate secure transmission capabilities."""
        logger.info("\n=== Secure Transmission Demo ===")
        
        # Generate session key
        session_key = self.secure_transmission.generate_session_key(self.demo_session_id, self.demo_user_id)
        logger.info(f"Generated session key: {session_key[:20]}...")
        
        # Encrypt game event
        game_payload = {
            "action": "player_move",
            "position": {"x": 100.0, "y": 50.0, "z": 25.0},
            "timestamp": time.time(),
            "player_id": self.demo_user_id
        }
        
        secure_event = self.secure_transmission.encrypt_event(
            EventType.GAME_ACTION,
            self.demo_user_id,
            self.demo_session_id,
            game_payload,
            EncryptionLevel.HIGH
        )
        
        if secure_event:
            logger.info(f"Encrypted event: {secure_event.event_id}")
            
            # Decrypt event
            decrypted_payload = self.secure_transmission.decrypt_event(secure_event, self.demo_session_id)
            if decrypted_payload:
                logger.info(f"Decrypted payload: {decrypted_payload['action']}")
            
            # Verify hash chain
            is_valid, violations = self.secure_transmission.verify_hash_chain()
            logger.info(f"Hash chain verification: {'PASSED' if is_valid else 'FAILED'}")
            
            if violations:
                logger.warning(f"Hash chain violations: {len(violations)}")
        
        # Rotate encryption keys
        self.secure_transmission.rotate_encryption_keys()
        logger.info("Encryption keys rotated")
        
        # Get secure transmission summary
        summary = self.secure_transmission.get_secure_transmission_summary()
        logger.info(f"Secure Transmission Summary: {summary}")
    
    async def demonstrate_enhanced_alerts(self):
        """Demonstrate enhanced alert system."""
        logger.info("\n=== Enhanced Alert System Demo ===")
        
        # Simulate security alerts
        alert_data = {
            "alert_type": "code_integrity_violation",
            "severity": "high",
            "identifier": self.demo_client_id,
            "details": {
                "section_name": "text",
                "expected_hash": "abc123",
                "actual_hash": "def456"
            },
            "mitigation_action": "immediate_ban",
            "confidence_score": 0.95,
            "location_data": {
                "latitude": 40.7128,
                "longitude": -74.0060
            }
        }
        
        # Broadcast enhanced alert
        await self.alert_manager.broadcast_enhanced_alert(alert_data, "anti_reverse_engineering")
        logger.info("Enhanced alert broadcasted")
        
        # Simulate another alert
        cheat_alert_data = {
            "alert_type": "speed_hack_detected",
            "severity": "critical",
            "identifier": self.demo_user_id,
            "details": {
                "detected_speed": 25.0,
                "max_allowed_speed": 10.0
            },
            "mitigation_action": "immediate_ban",
            "confidence_score": 0.98,
            "location_data": {
                "latitude": 34.0522,
                "longitude": -118.2437
            }
        }
        
        await self.alert_manager.broadcast_enhanced_alert(cheat_alert_data, "enhanced_anti_cheat")
        logger.info("Cheat detection alert broadcasted")
        
        # Get alert summary
        summary = self.alert_manager.get_enhanced_alert_summary()
        logger.info(f"Enhanced Alert Summary: {summary}")
    
    def demonstrate_threat_scenarios(self):
        """Demonstrate various threat scenarios."""
        logger.info("\n=== Threat Scenarios Demo ===")
        
        # Scenario 1: Code modification attempt
        logger.info("Scenario 1: Code modification attempt")
        modified_client_data = {
            "client_id": "malicious_client",
            "platform": "windows",
            "version": "1.0.0",
            "executable_sections": [
                {
                    "name": "text",
                    "expected_hash": "abc123def456",
                    "actual_hash": "modified_hash_789"  # Modified hash
                }
            ]
        }
        
        is_valid, alert = self.anti_re.verify_code_integrity(modified_client_data)
        logger.info(f"Modified code detection: {'DETECTED' if not is_valid else 'MISSED'}")
        
        # Scenario 2: Impossible movement
        logger.info("Scenario 2: Impossible movement")
        impossible_movement = {
            "position": {"x": 1000.0, "y": 5000.0, "z": 2500.0},  # Impossible position
            "inventory": {"sword": 1},
            "resources": {"gold": 1000},
            "abilities": ["attack"],
            "health": 100.0,
            "stamina": 80.0,
            "experience": 5000.0,
            "level": 10,
            "session_id": self.demo_session_id,
            "client_hash": "client_hash_123"
        }
        
        is_valid, alert = self.anti_cheat.validate_game_state(impossible_movement, "malicious_user")
        logger.info(f"Impossible movement detection: {'DETECTED' if not is_valid else 'MISSED'}")
        
        # Scenario 3: Asset tampering
        logger.info("Scenario 3: Asset tampering")
        tampered_assets = {
            "player_model_001": {
                "hash": "tampered_hash_123",  # Modified hash
                "size": 1024
            }
        }
        
        is_valid, alert = self.anti_cheat.verify_asset_signatures(tampered_assets, "malicious_user")
        logger.info(f"Asset tampering detection: {'DETECTED' if not is_valid else 'MISSED'}")
    
    def run_comprehensive_demo(self):
        """Run comprehensive security demonstration."""
        logger.info("Starting BlueWall Security Comprehensive Demo")
        logger.info("=" * 60)
        
        try:
            # Run all demonstrations
            self.demonstrate_anti_reverse_engineering()
            self.demonstrate_enhanced_anti_cheat()
            self.demonstrate_secure_transmission()
            
            # Run async demonstrations
            asyncio.run(self.demonstrate_enhanced_alerts())
            
            # Run threat scenarios
            self.demonstrate_threat_scenarios()
            
            logger.info("\n" + "=" * 60)
            logger.info("BlueWall Security Demo completed successfully!")
            
            # Final summary
            self.print_final_summary()
            
        except Exception as e:
            logger.error(f"Error during demo: {e}")
            raise
    
    def print_final_summary(self):
        """Print final summary of all security systems."""
        logger.info("\n=== FINAL SECURITY SYSTEM SUMMARY ===")
        
        # Anti-RE summary
        anti_re_summary = self.anti_re.get_anti_re_summary()
        logger.info(f"Anti-Reverse-Engineering: {anti_re_summary['total_code_checks']} checks, "
                   f"{anti_re_summary['decoy_endpoints']} decoys, "
                   f"{anti_re_summary['honeytokens']} honeytokens")
        
        # Anti-cheat summary
        anti_cheat_summary = self.anti_cheat.get_enhanced_anti_cheat_summary()
        logger.info(f"Enhanced Anti-Cheat: {anti_cheat_summary['active_game_states']} states, "
                   f"{anti_cheat_summary['memory_validations']} memory checks, "
                   f"{anti_cheat_summary['asset_signatures']} asset signatures")
        
        # Secure transmission summary
        transmission_summary = self.secure_transmission.get_secure_transmission_summary()
        logger.info(f"Secure Transmission: {transmission_summary['total_events']} events, "
                   f"{transmission_summary['active_encryption_keys']} keys, "
                   f"{transmission_summary['hash_chain_length']} hash chain entries")
        
        # Alert system summary
        alert_summary = self.alert_manager.get_enhanced_alert_summary()
        logger.info(f"Enhanced Alerts: {alert_summary['alert_stats']['total_alerts']} alerts, "
                   f"{alert_summary['globe_markers']} globe markers, "
                   f"{alert_summary['threat_levels']} threat levels")
        
        logger.info("\nAll security systems are operational and monitoring for threats!")

def main():
    """Main function to run the security demo."""
    try:
        # Create and run demo
        demo = BlueWallSecurityDemo()
        demo.run_comprehensive_demo()
        
    except KeyboardInterrupt:
        logger.info("\nDemo interrupted by user")
    except Exception as e:
        logger.error(f"Demo failed: {e}")
        raise

if __name__ == "__main__":
    main()
