# BlueWall Security Walls Package

A comprehensive security framework implementing five elemental security wall modules for multi-layered threat detection and prevention.

## Overview

The Security Walls package provides a sophisticated, multi-layered approach to cybersecurity by implementing five specialized security modules, each designed to protect against specific types of threats. This elemental approach ensures comprehensive coverage across all attack vectors.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Security Walls Manager                   │
├─────────────────────────────────────────────────────────────┤
│  Air Wall  │  Fire Wall  │  Earth Wall  │  Water Wall    │
│ (Network)  │ (Auth/Sess) │ (Data/DB)   │ (API/Misuse)   │
└─────────────────────────────────────────────────────────────┘
                              │
                        ┌─────┴─────┐
                        │ Ether Wall│
                        │ (Game/AC) │
                        └───────────┘
```

## Elemental Wall Modules

### 🔵 Air Wall - Network Traffic Analysis

**Purpose**: First line of defense against network-level attacks

**Capabilities**:
- DDoS attack detection and mitigation
- Rate limiting and traffic shaping
- Packet flood detection
- Geographic clustering analysis
- Abnormal request velocity detection
- Network anomaly identification

**Threats Detected**:
- Distributed Denial of Service (DDoS)
- Brute force network attacks
- Geographic attack patterns
- Traffic spikes and anomalies
- Packet flooding attacks

**Configuration**:
```python
air_wall_config = {
    "max_requests_per_minute": 60,
    "max_requests_per_hour": 1000,
    "ddos_burst_threshold": 100,
    "ddos_sustained_threshold": 500,
    "max_packet_size": 1048576,  # 1MB
    "enable_geo_tracking": True
}
```

### 🔴 Fire Wall - Authentication & Session Security

**Purpose**: Protection against authentication-based attacks and session hijacking

**Capabilities**:
- Brute force attack detection
- Progressive account locking
- JWT token replay detection
- Session hijacking prevention
- TOTP bypass detection
- IP-based blocking

**Threats Detected**:
- Credential stuffing attacks
- Brute force login attempts
- JWT token replay
- Session hijacking
- TOTP bypass attempts
- Account takeover

**Configuration**:
```python
fire_wall_config = {
    "max_failed_logins_per_username": 5,
    "brute_force_threshold": 3,
    "account_lock_duration_minutes": 30,
    "progressive_lock_duration": True,
    "jwt_replay_threshold": 3
}
```

### 🟢 Earth Wall - Data Integrity & Database Security

**Purpose**: Protection of data integrity and prevention of unauthorized database changes

**Capabilities**:
- Database operation monitoring
- Schema change detection
- Privilege escalation prevention
- Data sensitivity analysis
- Unusual access pattern detection
- Data exfiltration prevention

**Threats Detected**:
- Unauthorized schema changes
- Privilege escalation attempts
- Excessive data access
- Data manipulation attacks
- Bulk data operations
- Suspicious database patterns

**Configuration**:
```python
earth_wall_config = {
    "allow_schema_changes": False,
    "max_operations_per_user_per_minute": 100,
    "max_sensitive_data_access_per_hour": 10,
    "monitor_privilege_changes": True,
    "restricted_operation_types": ["DROP", "ALTER", "GRANT"]
}
```

### 💧 Water Wall - API Misuse & Dynamic IP Management

**Purpose**: Protection against API abuse and dynamic threat response

**Capabilities**:
- API abuse detection
- Dynamic IP blacklisting/whitelisting
- Reputation scoring
- Geographic abuse patterns
- Endpoint abuse detection
- Adaptive security measures

**Threats Detected**:
- API rate limit violations
- Geographic abuse patterns
- Suspicious user agents
- Large request attacks
- Endpoint abuse
- IP reputation violations

**Configuration**:
```python
water_wall_config = {
    "max_requests_per_ip_per_minute": 60,
    "blacklist_threshold": 20.0,
    "whitelist_threshold": 80.0,
    "enable_geo_tracking": True,
    "auto_blacklist_enabled": True,
    "progressive_blacklist": True
}
```

### ⚡ Ether Wall - Advanced Anti-Cheat & Anti-Hacking

**Purpose**: Game-specific protection and advanced threat detection

**Capabilities**:
- Server authoritative validation
- Physics validation
- Client integrity checks
- Bot detection
- Memory injection detection
- Behavior pattern analysis

**Threats Detected**:
- Speed hacking
- Teleportation hacks
- Aimbot detection
- Wallhack attempts
- Client modification
- Memory injection
- Bot automation

**Configuration**:
```python
ether_wall_config = {
    "speed_hack_threshold": 1.5,
    "teleport_distance_threshold": 100.0,
    "bot_response_time_threshold": 0.1,
    "physics_validation_enabled": True,
    "collision_detection": True,
    "behavior_analysis_enabled": True
}
```

## Integration

### SecurityWallsManager

The `SecurityWallsManager` class provides a unified interface for all security walls:

```python
from security_walls.integration import SecurityWallsManager

# Initialize manager
manager = SecurityWallsManager()

# Analyze request through all walls
request_data = {
    "ip_address": "192.168.1.100",
    "user_id": "user123",
    "endpoint": "/api/game/action",
    "method": "POST",
    "game_action": "player_move"
}

alerts = manager.analyze_request(request_data)

# Get comprehensive security status
status = manager.get_security_status()
```

### Request Flow

1. **Request Reception**: All requests are received by the main application
2. **Air Wall Analysis**: Network traffic patterns are analyzed
3. **Water Wall Analysis**: API usage patterns are monitored
4. **Fire Wall Analysis**: Authentication patterns are checked (if applicable)
5. **Earth Wall Analysis**: Database operations are monitored (if applicable)
6. **Ether Wall Analysis**: Game actions are validated (if applicable)
7. **Alert Generation**: Security alerts are generated and logged
8. **Response**: Appropriate mitigation actions are taken

## Usage Examples

### Basic Integration

```python
# Initialize individual walls
air_wall = AirWall()
fire_wall = FireWall()
earth_wall = EarthWall()
water_wall = WaterWall()
ether_wall = EtherWall()

# Monitor network traffic
air_alert = air_wall.analyze_request({
    "ip_address": "192.168.1.100",
    "endpoint": "/api/endpoint",
    "request_size": 1024
})

# Monitor authentication
fire_alert = fire_wall.record_login_attempt({
    "username": "user123",
    "ip_address": "192.168.1.100",
    "success": False,
    "failure_reason": "Invalid password"
})
```

### Advanced Configuration

```python
# Custom configuration for each wall
config = {
    "air_wall": {
        "max_requests_per_minute": 120,
        "ddos_burst_threshold": 200
    },
    "fire_wall": {
        "max_failed_logins_per_username": 10,
        "account_lock_duration_minutes": 60
    },
    "water_wall": {
        "blacklist_threshold": 15.0,
        "auto_blacklist_enabled": True
    }
}

manager = SecurityWallsManager(config)
```

### Event Logging Integration

```python
from logger.events import EventLogger

event_logger = EventLogger()

# Log security alerts
if air_alert:
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
```

## Configuration

### Environment Variables

```bash
# Air Wall
AIR_WALL_MAX_REQUESTS_PER_MINUTE=60
AIR_WALL_DDOS_BURST_THRESHOLD=100

# Fire Wall
FIRE_WALL_MAX_FAILED_LOGINS=5
FIRE_WALL_ACCOUNT_LOCK_DURATION=30

# Water Wall
WATER_WALL_BLACKLIST_THRESHOLD=20.0
WATER_WALL_AUTO_BLACKLIST=true

# Ether Wall
ETHER_WALL_SPEED_HACK_THRESHOLD=1.5
ETHER_WALL_PHYSICS_VALIDATION=true
```

### Configuration Files

```yaml
# config/security_walls.yaml
air_wall:
  max_requests_per_minute: 60
  ddos_burst_threshold: 100
  enable_geo_tracking: true

fire_wall:
  max_failed_logins_per_username: 5
  brute_force_threshold: 3
  progressive_lock_duration: true

water_wall:
  blacklist_threshold: 20.0
  auto_blacklist_enabled: true
  progressive_blacklist: true

ether_wall:
  speed_hack_threshold: 1.5
  physics_validation_enabled: true
  behavior_analysis_enabled: true
```

## Monitoring & Alerting

### Security Status

```python
# Get comprehensive security status
status = manager.get_security_status()

print(f"Active IPs: {status['air_wall']['active_ips']}")
print(f"Blocked Users: {status['fire_wall']['blocked_usernames']}")
print(f"Blacklisted IPs: {status['water_wall']['blacklisted_ips']}")
print(f"Total Alerts: {status['total_alerts']}")
```

### Alert Management

```python
# Get recent alerts
recent_alerts = manager.get_recent_alerts(limit=20)

for alert in recent_alerts:
    print(f"{alert['source_wall']}: {alert['alert_type']} - {alert['severity']}")
    print(f"Target: {alert['identifier']}")
    print(f"Action: {alert['mitigation_action']}")
```

## Performance Considerations

### Memory Management

- Each wall maintains its own data structures
- Automatic cleanup of old data (configurable intervals)
- Configurable storage limits for each wall
- Efficient data structures for high-traffic scenarios

### Scalability

- Stateless design for horizontal scaling
- Configurable thresholds for different environments
- Support for distributed deployments
- Efficient algorithms for real-time analysis

### Monitoring

- Built-in performance metrics
- Configurable logging levels
- Alert aggregation and correlation
- Real-time status monitoring

## Security Features

### Tamper Detection

- Hash-based integrity verification
- Timestamp validation
- Source verification
- Alert correlation

### Adaptive Security

- Progressive penalty systems
- Reputation-based scoring
- Geographic pattern recognition
- Behavioral analysis

### Compliance

- Comprehensive audit logging
- Event correlation
- Alert tracking and resolution
- Compliance reporting

## Testing

### Unit Tests

```python
# Test individual wall functionality
def test_air_wall_ddos_detection():
    air_wall = AirWall()
    # Test DDoS detection logic
    
def test_fire_wall_brute_force():
    fire_wall = FireWall()
    # Test brute force detection
```

### Integration Tests

```python
# Test wall integration
def test_security_walls_integration():
    manager = SecurityWallsManager()
    # Test complete request flow through all walls
```

### Performance Tests

```python
# Test performance under load
def test_high_traffic_performance():
    manager = SecurityWallsManager()
    # Test with high request volumes
```

## Deployment

### Production Considerations

- Configure appropriate thresholds for your environment
- Enable monitoring and alerting
- Set up log aggregation
- Configure backup and recovery
- Monitor performance metrics

### Scaling

- Deploy walls on separate servers if needed
- Use load balancers for high availability
- Implement caching for frequently accessed data
- Consider database sharding for large deployments

## Troubleshooting

### Common Issues

1. **High Memory Usage**: Check cleanup intervals and storage limits
2. **False Positives**: Adjust thresholds based on your traffic patterns
3. **Performance Issues**: Monitor wall-specific metrics and optimize
4. **Alert Overload**: Implement alert correlation and filtering

### Debug Mode

```python
# Enable debug logging
import logging
logging.getLogger("security_walls").setLevel(logging.DEBUG)

# Enable wall-specific debugging
air_wall.config["debug_mode"] = True
fire_wall.config["debug_mode"] = True
```

## Contributing

### Adding New Walls

1. Create new wall module following existing patterns
2. Implement required interface methods
3. Add configuration options
4. Update integration manager
5. Add tests and documentation

### Extending Existing Walls

1. Add new detection methods
2. Implement new configuration options
3. Update alert types and details
4. Maintain backward compatibility

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Create an issue in the repository
- Check the documentation
- Review the code examples
- Contact the development team
