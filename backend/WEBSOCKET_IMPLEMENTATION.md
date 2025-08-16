# WebSocket Threat Broadcasting Implementation

## Overview

This document describes the implementation of real-time security alert broadcasting via WebSockets in the BlueWall backend system. The implementation provides instant notification of security threats to authorized security officers and administrators.

## Architecture

### Components

1. **AlertManager** (`realtime/alert_manager.py`)
   - Centralized WebSocket connection management
   - Client authentication and role-based access control
   - Real-time alert broadcasting
   - Connection health monitoring with heartbeats

2. **WebSocket Endpoint** (`main.py`)
   - `/ws/security/alerts` endpoint for real-time connections
   - JWT token authentication via query parameters
   - Role-based access control (admin, officer only)

3. **Security Wall Integration**
   - All five elemental walls integrated with alert broadcasting
   - Automatic threat notification on detection
   - Structured JSON alert format

4. **Database Extensions**
   - Enhanced SecurityAlert model with new fields
   - Recent alerts endpoint for historical data

## WebSocket Connection Flow

### 1. Connection Establishment

```
Client → WebSocket Connection Request
    ↓
JWT Token Validation (Query Parameter)
    ↓
User Authentication & Role Verification
    ↓
Client Registration with AlertManager
    ↓
Welcome Message Sent
    ↓
Connection Established
```

### 2. Authentication Process

- **Token Format**: `ws://localhost:8000/ws/security/alerts?token=<JWT_TOKEN>`
- **Validation**: JWT token decoded and verified
- **Role Check**: Only `admin` and `officer` roles allowed
- **User Verification**: User must exist and be active

### 3. Message Types

#### Incoming Messages (Client → Server)
- `ping`: Client-initiated ping (server responds with pong)
- `pong`: Response to server heartbeat

#### Outgoing Messages (Server → Client)
- `welcome`: Initial connection confirmation
- `heartbeat`: Server health check
- Security alerts: Real-time threat notifications

## Alert Broadcasting System

### Alert Structure

```json
{
  "alert_id": "uuid-string",
  "wall_name": "Air Wall",
  "threat_level": "high",
  "timestamp": 1234567890.123,
  "details": {
    "alert_type": "ddos_burst_detected",
    "identifier": "192.168.1.100",
    "endpoint": "/api/events",
    "requests_count": 150,
    "mitigation_action": "immediate_block",
    "timestamp": "2024-01-01T12:00:00Z"
  },
  "source_wall": "air_wall",
  "identifier": "192.168.1.100",
  "alert_type": "ddos_burst_detected",
  "severity": "high",
  "mitigation_action": "immediate_block"
}
```

### Threat Levels

- **low**: Minor security events, monitoring recommended
- **medium**: Moderate threats, investigation required
- **high**: Significant threats, immediate action needed
- **critical**: Severe threats, emergency response required

### Security Wall Integration

#### Air Wall
- **Triggers**: DDoS attacks, rate limiting violations, packet floods
- **Data**: IP address, request patterns, geographic clustering
- **Mitigation**: Connection blocking, rate limiting, geographic restrictions

#### Fire Wall
- **Triggers**: Brute force attacks, suspicious logins, JWT replay
- **Data**: Username, IP address, failure patterns, TOTP bypass attempts
- **Mitigation**: Account locking, IP blocking, session invalidation

#### Water Wall
- **Triggers**: API abuse, suspicious response times, geographic abuse
- **Data**: Endpoint access patterns, IP reputation, geographic data
- **Mitigation**: IP blacklisting, access restrictions, geographic blocking

#### Earth Wall
- **Triggers**: Schema changes, privilege escalation, data sensitivity violations
- **Data**: Database operations, user access patterns, table sensitivity
- **Mitigation**: Access restrictions, operation monitoring, privilege review

#### Ether Wall
- **Triggers**: Game cheating, speed hacks, client modifications
- **Data**: Player actions, physics validation, client integrity
- **Mitigation**: Player bans, movement restrictions, client validation

## Connection Management

### Heartbeat System

- **Interval**: 30 seconds between heartbeats
- **Timeout**: 60 seconds for client response
- **Purpose**: Detect dead connections and maintain connection health

### Client Pool Management

- **Registration**: New clients added to connection pool
- **Cleanup**: Dead connections automatically removed
- **Statistics**: Connection counts and alert delivery metrics

### Error Handling

- **Connection Loss**: Graceful disconnection and cleanup
- **Authentication Failures**: Proper error codes and messages
- **Invalid Messages**: JSON validation and error logging

## API Endpoints

### WebSocket
- `GET /ws/security/alerts` - Real-time security alerts

### REST API
- `GET /alerts/recent` - Recent security alerts (admin/officer)
- `GET /security/status` - System status including WebSocket stats

## Security Features

### Authentication
- JWT token validation for all connections
- Role-based access control
- User existence and status verification

### Authorization
- Admin and officer roles only
- Automatic connection termination for unauthorized users
- Secure token handling

### Data Protection
- Structured alert format prevents injection
- Input validation and sanitization
- Secure WebSocket protocol

## Production Considerations

### Scalability
- Connection pooling for multiple clients
- Asynchronous alert broadcasting
- Efficient memory management

### Reliability
- Heartbeat monitoring for connection health
- Automatic cleanup of dead connections
- Error handling and logging

### Monitoring
- Connection statistics and metrics
- Alert delivery success rates
- System health indicators

## Usage Examples

### Frontend WebSocket Connection

```javascript
// Connect to WebSocket with JWT token
const token = 'your-jwt-token-here';
const ws = new WebSocket(`ws://localhost:8000/ws/security/alerts?token=${token}`);

ws.onopen = function() {
    console.log('Connected to security alerts');
};

ws.onmessage = function(event) {
    const alert = JSON.parse(event.data);
    
    if (alert.type === 'welcome') {
        console.log('Welcome message received');
    } else {
        // Handle security alert
        displaySecurityAlert(alert);
    }
};

ws.onclose = function() {
    console.log('Connection closed');
};
```

### Security Wall Alert Broadcasting

```python
# In any security wall module
from realtime.alert_manager import broadcast_alert

# When threat detected
alert_data = {
    "wall_name": "Air Wall",
    "threat_level": "high",
    "details": {
        "alert_type": "ddos_detected",
        "identifier": "192.168.1.100"
    },
    "source_wall": "air_wall",
    "identifier": "192.168.1.100",
    "alert_type": "ddos_detected",
    "severity": "high",
    "mitigation_action": "block_ip"
}

# Broadcast to all connected clients
await broadcast_alert(alert_data)
```

## Testing

### Test Script
Run `python test_websocket.py` to test basic WebSocket functionality.

### Manual Testing
1. Start the backend server
2. Connect with valid JWT token
3. Trigger security alerts through security walls
4. Verify real-time notification delivery

## Troubleshooting

### Common Issues

1. **Connection Refused (4001)**
   - Missing or invalid JWT token
   - Token expired or malformed

2. **Insufficient Privileges (4003)**
   - User role not admin or officer
   - User account inactive

3. **No Alerts Received**
   - Check security wall integration
   - Verify alert broadcasting calls
   - Check connection status

### Debug Information

- Enable debug logging for detailed connection information
- Monitor connection statistics via `/security/status` endpoint
- Check server logs for authentication and connection errors

## Future Enhancements

### Planned Features
- Alert acknowledgment and response tracking
- Custom alert filtering and preferences
- Alert escalation and notification chains
- Integration with external notification systems

### Performance Optimizations
- Connection load balancing
- Alert batching and compression
- Redis-based connection management
- Horizontal scaling support

## Conclusion

The WebSocket threat broadcasting system provides a robust, secure, and scalable solution for real-time security notifications. It integrates seamlessly with the existing security wall infrastructure and provides immediate visibility into security threats for security personnel.

The implementation follows security best practices, includes comprehensive error handling, and is designed for production deployment with proper monitoring and maintenance capabilities.
