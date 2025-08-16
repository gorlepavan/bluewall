// BlueWall Frontend Configuration

export const config = {
  // Backend API URL
  API_URL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
  
  // WebSocket URL
  WS_URL: import.meta.env.VITE_WS_URL || 'ws://localhost:8000',
  
  // Development mode
  DEV_MODE: import.meta.env.VITE_DEV_MODE === 'true',
  
  // Feature flags
  ENABLE_BLOOM: import.meta.env.VITE_ENABLE_BLOOM !== 'false',
  ENABLE_ATMOSPHERE: import.meta.env.VITE_ENABLE_ATMOSPHERE !== 'false',
  ENABLE_AUTO_ROTATION: import.meta.env.VITE_ENABLE_AUTO_ROTATION !== 'false',
  
  // 3D Settings
  EARTH_RADIUS: 1,
  ATMOSPHERE_RADIUS: 1.02,
  AUTO_ROTATION_SPEED: 0.001,
  
  // WebSocket Settings
  MAX_RECONNECT_ATTEMPTS: 5,
  RECONNECT_DELAY_BASE: 1000,
  MAX_RECONNECT_DELAY: 10000,
  
  // Alert Settings
  MAX_ALERTS_IN_MEMORY: 100,
  ALERT_ANIMATION_DURATION: 300,
  
  // UI Settings
  SIDEBAR_WIDTH: 320,
  HEADER_HEIGHT: 80,
  ANIMATION_DURATION: 200,
};
