# BlueWall Admin Dashboard Frontend

A cinematic 3D security monitoring dashboard built with React, Three.js, and real-time WebSocket integration.

## Features

- 🌍 **3D Earth Visualization**: Interactive 3D globe with realistic textures and atmospheric effects
- 🚨 **Real-time Threat Monitoring**: Live security alerts with WebSocket integration
- 📍 **Geographic Threat Markers**: Visual threat indicators at specific lat/lon coordinates
- 🎨 **Cinematic Effects**: Bloom glow, atmospheric haze, and smooth animations
- 📱 **Responsive Design**: Modern UI with TailwindCSS and Framer Motion
- 🔐 **Secure Authentication**: JWT-based login with TOTP support
- 📊 **Live Alert Feed**: Real-time sidebar showing incoming security alerts

## Tech Stack

- **React 18** - Modern React with hooks and functional components
- **Vite** - Fast build tool and dev server
- **Three.js** - 3D graphics library
- **React Three Fiber** - React renderer for Three.js
- **Drei** - Useful helpers for React Three Fiber
- **TailwindCSS** - Utility-first CSS framework
- **Framer Motion** - Animation library for React
- **WebSocket** - Real-time communication with backend

## Project Structure

```
src/
├── components/
│   ├── Login.jsx          # Authentication form
│   ├── AlertFeed.jsx      # Real-time alerts sidebar
│   └── Earth3D.jsx        # 3D Earth visualization
├── hooks/
│   └── useWebSocket.js    # WebSocket connection hook
├── App.jsx                # Main application component
├── main.jsx               # Application entry point
└── index.css              # Global styles and Tailwind imports
```

## Getting Started

### Prerequisites

- Node.js 16+ and npm
- Backend server running (see backend README)

### Installation

1. Install dependencies:
```bash
npm install
```

2. Start development server:
```bash
npm run dev
```

3. Open http://localhost:3000 in your browser

### Build for Production

```bash
npm run build
```

The built files will be in the `dist/` directory.

## Configuration

### Backend Integration

The frontend expects the backend to be running on `localhost:8000`. Update the WebSocket URL in `App.jsx` if needed:

```jsx
const { isConnected, alerts, error: wsError } = useWebSocket(
  isAuthenticated ? 'ws://localhost:8000/ws/security/alerts' : null,
  jwtToken
);
```

### Environment Variables

Create a `.env` file in the frontend directory:

```env
VITE_API_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000
```

## Features in Detail

### 3D Earth Visualization

- **Realistic Textures**: High-quality Earth textures with bump mapping
- **Atmospheric Effects**: Subtle blue atmosphere around the globe
- **Interactive Controls**: Orbit controls for camera movement
- **Auto-rotation**: Gentle Earth rotation for dynamic feel

### Threat Markers

- **Color-coded**: Green (low), Orange (medium), Red (high) threat levels
- **Animated**: Pulsing animation to draw attention
- **Interactive**: Click to view detailed alert information
- **Geographic**: Accurate positioning based on lat/lon coordinates

### Real-time Alerts

- **WebSocket Integration**: Live connection to backend alert system
- **Auto-reconnect**: Automatic reconnection on connection loss
- **Alert History**: Maintains last 100 alerts in memory
- **Real-time Updates**: Instant updates as new threats are detected

### Authentication

- **JWT Tokens**: Secure token-based authentication
- **TOTP Support**: Two-factor authentication with TOTP codes
- **Persistent Login**: Remembers authentication state
- **Secure Storage**: JWT tokens stored in localStorage

## API Endpoints

The frontend expects these backend endpoints:

- `POST /api/auth/login` - User authentication
- `GET /ws/security/alerts` - WebSocket for real-time alerts

## Styling

### TailwindCSS Classes

- **Glass Panel**: `.glass-panel` for translucent UI elements
- **Threat Colors**: `.threat-low`, `.threat-medium`, `.threat-high`
- **Custom Animations**: `.animate-pulse-slow`, `.animate-bounce-slow`

### Custom CSS

- Dark theme optimized for security monitoring
- Custom scrollbars for better UX
- Responsive design for various screen sizes

## Performance Optimizations

- **React.memo**: Prevents unnecessary re-renders
- **useCallback**: Optimizes function references
- **useMemo**: Caches expensive calculations
- **Lazy Loading**: Components loaded on demand

## Browser Support

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## Troubleshooting

### Common Issues

1. **WebSocket Connection Failed**
   - Ensure backend is running on port 8000
   - Check firewall settings
   - Verify WebSocket endpoint exists

2. **3D Performance Issues**
   - Reduce Earth texture resolution
   - Lower star count in background
   - Disable post-processing effects

3. **Authentication Errors**
   - Verify backend auth endpoint
   - Check JWT token format
   - Ensure TOTP is properly configured

### Development Tips

- Use React DevTools for component debugging
- Three.js Inspector for 3D scene debugging
- Browser DevTools for WebSocket monitoring

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is part of the BlueWall security system. See main project license for details.

## Support

For technical support or questions:
- Check the backend documentation
- Review WebSocket implementation details
- Consult Three.js and React Three Fiber documentation
