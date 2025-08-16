import React, { useState, useEffect } from 'react';
import { Canvas } from '@react-three/fiber';
import { OrbitControls, EffectComposer, Bloom, Vignette } from '@react-three/drei';
import { motion, AnimatePresence } from 'framer-motion';
import AlertFeed from './components/AlertFeed';
import Earth3D from './components/Earth3D';
import { demoAlerts, generateRandomAlert, simulateRealTimeAlerts } from './data/demoAlerts';

const AppDemo = () => {
  const [alerts, setAlerts] = useState(demoAlerts);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [showControls, setShowControls] = useState(true);
  const [isConnected, setIsConnected] = useState(true);

  // Simulate real-time alerts
  useEffect(() => {
    const interval = simulateRealTimeAlerts((newAlert) => {
      setAlerts(prev => [newAlert, ...prev.slice(0, 99)]);
    }, 15000); // New alert every 15 seconds

    return () => clearInterval(interval);
  }, []);

  const handleMarkerClick = (alert) => {
    setSelectedAlert(alert);
  };

  const handleCloseAlert = () => {
    setSelectedAlert(null);
  };

  const handleLogout = () => {
    // In demo mode, just refresh the page
    window.location.reload();
  };

  return (
    <div className="h-screen flex bg-black overflow-hidden">
      {/* Alert Feed Sidebar */}
      <AlertFeed alerts={alerts} isConnected={isConnected} />

      {/* Main 3D View */}
      <div className="flex-1 relative">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="absolute top-0 left-0 right-0 z-10 p-4"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <h1 className="text-2xl font-bold text-white">BlueWall Security Dashboard</h1>
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 rounded-full bg-green-400"></div>
                <span className="text-sm text-gray-300">Demo Mode - Live Monitoring</span>
              </div>
            </div>
            
            <div className="flex items-center space-x-4">
              <div className="px-3 py-1 bg-yellow-500/20 border border-yellow-500/50 text-yellow-300 rounded-lg text-sm">
                DEMO MODE
              </div>
              
              <button
                onClick={() => setShowControls(!showControls)}
                className="px-4 py-2 bg-bluewall-600 hover:bg-bluewall-700 rounded-lg text-white text-sm transition-colors"
              >
                {showControls ? 'Hide Controls' : 'Show Controls'}
              </button>
              
              <button
                onClick={handleLogout}
                className="px-4 py-2 bg-gray-600 hover:bg-gray-700 rounded-lg text-white text-sm transition-colors"
              >
                Reset Demo
              </button>
            </div>
          </div>
        </motion.div>

        {/* 3D Canvas */}
        <Canvas
          camera={{ position: [0, 0, 3], fov: 60 }}
          className="w-full h-full"
        >
          {/* Post-processing effects */}
          <EffectComposer>
            <Bloom 
              intensity={0.5} 
              luminanceThreshold={0.1} 
              luminanceSmoothing={0.9} 
            />
            <Vignette eskil={false} offset={0.1} darkness={1.1} />
          </EffectComposer>

          {/* 3D Scene */}
          <Earth3D alerts={alerts} onMarkerClick={handleMarkerClick} />

          {/* Camera Controls */}
          {showControls && (
            <OrbitControls
              enablePan={true}
              enableZoom={true}
              enableRotate={true}
              minDistance={1.5}
              maxDistance={10}
              autoRotate={false}
              autoRotateSpeed={0.5}
            />
          )}
        </Canvas>

        {/* Demo Info Overlay */}
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          className="absolute bottom-4 right-4 bg-bluewall-600/90 text-white px-4 py-2 rounded-lg shadow-lg max-w-xs"
        >
          <div className="text-sm">
            <div className="font-medium mb-1">Demo Mode Active</div>
            <div className="text-xs text-bluewall-200">
              New alerts appear every 15 seconds. Click markers to view details.
            </div>
          </div>
        </motion.div>

        {/* Alert Count Badge */}
        <motion.div
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          className="absolute bottom-4 left-4 bg-bluewall-600/90 text-white px-3 py-2 rounded-full shadow-lg"
        >
          <span className="text-sm font-medium">
            {alerts.length} Alert{alerts.length !== 1 ? 's' : ''}
          </span>
        </motion.div>
      </div>

      {/* Alert Detail Modal */}
      <AnimatePresence>
        {selectedAlert && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4"
            onClick={handleCloseAlert}
          >
            <motion.div
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              className="glass-panel p-6 max-w-md w-full"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-white">Alert Details</h3>
                <button
                  onClick={handleCloseAlert}
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  ✕
                </button>
              </div>
              
              <div className="space-y-3">
                <div>
                  <span className="text-gray-400 text-sm">Wall:</span>
                  <p className="text-white font-medium">{selectedAlert.wall_name}</p>
                </div>
                
                <div>
                  <span className="text-gray-400 text-sm">Threat Level:</span>
                  <span className={`ml-2 px-2 py-1 rounded-full text-xs font-medium uppercase ${
                    selectedAlert.threat_level === 'high' ? 'bg-red-500/20 text-red-300' :
                    selectedAlert.threat_level === 'medium' ? 'bg-orange-500/20 text-orange-300' :
                    'bg-green-500/20 text-green-300'
                  }`}>
                    {selectedAlert.threat_level}
                  </span>
                </div>
                
                {selectedAlert.details && (
                  <div>
                    <span className="text-gray-400 text-sm">Details:</span>
                    <p className="text-white text-sm mt-1">{selectedAlert.details}</p>
                  </div>
                )}
                
                {selectedAlert.location && (
                  <div>
                    <span className="text-gray-400 text-sm">Location:</span>
                    <p className="text-white text-sm mt-1">{selectedAlert.location}</p>
                  </div>
                )}
                
                <div>
                  <span className="text-gray-400 text-sm">Coordinates:</span>
                  <p className="text-white text-sm mt-1">
                    {selectedAlert.latitude}, {selectedAlert.longitude}
                  </p>
                </div>
                
                <div>
                  <span className="text-gray-400 text-sm">Timestamp:</span>
                  <p className="text-white text-sm mt-1">
                    {new Date(selectedAlert.timestamp).toLocaleString()}
                  </p>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default AppDemo;
