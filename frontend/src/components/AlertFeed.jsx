import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';

const AlertFeed = ({ alerts, isConnected }) => {
  const getThreatColor = (threatLevel) => {
    switch (threatLevel?.toLowerCase()) {
      case 'low':
        return 'border-green-500 bg-green-500/10';
      case 'medium':
        return 'border-orange-500 bg-orange-500/10';
      case 'high':
        return 'border-red-500 bg-red-500/10';
      default:
        return 'border-gray-500 bg-gray-500/10';
    }
  };

  const getThreatIcon = (threatLevel) => {
    switch (threatLevel?.toLowerCase()) {
      case 'low':
        return '🟢';
      case 'medium':
        return '🟠';
      case 'high':
        return '🔴';
      default:
        return '⚪';
    }
  };

  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    return date.toLocaleDateString();
  };

  return (
    <div className="w-80 h-full flex flex-col bg-gray-900/80 backdrop-blur-sm border-r border-gray-700">
      {/* Header */}
      <div className="p-4 border-b border-gray-700">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Security Alerts</h2>
          <div className="flex items-center space-x-2">
            <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-400' : 'bg-red-400'}`}></div>
            <span className="text-xs text-gray-400">
              {isConnected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
        </div>
        <p className="text-sm text-gray-400 mt-1">
          Real-time threat monitoring
        </p>
      </div>

      {/* Alerts List */}
      <div className="flex-1 overflow-hidden">
        {alerts.length === 0 ? (
          <div className="flex items-center justify-center h-full">
            <div className="text-center text-gray-500">
              <div className="text-4xl mb-2">🌍</div>
              <p className="text-sm">No alerts yet</p>
              <p className="text-xs text-gray-600">Monitoring for threats...</p>
            </div>
          </div>
        ) : (
          <div className="h-full overflow-y-auto p-2">
            <AnimatePresence initial={false}>
              {alerts.map((alert, index) => (
                <motion.div
                  key={alert.id}
                  initial={{ opacity: 0, x: 50, scale: 0.9 }}
                  animate={{ opacity: 1, x: 0, scale: 1 }}
                  exit={{ opacity: 0, x: -50, scale: 0.9 }}
                  transition={{ duration: 0.3, delay: index * 0.1 }}
                  className={`mb-3 p-3 rounded-lg border-l-4 ${getThreatColor(alert.threat_level)} hover:bg-white/5 transition-all duration-200 cursor-pointer`}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-center space-x-2">
                      <span className="text-lg">{getThreatIcon(alert.threat_level)}</span>
                      <div className="flex-1">
                        <div className="flex items-center space-x-2">
                          <span className="font-medium text-white text-sm">
                            {alert.wall_name || 'Unknown Wall'}
                          </span>
                          <span className={`px-2 py-1 rounded-full text-xs font-medium uppercase ${
                            alert.threat_level === 'high' ? 'bg-red-500/20 text-red-300' :
                            alert.threat_level === 'medium' ? 'bg-orange-500/20 text-orange-300' :
                            'bg-green-500/20 text-green-300'
                          }`}>
                            {alert.threat_level || 'Unknown'}
                          </span>
                        </div>
                        
                        {alert.details && (
                          <p className="text-gray-300 text-sm mt-1 line-clamp-2">
                            {alert.details}
                          </p>
                        )}
                        
                        <div className="flex items-center justify-between mt-2">
                          <span className="text-xs text-gray-400">
                            {formatTimestamp(alert.timestamp)}
                          </span>
                          
                          {alert.location && (
                            <span className="text-xs text-bluewall-300">
                              📍 {alert.location}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="p-3 border-t border-gray-700 bg-gray-800/50">
        <div className="text-center">
          <p className="text-xs text-gray-400">
            {alerts.length} alert{alerts.length !== 1 ? 's' : ''} • Last updated: {alerts.length > 0 ? formatTimestamp(alerts[0]?.timestamp) : 'Never'}
          </p>
        </div>
      </div>
    </div>
  );
};

export default AlertFeed;
