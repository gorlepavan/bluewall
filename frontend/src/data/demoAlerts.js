// Demo security alerts for testing the frontend
export const demoAlerts = [
  {
    id: 1,
    wall_name: "Fire Wall",
    threat_level: "high",
    details: "Unauthorized access attempt detected from suspicious IP range",
    location: "New York, USA",
    latitude: 40.7128,
    longitude: -74.0060,
    timestamp: new Date(Date.now() - 1000 * 60 * 5).toISOString() // 5 minutes ago
  },
  {
    id: 2,
    wall_name: "Water Wall",
    threat_level: "medium",
    details: "Multiple failed login attempts from geographic anomaly",
    location: "London, UK",
    latitude: 51.5074,
    longitude: -0.1278,
    timestamp: new Date(Date.now() - 1000 * 60 * 15).toISOString() // 15 minutes ago
  },
  {
    id: 3,
    wall_name: "Earth Wall",
    threat_level: "low",
    details: "Unusual traffic pattern detected during off-hours",
    location: "Tokyo, Japan",
    latitude: 35.6762,
    longitude: 139.6503,
    timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString() // 30 minutes ago
  },
  {
    id: 4,
    wall_name: "Air Wall",
    threat_level: "high",
    details: "Critical system breach attempt from known threat actor",
    location: "Sydney, Australia",
    latitude: -33.8688,
    longitude: 151.2093,
    timestamp: new Date(Date.now() - 1000 * 60 * 2).toISOString() // 2 minutes ago
  },
  {
    id: 5,
    wall_name: "Ether Wall",
    threat_level: "medium",
    details: "Suspicious data exfiltration pattern detected",
    location: "Berlin, Germany",
    latitude: 52.5200,
    longitude: 13.4050,
    timestamp: new Date(Date.now() - 1000 * 60 * 45).toISOString() // 45 minutes ago
  },
  {
    id: 6,
    wall_name: "Fire Wall",
    threat_level: "low",
    details: "Minor configuration drift detected in security rules",
    location: "Mumbai, India",
    latitude: 19.0760,
    longitude: 72.8777,
    timestamp: new Date(Date.now() - 1000 * 60 * 60).toISOString() // 1 hour ago
  },
  {
    id: 7,
    wall_name: "Water Wall",
    threat_level: "high",
    details: "Zero-day exploit attempt detected and blocked",
    location: "São Paulo, Brazil",
    latitude: -23.5505,
    longitude: -46.6333,
    timestamp: new Date(Date.now() - 1000 * 60 * 10).toISOString() // 10 minutes ago
  },
  {
    id: 8,
    wall_name: "Earth Wall",
    threat_level: "medium",
    details: "Unusual network behavior from internal system",
    location: "Cairo, Egypt",
    latitude: 30.0444,
    longitude: 31.2357,
    timestamp: new Date(Date.now() - 1000 * 60 * 25).toISOString() // 25 minutes ago
  }
];

// Function to generate a new random alert
export const generateRandomAlert = () => {
  const walls = ["Fire Wall", "Water Wall", "Earth Wall", "Air Wall", "Ether Wall"];
  const threatLevels = ["low", "medium", "high"];
  const locations = [
    { name: "Paris, France", lat: 48.8566, lon: 2.3522 },
    { name: "Moscow, Russia", lat: 55.7558, lon: 37.6176 },
    { name: "Beijing, China", lat: 39.9042, lon: 116.4074 },
    { name: "Mexico City, Mexico", lat: 19.4326, lon: -99.1332 },
    { name: "Cape Town, South Africa", lat: -33.9249, lon: 18.4241 }
  ];

  const randomWall = walls[Math.floor(Math.random() * walls.length)];
  const randomThreat = threatLevels[Math.floor(Math.random() * threatLevels.length)];
  const randomLocation = locations[Math.floor(Math.random() * locations.length)];

  return {
    id: Date.now() + Math.random(),
    wall_name: randomWall,
    threat_level: randomThreat,
    details: `Random security event detected on ${randomWall}`,
    location: randomLocation.name,
    latitude: randomLocation.lat,
    longitude: randomLocation.lon,
    timestamp: new Date().toISOString()
  };
};

// Function to simulate real-time alerts
export const simulateRealTimeAlerts = (callback, interval = 10000) => {
  return setInterval(() => {
    const newAlert = generateRandomAlert();
    callback(newAlert);
  }, interval);
};
