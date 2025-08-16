import React, { useRef, useMemo, useEffect, useState } from 'react';
import { useFrame, useThree } from '@react-three/fiber';
import { Sphere, Stars, Text, Html } from '@react-three/drei';
import * as THREE from 'three';

const Earth3D = ({ alerts, onMarkerClick }) => {
  const earthRef = useRef();
  const groupRef = useRef();
  const { camera } = useThree();
  const [texturesLoaded, setTexturesLoaded] = useState(false);

  // Earth material with fallback for missing textures
  const earthMaterial = useMemo(() => {
    const material = new THREE.MeshPhongMaterial({
      color: new THREE.Color(0x0077ff), // Blue fallback
      shininess: 5
    });

    // Try to load textures, fallback gracefully if they fail
    const textureLoader = new THREE.TextureLoader();
    
    // Load Earth texture
    textureLoader.load(
      '/earth_texture.jpg',
      (texture) => {
        material.map = texture;
        material.needsUpdate = true;
        setTexturesLoaded(true);
      },
      undefined,
      (error) => {
        console.warn('Earth texture failed to load, using fallback:', error);
        // Use procedural texture as fallback
        material.color.setHex(0x0077ff);
      }
    );

    // Load bump map
    textureLoader.load(
      '/earth_bump.jpg',
      (bumpMap) => {
        material.bumpMap = bumpMap;
        material.bumpScale = 0.05;
        material.needsUpdate = true;
      },
      undefined,
      (error) => {
        console.warn('Earth bump map failed to load:', error);
      }
    );

    // Load specular map
    textureLoader.load(
      '/earth_specular.jpg',
      (specularMap) => {
        material.specularMap = specularMap;
        material.specular = new THREE.Color('grey');
        material.needsUpdate = true;
      },
      undefined,
      (error) => {
        console.warn('Earth specular map failed to load:', error);
      }
    );

    return material;
  }, []);

  // Atmosphere material
  const atmosphereMaterial = useMemo(() => {
    return new THREE.MeshPhongMaterial({
      color: new THREE.Color(0x0077ff),
      transparent: true,
      opacity: 0.1,
      side: THREE.BackSide
    });
  }, []);

  // Convert lat/lon to 3D position
  const latLonToPosition = (lat, lon, radius = 1) => {
    const phi = (90 - lat) * (Math.PI / 180);
    const theta = (lon + 180) * (Math.PI / 180);
    
    const x = -(radius * Math.sin(phi) * Math.cos(theta));
    const z = (radius * Math.sin(phi) * Math.sin(theta));
    const y = (radius * Math.cos(phi));
    
    return [x, y, z];
  };

  // Threat marker component
  const ThreatMarker = ({ alert, position }) => {
    const markerRef = useRef();
    const [hovered, setHovered] = useState(false);

    const getThreatColor = (threatLevel) => {
      switch (threatLevel?.toLowerCase()) {
        case 'low': return '#10b981';
        case 'medium': return '#f59e0b';
        case 'high': return '#ef4444';
        default: return '#6b7280';
      }
    };

    const getThreatSize = (threatLevel) => {
      switch (threatLevel?.toLowerCase()) {
        case 'high': return 0.03;
        case 'medium': return 0.025;
        case 'low': return 0.02;
        default: return 0.02;
      }
    };

    useEffect(() => {
      if (markerRef.current) {
        markerRef.current.material.color.setHex(getThreatColor(alert.threat_level));
      }
    }, [alert.threat_level]);

    useFrame((state) => {
      if (markerRef.current) {
        // Pulsing animation
        const scale = 1 + Math.sin(state.clock.elapsedTime * 3) * 0.2;
        markerRef.current.scale.setScalar(scale);
        
        // Rotation to face camera
        markerRef.current.lookAt(camera.position);
      }
    });

    return (
      <group position={position}>
        {/* Main marker */}
        <mesh
          ref={markerRef}
          onPointerOver={() => setHovered(true)}
          onPointerOut={() => setHovered(false)}
          onClick={() => onMarkerClick(alert)}
        >
          <sphereGeometry args={[getThreatSize(alert.threat_level), 8, 6]} />
          <meshBasicMaterial color={getThreatColor(alert.threat_level)} />
        </mesh>
        
        {/* Glow effect */}
        <mesh position={[0, 0, 0.001]}>
          <sphereGeometry args={[getThreatSize(alert.threat_level) * 1.5, 8, 6]} />
          <meshBasicMaterial 
            color={getThreatColor(alert.threat_level)} 
            transparent 
            opacity={0.3} 
          />
        </mesh>

        {/* Hover tooltip */}
        {hovered && (
          <Html position={[0, 0.05, 0]} center>
            <div className="bg-gray-900 text-white px-3 py-2 rounded-lg text-sm whitespace-nowrap border border-gray-600 shadow-lg">
              <div className="font-medium">{alert.wall_name}</div>
              <div className="text-xs text-gray-300 capitalize">{alert.threat_level} threat</div>
            </div>
          </Html>
        )}
      </group>
    );
  };

  // Auto-rotation
  useFrame((state) => {
    if (earthRef.current) {
      earthRef.current.rotation.y += 0.001;
    }
  });

  // Camera controls
  useEffect(() => {
    // Set initial camera position
    camera.position.set(0, 0, 3);
    camera.lookAt(0, 0, 0);
  }, [camera]);

  return (
    <group ref={groupRef}>
      {/* Stars background */}
      <Stars 
        radius={100} 
        depth={50} 
        count={5000} 
        factor={4} 
        saturation={0} 
        fade 
        speed={1}
      />

      {/* Earth */}
      <mesh ref={earthRef}>
        <Sphere args={[1, 64, 64]}>
          <primitive object={earthMaterial} />
        </Sphere>
      </mesh>

      {/* Atmosphere */}
      <mesh>
        <Sphere args={[1.02, 64, 64]}>
          <primitive object={atmosphereMaterial} />
        </Sphere>
      </mesh>

      {/* Threat markers */}
      {alerts.map((alert, index) => {
        if (alert.latitude && alert.longitude) {
          const position = latLonToPosition(
            parseFloat(alert.latitude), 
            parseFloat(alert.longitude)
          );
          
          return (
            <ThreatMarker
              key={`${alert.id}-${index}`}
              alert={alert}
              position={position}
            />
          );
        }
        return null;
      })}

      {/* Ambient light */}
      <ambientLight intensity={0.2} />
      
      {/* Directional light (sun) */}
      <directionalLight
        position={[5, 3, 5]}
        intensity={1}
        castShadow
        shadow-mapSize-width={2048}
        shadow-mapSize-height={2048}
      />
    </group>
  );
};

export default Earth3D;
