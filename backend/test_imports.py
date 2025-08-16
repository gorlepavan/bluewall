#!/usr/bin/env python3
"""
Test script to check if all BlueWall modules can be imported without errors.
"""

import sys
import traceback

def test_imports():
    """Test importing all BlueWall modules."""
    modules_to_test = [
        "db.session",
        "db.models", 
        "auth.security",
        "logger.events",
        "security_walls.air_wall",
        "security_walls.fire_wall",
        "security_walls.earth_wall",
        "security_walls.water_wall",
        "security_walls.ether_wall",
        "security_walls.integration"
    ]
    
    failed_imports = []
    
    for module_name in modules_to_test:
        try:
            print(f"Testing import: {module_name}")
            __import__(module_name)
            print(f"✓ Successfully imported {module_name}")
        except Exception as e:
            print(f"✗ Failed to import {module_name}: {str(e)}")
            failed_imports.append((module_name, str(e)))
            traceback.print_exc()
    
    print("\n" + "="*50)
    if failed_imports:
        print(f"❌ {len(failed_imports)} import(s) failed:")
        for module_name, error in failed_imports:
            print(f"  - {module_name}: {error}")
        return False
    else:
        print("✅ All imports successful!")
        return True

if __name__ == "__main__":
    success = test_imports()
    sys.exit(0 if success else 1)
