#!/usr/bin/env python3
"""
Import verification script for BlueWall project.
Tests all expected modules can be imported successfully.
"""

import sys
import traceback
from pathlib import Path

# Add the backend directory to Python path
backend_path = Path(__file__).parent.parent
sys.path.insert(0, str(backend_path))

# Expected modules to test
modules = [
    "main",
    "start",
    "config",
    "auth",
    "db",
    "realtime",
    "security_walls",
    "logger",
]

def test_import(module_name):
    """Test importing a module and return success status."""
    try:
        __import__(module_name)
        print(f"✓ OK: {module_name}")
        return True
    except Exception as e:
        print(f"✗ FAIL: {module_name}")
        print(f"  Error: {e}")
        traceback.print_exc()
        return False

def main():
    """Run import tests for all expected modules."""
    print("Running import verification for BlueWall backend...")
    print("=" * 50)
    
    failed_imports = []
    
    for module in modules:
        if not test_import(module):
            failed_imports.append(module)
        print()
    
    print("=" * 50)
    if failed_imports:
        print(f"❌ Import verification FAILED: {len(failed_imports)} modules failed")
        print(f"Failed modules: {', '.join(failed_imports)}")
        sys.exit(1)
    else:
        print("✅ All imports successful!")
        sys.exit(0)

if __name__ == "__main__":
    main()
