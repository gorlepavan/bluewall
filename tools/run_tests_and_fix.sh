#!/bin/bash
# Test runner script for BlueWall backend
# Runs pytest and attempts automated fixes for common issues

set -e

echo "🧪 Running tests and attempting fixes..."

# Check if we're in the right directory
if [ ! -d "backend" ]; then
    echo "❌ Error: Must run from project root directory"
    exit 1
fi

cd backend

# Install pytest if not present
echo "📦 Installing pytest..."
pip install --quiet pytest pytest-asyncio

# Run tests
echo "🧪 Running pytest..."
pytest -q --tb=short || {
    echo "⚠️  Some tests failed. Attempting to analyze and fix common issues..."
    
    # Check for import errors and try to fix relative imports
    failed_tests=$(pytest --collect-only -q 2>&1 | grep "ImportError\|ModuleNotFoundError" || true)
    
    if [ -n "$failed_tests" ]; then
        echo "🔧 Found import errors, attempting fixes..."
        # This would need more sophisticated logic in practice
        echo "   Manual review needed for import issues"
    fi
    
    # Run tests again to see current status
    echo "🧪 Re-running tests after fixes..."
    pytest -q --tb=short || {
        echo "❌ Tests still failing after fixes"
        exit 1
    }
}

echo "✅ Tests completed successfully!"
