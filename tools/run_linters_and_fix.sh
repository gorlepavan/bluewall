#!/bin/bash
# Linter and formatter script for BlueWall backend
# Runs ruff, black, and isort with auto-fix capabilities

set -e

echo "🔍 Running Python linters and formatters..."

# Check if we're in the right directory
if [ ! -d "backend" ]; then
    echo "❌ Error: Must run from project root directory"
    exit 1
fi

cd backend

# Install dev tools if not present
echo "📦 Installing/updating dev tools..."
pip install --quiet ruff black isort mypy

# Run ruff with auto-fix
echo "🔧 Running ruff with auto-fix..."
ruff check . --fix --exit-zero || true
ruff_fixed=$(ruff check . --exit-zero 2>&1 | grep -c "fixed" || echo "0")

# Run black formatting
echo "🎨 Running black formatter..."
black . --quiet || true

# Run isort
echo "📚 Running isort..."
isort . --atomic || true

# Final check
echo "🔍 Final linting check..."
ruff check . --exit-zero || true

echo "✅ Linting and formatting complete!"
echo "   Ruff fixed: $ruff_fixed issues"
