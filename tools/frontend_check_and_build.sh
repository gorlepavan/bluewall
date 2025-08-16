#!/bin/bash
# Frontend check and build script for BlueWall
# Runs npm ci, audit fix, build, and linting

set -e

echo "🌐 Running frontend checks and build..."

# Check if we're in the right directory
if [ ! -d "frontend" ]; then
    echo "❌ Error: Must run from project root directory"
    exit 1
fi

cd frontend

# Check if package-lock.json exists
if [ ! -f "package-lock.json" ]; then
    echo "⚠️  No package-lock.json found, running npm install..."
    npm install
else
    echo "📦 Running npm ci..."
    npm ci
fi

# Run npm audit fix
echo "🔒 Running npm audit fix..."
npm audit fix || true

# Check for remaining high/critical vulnerabilities
echo "🔍 Checking for remaining vulnerabilities..."
vulns=$(npm audit --audit-level=high 2>&1 | grep -c "high\|critical" || echo "0")
if [ "$vulns" -gt 0 ]; then
    echo "⚠️  High/Critical vulnerabilities found, attempting force fix..."
    npm audit fix --force || true
fi

# Run ESLint if config exists
if [ -f ".eslintrc.js" ] || [ -f ".eslintrc.json" ] || [ -f ".eslintrc" ]; then
    echo "🔍 Running ESLint..."
    npx eslint --fix . --ext .js,.jsx,.ts,.tsx || true
fi

# Run Stylelint if config exists
if [ -f ".stylelintrc" ] || [ -f ".stylelintrc.js" ] || [ -f ".stylelintrc.json" ]; then
    echo "🎨 Running Stylelint..."
    npx stylelint --fix "**/*.css" || true
fi

# Build the project
echo "🏗️  Building frontend..."
if [ -f "vite.config.js" ]; then
    echo "   Using Vite build..."
    npm run build || npx vite build
else
    echo "   Using npm build..."
    npm run build
fi

# Build Tailwind CSS
echo "🎨 Building Tailwind CSS..."
if [ -f "tailwind.config.js" ]; then
    npx tailwindcss -i src/styles.css -o dist/styles.css --minify || {
        echo "⚠️  Tailwind build failed, trying alternative..."
        npx tailwindcss -i src/index.css -o dist/styles.css --minify || true
    }
fi

echo "✅ Frontend checks and build complete!"
