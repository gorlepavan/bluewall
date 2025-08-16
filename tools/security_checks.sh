#!/bin/bash
# Security checks script for BlueWall
# Runs Bandit, npm audit, and secrets scanning

set -e

echo "🔒 Running security checks..."

# Check if we're in the right directory
if [ ! -d "backend" ] || [ ! -d "frontend" ]; then
    echo "❌ Error: Must run from project root directory"
    exit 1
fi

# Install Bandit if not present
echo "📦 Installing Bandit..."
pip install --quiet bandit

# Run Bandit on backend
echo "🔍 Running Bandit security scan on backend..."
cd backend
bandit -r . -lll -f json -o ../ci/bandit_report.json || {
    echo "⚠️  Bandit scan completed with issues"
}

# Count high severity issues
high_issues=$(grep -c '"severity": "HIGH"' ../ci/bandit_report.json 2>/dev/null || echo "0")
echo "   High severity issues: $high_issues"

cd ..

# Run npm audit on frontend
echo "🔍 Running npm audit on frontend..."
cd frontend
npm audit --audit-level=high --json > ../ci/npm_audit_report.json 2>/dev/null || {
    echo "⚠️  npm audit completed with issues"
}

# Count high/critical vulnerabilities
high_vulns=$(grep -c '"severity": "high"' ../ci/npm_audit_report.json 2>/dev/null || echo "0")
critical_vulns=$(grep -c '"severity": "critical"' ../ci/npm_audit_report.json 2>/dev/null || echo "0")
echo "   High vulnerabilities: $high_vulns"
echo "   Critical vulnerabilities: $critical_vulns"

cd ..

# Run secrets scan
echo "🔍 Running secrets scan..."
echo "   Scanning for potential secrets in repository..."

# Create secrets scan script
cat > ci/secrets_scan.py << 'EOF'
#!/usr/bin/env python3
import re
import os
from pathlib import Path

def scan_for_secrets():
    """Scan repository for potential secrets."""
    secrets_found = []
    
    # Patterns to look for
    patterns = [
        r'[A-Za-z0-9+/]{40,}={0,2}',  # Base64 strings > 40 chars
        r'SECRET_KEY\s*=\s*["\'][^"\']+["\']',
        r'AWS_SECRET\s*=\s*["\'][^"\']+["\']',
        r'STRIPE_SECRET\s*=\s*["\'][^"\']+["\']',
        r'API_KEY\s*=\s*["\'][^"\']+["\']',
        r'PASSWORD\s*=\s*["\'][^"\']+["\']',
    ]
    
    # Directories to exclude
    exclude_dirs = {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}
    
    for root, dirs, files in os.walk('.'):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        
        for file in files:
            if file.endswith(('.py', '.js', '.jsx', '.ts', '.tsx', '.env', '.config')):
                file_path = Path(root) / file
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        for i, pattern in enumerate(patterns):
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                secrets_found.append({
                                    'file': str(file_path),
                                    'pattern': i,
                                    'match': match.group()[:50] + '...' if len(match.group()) > 50 else match.group()
                                })
                except Exception as e:
                    continue
    
    return secrets_found

if __name__ == "__main__":
    secrets = scan_for_secrets()
    if secrets:
        print(f"Found {len(secrets)} potential secrets:")
        for secret in secrets:
            print(f"  {secret['file']}: {secret['match']}")
    else:
        print("No potential secrets found.")
EOF

# Run secrets scan
python ci/secrets_scan.py > ci/secrets_report.txt 2>&1
secrets_count=$(grep -c "Found" ci/secrets_report.txt 2>/dev/null || echo "0")
echo "   Potential secrets found: $secrets_count"

echo "✅ Security checks complete!"
echo "   Reports saved to ci/ directory"
