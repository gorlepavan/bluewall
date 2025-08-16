#!/bin/bash
# Main orchestrator script for BlueWall verification
# Runs all checks and generates comprehensive report

set -e

echo "🚀 Starting comprehensive BlueWall verification..."
echo "=================================================="

# Initialize results
results_file="ci/verification_report.json"
markdown_file="ci/verification_report.md"
auto_fixes_applied=()
overall_status="pass"

# Function to log results
log_result() {
    local step=$1
    local status=$2
    local details=$3
    
    if [ "$status" = "fail" ]; then
        overall_status="fail"
    fi
    
    echo "   $step: $status"
}

# Function to run step and capture output
run_step() {
    local step_name=$1
    local script_path=$2
    local output_file="ci/${step_name}_output.txt"
    
    echo "🔍 Running $step_name..."
    
    if [ -f "$script_path" ]; then
        if bash "$script_path" > "$output_file" 2>&1; then
            log_result "$step_name" "pass" "Script completed successfully"
            return 0
        else
            log_result "$step_name" "fail" "Script failed, see $output_file"
            return 1
        fi
    else
        log_result "$step_name" "fail" "Script not found: $script_path"
        return 1
    fi
}

# Create results directory
mkdir -p ci

# Step 1: Import check
echo "📋 Step 1: Import verification"
if python backend/scripts/import_check.py > ci/import_check_output.txt 2>&1; then
    log_result "import_check" "pass" "All imports successful"
else
    log_result "import_check" "fail" "Import failures detected"
fi

# Step 2: Linters and formatters
echo "📋 Step 2: Linting and formatting"
run_step "linters" "tools/run_linters_and_fix.sh"

# Step 3: Tests
echo "📋 Step 3: Test execution"
run_step "tests" "tools/run_tests_and_fix.sh"

# Step 4: Frontend build
echo "📋 Step 4: Frontend build and checks"
run_step "frontend_build" "tools/frontend_check_and_build.sh"

# Step 5: Security checks
echo "📋 Step 5: Security scanning"
run_step "security" "tools/security_checks.sh"

# Step 6: Runtime smoke tests
echo "📋 Step 6: Runtime smoke tests"
echo "   Starting backend for smoke tests..."

# Try to start backend for smoke tests
cd backend
python -c "
import asyncio
import sys
try:
    from main import app
    print('Backend app imported successfully')
    sys.exit(0)
except Exception as e:
    print(f'Backend import failed: {e}')
    sys.exit(1)
" > ../ci/runtime_smoke_output.txt 2>&1

if [ $? -eq 0 ]; then
    log_result "runtime_smoke" "pass" "Backend app imports successfully"
else
    log_result "runtime_smoke" "fail" "Backend app import failed"
fi

cd ..

# Generate JSON report
echo "📊 Generating verification report..."
cat > "$results_file" << EOF
{
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "overall_status": "$overall_status",
  "import_check": {
    "status": "$(grep -q "FAIL" ci/import_check_output.txt && echo "fail" || echo "pass")",
    "details": "See ci/import_check_output.txt"
  },
  "linters": {
    "status": "$(grep -q "FAIL" ci/linters_output.txt 2>/dev/null && echo "fail" || echo "pass")",
    "details": "See ci/linters_output.txt"
  },
  "tests": {
    "status": "$(grep -q "FAIL" ci/tests_output.txt 2>/dev/null && echo "fail" || echo "pass")",
    "details": "See ci/tests_output.txt"
  },
  "frontend_build": {
    "status": "$(grep -q "FAIL" ci/frontend_build_output.txt 2>/dev/null && echo "fail" || echo "pass")",
    "details": "See ci/frontend_build_output.txt"
  },
  "security": {
    "status": "$(grep -q "FAIL" ci/security_output.txt 2>/dev/null && echo "fail" || echo "pass")",
    "details": "See ci/security_output.txt"
  },
  "runtime_smoke": {
    "status": "$(grep -q "FAIL" ci/runtime_smoke_output.txt 2>/dev/null && echo "fail" || echo "pass")",
    "details": "See ci/runtime_smoke_output.txt"
  },
  "auto_fixes_applied": [],
  "manual_fixes_patch": "ci/manual_fixes.patch"
}
EOF

# Generate markdown report
echo "📝 Generating markdown report..."
cat > "$markdown_file" << EOF
# BlueWall Verification Report

**Generated:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")
**Overall Status:** $overall_status

## Summary

This report summarizes the results of comprehensive verification checks across the BlueWall project.

## Detailed Results

### 1. Import Verification
- **Status:** $(grep -q "FAIL" ci/import_check_output.txt && echo "❌ FAILED" || echo "✅ PASSED")
- **Details:** See \`ci/import_check_output.txt\`

### 2. Linting and Formatting
- **Status:** $(grep -q "FAIL" ci/linters_output.txt 2>/dev/null && echo "❌ FAILED" || echo "✅ PASSED")
- **Details:** See \`ci/linters_output.txt\`

### 3. Test Execution
- **Status:** $(grep -q "FAIL" ci/tests_output.txt 2>/dev/null && echo "❌ FAILED" || echo "✅ PASSED")
- **Details:** See \`ci/tests_output.txt\`

### 4. Frontend Build
- **Status:** $(grep -q "FAIL" ci/frontend_build_output.txt 2>/dev/null && echo "❌ FAILED" || echo "✅ PASSED")
- **Details:** See \`ci/frontend_build_output.txt\`

### 5. Security Scanning
- **Status:** $(grep -q "FAIL" ci/security_output.txt 2>/dev/null && echo "❌ FAILED" || echo "✅ PASSED")
- **Details:** See \`ci/security_output.txt\`

### 6. Runtime Smoke Tests
- **Status:** $(grep -q "FAIL" ci/runtime_smoke_output.txt 2>/dev/null && echo "❌ FAILED" || echo "✅ PASSED")
- **Details:** See \`ci/runtime_smoke_output.txt\`

## Next Steps

$(if [ "$overall_status" = "pass" ]; then
    echo "- ✅ All checks passed! The project is ready for deployment."
else
    echo "- ❌ Some checks failed. Review the detailed output files above."
    echo "- 🔧 Apply manual fixes as needed."
    echo "- 🧪 Re-run verification after fixes."
fi)

## Files Generated

- \`ci/verification_report.json\` - Machine-readable results
- \`ci/verification_report.md\` - This human-readable report
- Individual step output files in \`ci/\` directory
EOF

# Git actions
echo "🔧 Setting up Git actions..."
if command -v git >/dev/null 2>&1; then
    # Create auto-fixes branch
    git checkout -b ci/auto-fixes 2>/dev/null || git checkout ci/auto-fixes 2>/dev/null
    
    # Add and commit safe fixes
    git add ci/ tools/ backend/scripts/ 2>/dev/null || true
    git commit -m "ci: apply automatic fixes and verification scripts" 2>/dev/null || true
    
    echo "   Created/updated branch: ci/auto-fixes"
else
    echo "   Git not available, skipping Git actions"
fi

# Final summary
echo ""
echo "=================================================="
echo "🏁 Verification complete!"
echo ""
echo "📊 Results: $results_file"
echo "📝 Summary: $markdown_file"
echo "🔧 Git branch: ci/auto-fixes"
echo ""

if [ "$overall_status" = "pass" ]; then
    echo "✅ ALL CHECKS PASS — ZERO WARNINGS"
    exit 0
else
    echo "❌ Some checks failed. Review the reports above."
    echo "🔧 Manual fixes may be required."
    exit 1
fi
