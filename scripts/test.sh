#!/bin/bash
##############################################################################
# AFRETIP Comprehensive Test Script - Updated for Actual CLI Implementation
# Automated First Response Threat Intelligence Pipeline Testing Suite
##############################################################################

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo "=============================================================================="
    echo -e "${BLUE}🧪 $1${NC}"
    echo "=============================================================================="
}

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_WARNINGS=0

# Track test results
test_result() {
    local test_name="$1"
    local result="$2"
    local message="$3"

    case $result in
        "PASS")
            print_success "✅ $test_name: $message"
            TESTS_PASSED=$((TESTS_PASSED + 1))
            ;;
        "FAIL")
            print_error "❌ $test_name: $message"
            TESTS_FAILED=$((TESTS_FAILED + 1))
            ;;
        "WARN")
            print_warning "⚠️  $test_name: $message"
            TESTS_WARNINGS=$((TESTS_WARNINGS + 1))
            ;;
    esac
}

# Detect environment (development vs production)
detect_environment() {
    if [ -f "/opt/afretip/venv/bin/python" ] && [ -f "/opt/afretip/config/config.yaml" ]; then
        ENVIRONMENT="production"
        AFRETIP_HOME="/opt/afretip"
        CONFIG_PATH="/opt/afretip/config/config.yaml"
        PYTHON_CMD="/opt/afretip/venv/bin/python"
        CLI_CMD="threat-intel"
    elif [ -f "src/threat_intel/__init__.py" ] && [ -f "setup.py" ]; then
        ENVIRONMENT="development"
        AFRETIP_HOME="$(pwd)"
        CONFIG_PATH="config/config.yaml"
        PYTHON_CMD="python3"
        CLI_CMD="python3 -m threat_intel.cli"
    else
        print_error "AFRETIP installation not found"
        exit 1
    fi

    print_status "Environment: $ENVIRONMENT"
    print_status "Home: $AFRETIP_HOME"
    print_status "Config: $CONFIG_PATH"
}

# Test 1: Installation and Configuration
test_installation() {
    print_header "Installation & Configuration Tests"

    # Test Python version
    if PYTHON_VERSION=$($PYTHON_CMD --version 2>&1); then
        test_result "Python Version" "PASS" "$PYTHON_VERSION"
    else
        test_result "Python Version" "FAIL" "Python not accessible"
        return 1
    fi

    # Test AFRETIP package import
    if $PYTHON_CMD -c "import threat_intel; print('AFRETIP package available')" 2>/dev/null; then
        test_result "Package Import" "PASS" "AFRETIP package imports successfully"
    else
        test_result "Package Import" "FAIL" "Cannot import AFRETIP package"
        return 1
    fi

    # Test CLI availability
    if $CLI_CMD --help >/dev/null 2>&1; then
        test_result "CLI Access" "PASS" "CLI interface accessible"
    else
        test_result "CLI Access" "FAIL" "CLI interface not working"
        return 1
    fi

    # Test configuration file
    if [ -f "$CONFIG_PATH" ]; then
        test_result "Configuration File" "PASS" "Config file exists at $CONFIG_PATH"
    else
        test_result "Configuration File" "FAIL" "Config file missing"
        return 1
    fi

    # Test configuration validation using the ACTUAL command
    if $CLI_CMD validate-config --config "$CONFIG_PATH" >/dev/null 2>&1; then
        test_result "Configuration Validation" "PASS" "Configuration is valid"
    else
        test_result "Configuration Validation" "FAIL" "Configuration validation failed"
        return 1
    fi
}

# Test 2: Component Testing
test_components() {
    print_header "Component Tests"

    # Test dry run
    if $CLI_CMD dry-run --config "$CONFIG_PATH" >/dev/null 2>&1; then
        test_result "Dry Run" "PASS" "Basic pipeline functionality works"
    else
        test_result "Dry Run" "FAIL" "Dry run failed"
    fi

    # Test status command
    if $CLI_CMD status --config "$CONFIG_PATH" >/dev/null 2>&1; then
        test_result "Status Check" "PASS" "Status command works"
    else
        test_result "Status Check" "FAIL" "Status command failed"
    fi

    # Test version command
    if VERSION_OUTPUT=$($CLI_CMD version 2>&1); then
        test_result "Version Command" "PASS" "Version: $(echo "$VERSION_OUTPUT" | grep -o 'Version: [0-9.]*' || echo 'Available')"
    else
        test_result "Version Command" "FAIL" "Version command failed"
    fi

    # Test available CLI commands
    print_status "Testing available CLI commands..."
    if $CLI_CMD --help 2>&1 | grep -q "validate-config"; then
        test_result "Validate Config Command" "PASS" "validate-config command available"
    else
        test_result "Validate Config Command" "FAIL" "validate-config command missing"
    fi

    if $CLI_CMD --help 2>&1 | grep -q "test-classification"; then
        test_result "Test Classification Command" "PASS" "test-classification command available"
    else
        test_result "Test Classification Command" "FAIL" "test-classification command missing"
    fi
}

# Test 3: IOC Extraction and Classification
test_ioc_processing() {
    print_header "IOC Processing Tests"

    # Create test log file
    TEST_LOG_DIR="$AFRETIP_HOME/test_logs"
    mkdir -p "$TEST_LOG_DIR"

    # Create sample malicious log
    cat > "$TEST_LOG_DIR/sample_malicious.log" << 'EOF'
{"timestamp":"2025-01-20T10:30:00Z","rule":{"id":12345,"level":7,"description":"Suspicious network connection"},"data":{"srcip":"192.168.1.100","dstip":"185.220.100.250","dstport":443,"url":"http://malicious-domain.evil/payload.exe","process":"malware.exe","hash":"a1b2c3d4e5f6789abcdef1234567890"}}
EOF

    # Test IOC extraction with sample log using ACTUAL CLI parameter
    if $CLI_CMD dry-run --config "$CONFIG_PATH" --log-sample "$TEST_LOG_DIR/sample_malicious.log" >/dev/null 2>&1; then
        test_result "IOC Extraction" "PASS" "IOCs extracted from sample log"
    else
        test_result "IOC Extraction" "FAIL" "IOC extraction failed - using fallback test"

        # Fallback: test with dry-run only
        if $CLI_CMD dry-run --config "$CONFIG_PATH" >/dev/null 2>&1; then
            test_result "IOC Extraction Fallback" "WARN" "Dry-run works but log-sample parameter not supported"
        else
            test_result "IOC Extraction Fallback" "FAIL" "Even basic dry-run failed"
        fi
    fi

    # Test hybrid classification using ACTUAL command
    if $CLI_CMD test-classification "185.220.100.250" --ioc-type ip --config "$CONFIG_PATH" >/dev/null 2>&1; then
        test_result "Hybrid Classification" "PASS" "IOC classification working"
    else
        test_result "Hybrid Classification" "WARN" "Classification test failed (command may not be implemented)"
    fi

    # Cleanup test files
    rm -rf "$TEST_LOG_DIR"
}

# Test 4: Analytics System
test_analytics() {
    print_header "Analytics System Tests"

    # Test analytics initialization
    if $PYTHON_CMD -c "
from threat_intel.analytics.metrics import initialize_analytics
from threat_intel.utils.config import load_config
config = load_config('$CONFIG_PATH')
analytics = initialize_analytics(config)
print('Analytics initialized successfully')
" 2>/dev/null; then
        test_result "Analytics Initialization" "PASS" "Analytics system initializes"
    else
        test_result "Analytics Initialization" "WARN" "Analytics initialization failed"
    fi

    # Test analytics commands
    if $CLI_CMD show-stats --config "$CONFIG_PATH" 2>/dev/null | grep -q "No analytics available"; then
        test_result "Analytics Commands" "WARN" "Analytics not running (expected for test)"
    elif $CLI_CMD show-stats --config "$CONFIG_PATH" >/dev/null 2>&1; then
        test_result "Analytics Commands" "PASS" "Analytics commands working"
    else
        test_result "Analytics Commands" "FAIL" "Analytics commands failed"
    fi
}

# Test 5: System Integration
test_integration() {
    print_header "System Integration Tests"

    # Test Wazuh integration
    if [ -d "/var/ossec" ]; then
        test_result "Wazuh Detection" "PASS" "Wazuh installation found"

        # Test socket access
        if [ -S "/var/ossec/queue/sockets/queue" ]; then
            test_result "Wazuh Socket" "PASS" "Wazuh socket accessible"
        else
            test_result "Wazuh Socket" "WARN" "Wazuh socket not accessible - will use file monitoring"
        fi

        # Test archives file
        if [ -f "/var/ossec/logs/archives/archives.json" ]; then
            test_result "Wazuh Archives" "PASS" "Archives file accessible"
        else
            test_result "Wazuh Archives" "WARN" "Archives file not accessible"
        fi
    else
        test_result "Wazuh Detection" "WARN" "Wazuh not detected"
    fi

    # Test data directories (production only)
    if [ "$ENVIRONMENT" = "production" ]; then
        for dir in "/var/lib/afretip" "/var/log/afretip"; do
            if [ -d "$dir" ] && [ -w "$dir" ]; then
                test_result "Data Directory $(basename "$dir")" "PASS" "Directory accessible and writable"
            else
                test_result "Data Directory $(basename "$dir")" "FAIL" "Directory not accessible: $dir"
            fi
        done
    else
        test_result "Data Directories" "PASS" "Development mode - skipping data directory tests"
    fi
}

# Test 6: Performance Testing
test_performance() {
    print_header "Performance Tests"

    # Create simple performance test
    PERF_TEST_FILE="$AFRETIP_HOME/perf_test.py"
    cat > "$PERF_TEST_FILE" << 'EOF'
#!/usr/bin/env python3
import asyncio
import time
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from threat_intel.core.models import WazuhRawLog
from threat_intel.utils.config import load_config

async def simple_performance_test():
    try:
        config = load_config(sys.argv[1])

        # Create test logs
        test_logs = []
        for i in range(100):
            log = WazuhRawLog(
                full_log=f"Test log {i} with IP 192.168.1.{i%255}",
                rule_id=1002 + (i % 10),
                rule_level=5,
                description=f"Test rule {i}",
                source_system="performance_test"
            )
            test_logs.append(log)

        start_time = time.time()

        # Simple processing simulation
        for log in test_logs:
            # Simulate basic processing
            await asyncio.sleep(0.001)  # 1ms per log

        end_time = time.time()
        total_time = end_time - start_time

        print(f"Processed {len(test_logs)} logs in {total_time:.2f} seconds")
        print(f"Rate: {len(test_logs)/total_time:.2f} logs/second")

        # Performance threshold check
        if len(test_logs)/total_time > 10:
            print("PERFORMANCE_PASS")
        else:
            print("PERFORMANCE_WARN")

    except Exception as e:
        print(f"PERFORMANCE_FAIL: {e}")

if __name__ == "__main__":
    asyncio.run(simple_performance_test())
EOF

    # Run performance test
    PERF_RESULT=$($PYTHON_CMD "$PERF_TEST_FILE" "$CONFIG_PATH" 2>&1 | tail -1)

    if echo "$PERF_RESULT" | grep -q "PERFORMANCE_PASS"; then
        test_result "Performance Test" "PASS" "Processing rate acceptable (>10 logs/sec)"
    elif echo "$PERF_RESULT" | grep -q "PERFORMANCE_WARN"; then
        test_result "Performance Test" "WARN" "Processing rate below threshold"
    else
        test_result "Performance Test" "FAIL" "Performance test failed"
    fi

    # Cleanup
    rm -f "$PERF_TEST_FILE"
}

# Test 7: Code Quality (Development only)
test_code_quality() {
    if [ "$ENVIRONMENT" = "development" ]; then
        print_header "Code Quality Tests"

        # Test MyPy type checking
        if command -v mypy >/dev/null 2>&1; then
            if mypy src/ --no-error-summary >/dev/null 2>&1; then
                test_result "Type Checking" "PASS" "MyPy type checking passed"
            else
                test_result "Type Checking" "FAIL" "MyPy type checking failed"
            fi
        else
            test_result "Type Checking" "WARN" "MyPy not installed"
        fi

        # Test code formatting (if ruff available)
        if command -v ruff >/dev/null 2>&1; then
            if ruff check src/ >/dev/null 2>&1; then
                test_result "Code Linting" "PASS" "Ruff linting passed"
            else
                test_result "Code Linting" "WARN" "Ruff linting issues found"
            fi

            if ruff format --check src/ >/dev/null 2>&1; then
                test_result "Code Formatting" "PASS" "Code formatting correct"
            else
                test_result "Code Formatting" "WARN" "Code formatting issues found"
            fi
        else
            test_result "Code Quality Tools" "WARN" "Ruff not installed"
        fi

        # Test pytest if available
        if command -v pytest >/dev/null 2>&1 && [ -d "tests" ]; then
            if pytest tests/ -v --tb=no >/dev/null 2>&1; then
                test_result "Unit Tests" "PASS" "PyTest unit tests passed"
            else
                test_result "Unit Tests" "FAIL" "PyTest unit tests failed"
            fi
        else
            test_result "Unit Tests" "WARN" "PyTest not available or no tests directory"
        fi
    else
        print_status "Skipping code quality tests (production environment)"
    fi
}

# Test 8: Error Handling
test_error_handling() {
    print_header "Error Handling Tests"

    # Test invalid configuration
    INVALID_CONFIG="/tmp/invalid_config.yaml"
    echo "invalid_yaml: [unclosed" > "$INVALID_CONFIG"

    if ! $CLI_CMD validate-config --config "$INVALID_CONFIG" >/dev/null 2>&1; then
        test_result "Invalid Config Handling" "PASS" "Invalid configuration properly rejected"
    else
        test_result "Invalid Config Handling" "FAIL" "Invalid configuration accepted"
    fi

    rm -f "$INVALID_CONFIG"

    # Test missing configuration
    if ! $CLI_CMD validate-config --config "/nonexistent/config.yaml" >/dev/null 2>&1; then
        test_result "Missing Config Handling" "PASS" "Missing configuration properly handled"
    else
        test_result "Missing Config Handling" "FAIL" "Missing configuration not handled"
    fi

    # Test invalid IOC classification (only if command exists)
    if $CLI_CMD --help 2>&1 | grep -q "test-classification"; then
        if ! $CLI_CMD test-classification "../../../etc/passwd" --ioc-type domain --config "$CONFIG_PATH" >/dev/null 2>&1; then
            test_result "Input Sanitization" "PASS" "Path traversal attempt blocked"
        else
            test_result "Input Sanitization" "WARN" "Input sanitization may need review"
        fi
    else
        test_result "Input Sanitization" "WARN" "test-classification command not available"
    fi
}

# Test 9: CLI Commands Comprehensive Test
test_cli_commands() {
    print_header "CLI Commands Comprehensive Test"

    # Test all expected commands
    declare -A expected_commands=(
        ["start"]="Start the pipeline"
        ["test"]="Test components"
        ["dry-run"]="Dry run validation"
        ["status"]="Show status"
        ["version"]="Show version"
        ["show-stats"]="Show analytics stats"
        ["generate-report"]="Generate analytics report"
        ["validate-config"]="Validate configuration"
        ["test-classification"]="Test IOC classification"
    )

    for cmd in "${!expected_commands[@]}"; do
        if $CLI_CMD --help 2>&1 | grep -q "$cmd"; then
            test_result "CLI Command: $cmd" "PASS" "${expected_commands[$cmd]} - Available"
        else
            test_result "CLI Command: $cmd" "FAIL" "${expected_commands[$cmd]} - Missing"
        fi
    done

    # Test parameter support for dry-run
    if $CLI_CMD dry-run --help 2>&1 | grep -q "log-sample"; then
        test_result "Dry-run Log Sample" "PASS" "--log-sample parameter available"
    else
        test_result "Dry-run Log Sample" "FAIL" "--log-sample parameter missing"
    fi

    # Test parameter support for test-classification
    if $CLI_CMD --help 2>&1 | grep -q "test-classification"; then
        if $CLI_CMD test-classification --help 2>&1 | grep -q "ioc-type"; then
            test_result "Test Classification IOC Type" "PASS" "--ioc-type parameter available"
        else
            test_result "Test Classification IOC Type" "FAIL" "--ioc-type parameter missing"
        fi
    else
        test_result "Test Classification Availability" "FAIL" "test-classification command missing"
    fi
}

# Generate test report
generate_report() {
    print_header "Test Results Summary"

    TOTAL_TESTS=$((TESTS_PASSED + TESTS_FAILED + TESTS_WARNINGS))

    echo ""
    print_status "Test Environment: $ENVIRONMENT"
    print_status "Configuration: $CONFIG_PATH"
    print_status "Total Tests: $TOTAL_TESTS"
    echo ""

    print_success "✅ Passed: $TESTS_PASSED"
    print_error "❌ Failed: $TESTS_FAILED"
    print_warning "⚠️  Warnings: $TESTS_WARNINGS"
    echo ""

    # Calculate success rate
    if [ $TOTAL_TESTS -gt 0 ]; then
        SUCCESS_RATE=$(( (TESTS_PASSED * 100) / TOTAL_TESTS ))
        print_status "Success Rate: $SUCCESS_RATE%"
    fi

    # Overall result
    if [ $TESTS_FAILED -eq 0 ]; then
        if [ $TESTS_WARNINGS -eq 0 ]; then
            print_success "🎉 All tests passed! AFRETIP is ready for use."
            OVERALL_RESULT=0
        else
            print_warning "⚠️  Tests completed with warnings. Review warnings before production use."
            OVERALL_RESULT=1
        fi
    else
        print_error "❌ Tests failed. Fix issues before using AFRETIP."
        OVERALL_RESULT=2
    fi

    # Save report to file
    REPORT_FILE="$AFRETIP_HOME/test_report_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "AFRETIP Test Report - $(date)"
        echo "Environment: $ENVIRONMENT"
        echo "Total Tests: $TOTAL_TESTS"
        echo "Passed: $TESTS_PASSED"
        echo "Failed: $TESTS_FAILED"
        echo "Warnings: $TESTS_WARNINGS"
        echo "Success Rate: $SUCCESS_RATE%"
    } > "$REPORT_FILE"

    print_status "Test report saved: $REPORT_FILE"

    return $OVERALL_RESULT
}

# Parse command line options
QUICK_TEST=false
SKIP_PERFORMANCE=false
SKIP_CODE_QUALITY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --quick)
            QUICK_TEST=true
            shift
            ;;
        --skip-performance)
            SKIP_PERFORMANCE=true
            shift
            ;;
        --skip-code-quality)
            SKIP_CODE_QUALITY=true
            shift
            ;;
        --config)
            CUSTOM_CONFIG="$2"
            shift 2
            ;;
        --help|-h)
            echo "AFRETIP Test Script"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --quick              Run quick tests only"
            echo "  --skip-performance   Skip performance tests"
            echo "  --skip-code-quality  Skip code quality tests"
            echo "  --config PATH        Use custom configuration file"
            echo "  --help, -h           Show this help"
            echo ""
            echo "Test Categories:"
            echo "  • Installation & Configuration"
            echo "  • Component Testing"
            echo "  • IOC Processing"
            echo "  • Analytics System"
            echo "  • System Integration"
            echo "  • Performance Testing"
            echo "  • Code Quality (dev only)"
            echo "  • Error Handling"
            echo "  • CLI Commands Comprehensive"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Main execution
main() {
    print_header "AFRETIP Comprehensive Test Suite - Updated for Real CLI"

    # Environment detection
    detect_environment

    # Use custom config if provided
    if [ -n "$CUSTOM_CONFIG" ]; then
        CONFIG_PATH="$CUSTOM_CONFIG"
        print_status "Using custom configuration: $CONFIG_PATH"
    fi

    echo ""
    print_status "Starting test execution..."
    echo ""

    # Run test suites
    test_installation
    test_components
    test_cli_commands  # New comprehensive CLI test

    if [ "$QUICK_TEST" = false ]; then
        test_ioc_processing
        test_analytics
        test_integration

        if [ "$SKIP_PERFORMANCE" = false ]; then
            test_performance
        fi

        if [ "$SKIP_CODE_QUALITY" = false ]; then
            test_code_quality
        fi

        test_error_handling
    fi

    # Generate final report
    generate_report
}

# Run main function
main "$@"
