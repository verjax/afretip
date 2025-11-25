#!/bin/bash
##############################################################################
# AFRETIP Start Script
# Automated First Response Threat Intelligence Pipeline Launcher
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
    echo -e "${BLUE}🚀 $1${NC}"
    echo "=============================================================================="
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
        print_error "Please either:"
        print_error "  • Install AFRETIP using: sudo ./scripts/install.sh"
        print_error "  • Or run from development directory with setup.py"
        exit 1
    fi
}

# Check configuration file
check_configuration() {
    print_status "Checking configuration..."

    if [ ! -f "$CONFIG_PATH" ]; then
        print_error "Configuration file not found: $CONFIG_PATH"

        if [ "$ENVIRONMENT" = "development" ]; then
            # Check for config template in development
            if [ -f "config/config.yaml.example" ]; then
                print_status "Found config template, copying..."
                cp config/config.yaml.example config/config.yaml
                print_warning "Please edit config/config.yaml with your settings before starting"
                exit 1
            else
                print_error "No configuration template found"
                print_error "Create config/config.yaml or run: sudo ./scripts/install.sh"
                exit 1
            fi
        else
            print_error "Production configuration missing"
            print_error "Reinstall AFRETIP: sudo ./scripts/install.sh"
            exit 1
        fi
    fi

    print_success "Configuration found: $CONFIG_PATH"
}

# Check dependencies and installation
check_dependencies() {
    print_status "Checking dependencies..."

    # Check Python version
    PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | cut -d' ' -f2)
    print_status "Python version: $PYTHON_VERSION"

    # Check if AFRETIP package is available
    if ! $PYTHON_CMD -c "import threat_intel; print('AFRETIP package available')" 2>/dev/null; then
        print_error "AFRETIP package not installed"

        if [ "$ENVIRONMENT" = "development" ]; then
            print_error "Install development dependencies:"
            print_error "  pip3 install -r requirements.txt"
            print_error "  pip3 install -e ."
        else
            print_error "Production installation broken, reinstall:"
            print_error "  sudo ./scripts/install.sh"
        fi
        exit 1
    fi

    print_success "AFRETIP package available"

    # Test CLI accessibility
    if [ "$ENVIRONMENT" = "production" ]; then
        if ! command -v threat-intel &>/dev/null; then
            print_warning "threat-intel command not in PATH, using direct python"
            CLI_CMD="/opt/afretip/venv/bin/python -m threat_intel.cli"
        fi
    fi

    print_success "Dependencies verified"
}

# Check system requirements
check_system() {
    print_status "Checking system requirements..."

    # Check if running as appropriate user
    if [ "$ENVIRONMENT" = "production" ]; then
        CURRENT_USER=$(whoami)
        if [ "$CURRENT_USER" = "root" ]; then
            print_warning "Running as root - switching to afretip user recommended"
            print_status "To run as afretip user: sudo -u afretip $0"
        elif [ "$CURRENT_USER" != "afretip" ]; then
            print_warning "Running as $CURRENT_USER instead of afretip user"
            print_status "To run as afretip user: sudo -u afretip $0"
        else
            print_success "Running as afretip user"
        fi
    else
        print_status "Development mode - user: $(whoami)"
    fi

    # Check Wazuh availability
    if [ -d "/var/ossec" ]; then
        print_success "Wazuh installation detected"

        # Check socket access
        if [ -S "/var/ossec/queue/sockets/queue" ]; then
            print_success "Wazuh socket available"
        else
            print_warning "Wazuh socket not accessible - will use file monitoring"
        fi

        # Check archives file
        if [ -f "/var/ossec/logs/archives/archives.json" ]; then
            print_success "Wazuh archives file accessible"
        else
            print_warning "Wazuh archives file not accessible"
        fi
    else
        print_warning "Wazuh not detected - ensure it's installed for production use"
    fi

    # Check data directories (production only)
    if [ "$ENVIRONMENT" = "production" ]; then
        for dir in "/var/lib/afretip" "/var/log/afretip"; do
            if [ -d "$dir" ] && [ -w "$dir" ]; then
                print_success "Data directory accessible: $dir"
            else
                print_error "Data directory not accessible: $dir"
                exit 1
            fi
        done
    fi

    print_success "System requirements verified"
}

# Perform pre-flight checks
preflight_check() {
    print_status "Performing pre-flight configuration check..."

    # Use CLI to validate configuration
    if $CLI_CMD dry-run --config "$CONFIG_PATH" >/dev/null 2>&1; then
        print_success "Configuration validation passed"
    else
        print_error "Configuration validation failed"
        print_status "Running detailed validation..."
        $CLI_CMD dry-run --config "$CONFIG_PATH"
        exit 1
    fi

    # Check component status
    print_status "Checking component status..."
    $CLI_CMD status --config "$CONFIG_PATH"

    print_success "Pre-flight checks completed"
}

# Show startup banner
show_banner() {
    print_header "AFRETIP - Automated First Response Threat Intelligence Pipeline"
    echo ""
    echo "Environment: $ENVIRONMENT"
    echo "Home Directory: $AFRETIP_HOME"
    echo "Configuration: $CONFIG_PATH"
    echo "Python: $PYTHON_CMD"
    echo "CLI Command: $CLI_CMD"
    echo ""
    echo "🛡️ Threat Intelligence Pipeline Starting..."
    echo ""
}

# Handle shutdown gracefully
cleanup() {
    echo ""
    print_status "Shutdown signal received..."
    print_status "Stopping AFRETIP gracefully..."

    # Analytics will auto-export on shutdown
    if [ "$ENVIRONMENT" = "production" ]; then
        print_status "Analytics data will be automatically exported"
    fi

    print_success "AFRETIP stopped"
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Parse command line options
FORCE_START=false
BACKGROUND=false
ANALYTICS_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --force)
            FORCE_START=true
            shift
            ;;
        --background|-b)
            BACKGROUND=true
            shift
            ;;
        --analytics-only)
            ANALYTICS_ONLY=true
            shift
            ;;
        --config)
            CUSTOM_CONFIG="$2"
            shift 2
            ;;
        --help|-h)
            echo "AFRETIP Start Script"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --force           Skip pre-flight checks"
            echo "  --background, -b  Run in background"
            echo "  --analytics-only  Start with analytics collection only"
            echo "  --config PATH     Use custom configuration file"
            echo "  --help, -h        Show this help"
            echo ""
            echo "Examples:"
            echo "  $0                    # Normal start with checks"
            echo "  $0 --force           # Skip validation and start"
            echo "  $0 --background      # Start in background"
            echo "  $0 --config custom.yaml  # Use custom config"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            print_status "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Use custom config if provided
if [ -n "$CUSTOM_CONFIG" ]; then
    CONFIG_PATH="$CUSTOM_CONFIG"
    print_status "Using custom configuration: $CONFIG_PATH"
fi

# Main execution
main() {
    print_header "AFRETIP Startup Process"

    # Detection and validation
    detect_environment
    check_configuration
    check_dependencies
    check_system

    # Pre-flight checks (unless --force)
    if [ "$FORCE_START" = false ]; then
        preflight_check
    else
        print_warning "Skipping pre-flight checks (--force mode)"
    fi

    # Show startup information
    show_banner

    # Prepare start command
    START_CMD="$CLI_CMD start --config $CONFIG_PATH"

    if [ "$ANALYTICS_ONLY" = true ]; then
        print_status "Starting in analytics-only mode..."
        # Add analytics-only flag if your CLI supports it
        # START_CMD="$START_CMD --analytics-only"
    fi

    # Start the pipeline
    if [ "$BACKGROUND" = true ]; then
        print_status "Starting AFRETIP in background..."
        nohup $START_CMD > /dev/null 2>&1 &
        PID=$!
        echo $PID > /tmp/afretip.pid
        print_success "AFRETIP started in background (PID: $PID)"
        print_status "To stop: kill $PID"
        print_status "To check status: $CLI_CMD status --config $CONFIG_PATH"
    else
        print_status "Starting AFRETIP in foreground..."
        print_status "Press Ctrl+C to stop gracefully"
        echo ""

        # Execute the start command
        exec $START_CMD
    fi
}

# Additional helper functions for different start modes

# Development mode with hot reload
dev_start() {
    print_status "Development mode startup..."

    # Check for development dependencies
    if ! $PYTHON_CMD -c "import watchdog" 2>/dev/null; then
        print_warning "Watchdog not installed - no hot reload"
        print_status "Install with: pip3 install watchdog"
    fi

    # Start with development settings
    export AFRETIP_DEV_MODE=1
    exec $START_CMD
}

# Production service start
service_start() {
    print_status "Service mode startup..."

    # Ensure running as afretip user
    if [ "$(whoami)" != "afretip" ]; then
        print_error "Service mode requires afretip user"
        exit 1
    fi

    # Start with production settings
    export AFRETIP_PRODUCTION_MODE=1
    exec $START_CMD
}

# Check for special modes
if [ "$ENVIRONMENT" = "development" ] && [ "$USER" != "afretip" ]; then
    # Development mode
    if [ -f ".dev-mode" ] || [ "$AFRETIP_DEV_MODE" = "1" ]; then
        dev_start
    fi
fi

if [ "$ENVIRONMENT" = "production" ] && [ "$(whoami)" = "afretip" ]; then
    # Production service mode
    if [ "$AFRETIP_SERVICE_MODE" = "1" ]; then
        service_start
    fi
fi

# Run main function
main "$@"
