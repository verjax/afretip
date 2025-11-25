#!/bin/bash
# AFRETIP Complete Installation and Setup Script

set -e  # Exit on any error

echo "🚀 AFRETIP (Automated First Response Threat Intelligence Pipeline) Setup"
echo "=================================================================="

# Get the absolute path of the script directory - works from anywhere
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(dirname "$SCRIPT_DIR")"  # Go up one level from scripts/

# Define all paths as absolute based on script location
CONFIG_DIR="${SOURCE_DIR}/config"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"
CONFIG_FILE_ROOT="${SOURCE_DIR}/config.yaml"
REQUIREMENTS_FILE="${SOURCE_DIR}/requirements.txt"
SETUP_PY="${SOURCE_DIR}/setup.py"
PYPROJECT_TOML="${SOURCE_DIR}/pyproject.toml"
SRC_DIR="${SOURCE_DIR}/src"

# Configuration
AFRETIP_USER="afretip"
AFRETIP_GROUP="afretip"
AFRETIP_HOME="/opt/afretip"
AFRETIP_LOGS="/var/log/afretip"
AFRETIP_DATA="/var/lib/afretip"
AFRETIP_REPO="https://git.mif.vu.lt/micac/2025/afretip.git"

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

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Check if Wazuh is installed
check_wazuh() {
    print_status "Checking Wazuh installation..."

    if [ ! -d "/var/ossec" ]; then
        print_error "Wazuh not found. Please install Wazuh first."
        exit 1
    fi

    # Check for the correct socket path (analysis, not queue)
    if [ ! -S "/var/ossec/queue/sockets/queue" ]; then
        print_warning "Wazuh analysis socket not found. Pipeline will use file monitoring."
    else
        print_success "Wazuh analysis socket found"
    fi

    if ! id "wazuh" &>/dev/null; then
        print_error "Wazuh user 'wazuh' not found"
        exit 1
    fi

    print_success "Wazuh installation verified"
}

# Check system dependencies
check_dependencies() {
    print_status "Checking system dependencies..."

    # Check for python3
    if ! command -v python3 &> /dev/null; then
        print_error "Python3 not found. Please install python3 first."
        exit 1
    fi

    # Check for pip3 (optional now with venv approach)
    if ! command -v pip3 &> /dev/null; then
        print_warning "pip3 not found. Will attempt to use python3 -m pip"
    fi

    # Check for git (optional since we support local files)
    if ! command -v git &> /dev/null; then
        print_warning "Git not found. Local source code must be available."
    fi

    print_success "System dependencies verified"
}

# Create AFRETIP system user
create_user() {
    print_status "Creating AFRETIP system user..."

    # Create group if it doesn't exist
    if ! getent group "$AFRETIP_GROUP" &>/dev/null; then
        groupadd --system "$AFRETIP_GROUP"
        print_success "Created group: $AFRETIP_GROUP"
    else
        print_status "Group $AFRETIP_GROUP already exists"
    fi

    # Create user if it doesn't exist
    if ! id "$AFRETIP_USER" &>/dev/null; then
        useradd --system \
            --gid "$AFRETIP_GROUP" \
            --home-dir "$AFRETIP_HOME" \
            --shell /bin/bash \
            --comment "AFRETIP Service User" \
            "$AFRETIP_USER"
        print_success "Created user: $AFRETIP_USER"
    else
        print_status "User $AFRETIP_USER already exists"
    fi

    # Add afretip user to wazuh group for socket access
    usermod -a -G wazuh "$AFRETIP_USER"
    print_success "Added $AFRETIP_USER to wazuh group"
}

# Create directory structure
create_directories() {
    print_status "Creating directory structure..."

    # Create home directory
    mkdir -p "$AFRETIP_HOME"
    chown "$AFRETIP_USER:$AFRETIP_GROUP" "$AFRETIP_HOME"
    chmod 755 "$AFRETIP_HOME"

    # Create logs directory
    mkdir -p "$AFRETIP_LOGS"
    chown "$AFRETIP_USER:$AFRETIP_GROUP" "$AFRETIP_LOGS"
    chmod 750 "$AFRETIP_LOGS"

    # Create data directory
    mkdir -p "$AFRETIP_DATA"
    chown "$AFRETIP_USER:$AFRETIP_GROUP" "$AFRETIP_DATA"
    chmod 750 "$AFRETIP_DATA"

    # Create subdirectories
    mkdir -p "$AFRETIP_DATA"/{raw_logs,extracted_iocs,suspicious_findings,siem_output,stix_output,analytics,research_exports}
    chown -R "$AFRETIP_USER:$AFRETIP_GROUP" "$AFRETIP_DATA"

    # Create config directory
    mkdir -p "$AFRETIP_HOME/config"
    chown "$AFRETIP_USER:$AFRETIP_GROUP" "$AFRETIP_HOME/config"

    print_success "Directory structure created"
}

# Clone AFRETIP repository or copy local files
clone_repository() {
    print_status "Setting up AFRETIP source code..."

    # Remove existing installation if present
    if [ -d "$AFRETIP_HOME/src" ]; then
        print_status "Removing existing installation..."
        rm -rf "$AFRETIP_HOME/src" "$AFRETIP_HOME/setup.py" "$AFRETIP_HOME/requirements.txt"
    fi

    print_status "Script location: $SCRIPT_DIR"
    print_status "Source directory: $SOURCE_DIR"

    # Check if we have local source code available
    if [ -f "$SETUP_PY" ] && [ -d "$SRC_DIR" ] && [ -f "$REQUIREMENTS_FILE" ]; then
        print_status "Found local source code, using uploaded files..."

        # Copy source code from local directory using absolute paths
        cp -r "$SOURCE_DIR"/* "$AFRETIP_HOME/"
        chown -R "$AFRETIP_USER:$AFRETIP_GROUP" "$AFRETIP_HOME"

        print_success "Local code copied successfully"

    else
        print_status "Local source code not found, attempting git clone..."

        # Check if git is available
        if ! command -v git &> /dev/null; then
            print_error "Git not found and local source code not available"
            print_error "Please either:"
            print_error "1. Install git: sudo apt install git"
            print_error "2. Upload complete AFRETIP source code to this directory"
            exit 1
        fi

        # Check network connectivity to git repository
        if ! curl -s --head "$AFRETIP_REPO" > /dev/null 2>&1; then
            print_error "Cannot reach git repository and local source code not available"
            print_error "Please upload complete AFRETIP source code to this directory"
            exit 1
        fi

        # Clone repository to temporary location
        TEMP_DIR=$(mktemp -d)
        if git clone "$AFRETIP_REPO" "$TEMP_DIR"; then
            # Copy source code to AFRETIP_HOME
            cp -r "$TEMP_DIR"/* "$AFRETIP_HOME/"
            chown -R "$AFRETIP_USER:$AFRETIP_GROUP" "$AFRETIP_HOME"

            # Cleanup
            rm -rf "$TEMP_DIR"

            print_success "Repository cloned successfully"
        else
            print_error "Git clone failed"
            print_error "Please upload complete AFRETIP source code to this directory"
            exit 1
        fi
    fi

    # Verify essential files are now present
    if [ ! -f "$AFRETIP_HOME/setup.py" ] || [ ! -d "$AFRETIP_HOME/src" ]; then
        print_error "Essential files missing after source setup"
        print_error "Required: setup.py, src/ directory, requirements.txt"
        exit 1
    fi

    print_success "Source code setup completed"
}

# Install AFRETIP Python package in virtual environment
install_package() {
    print_status "Installing AFRETIP Python package in virtual environment..."

    # Ensure python3-venv is installed
    if ! python3 -m venv --help &>/dev/null; then
        print_status "Installing python3-venv package..."
        apt update
        apt install -y python3-venv python3-full
    fi

    # Change to AFRETIP_HOME using absolute path
    cd "$AFRETIP_HOME"

    # Remove any existing corrupted venv
    if [ -d "venv" ]; then
        print_status "Removing existing virtual environment..."
        rm -rf venv
    fi

    # Create virtual environment as root with upgrade-deps
    if python3 -m venv --upgrade-deps venv; then
        print_success "Virtual environment created with upgraded dependencies"
    else
        print_error "Failed to create virtual environment"
        exit 1
    fi

    # Change ownership to afretip user
    chown -R "$AFRETIP_USER:$AFRETIP_GROUP" venv

    # Test the virtual environment works
    if sudo -u "$AFRETIP_USER" ./venv/bin/python -c "import sys; print(f'Python {sys.version} in venv')"; then
        print_success "Virtual environment Python working"
    else
        print_error "Virtual environment Python not working"
        exit 1
    fi

    # Upgrade pip first
    print_status "Upgrading pip and build tools..."
    if sudo -u "$AFRETIP_USER" ./venv/bin/python -m pip install --upgrade pip setuptools wheel; then
        print_success "Build tools upgraded successfully"
    else
        print_warning "Build tools upgrade failed, continuing with existing versions"
    fi

    # Install dependencies explicitly first (backup method)
    if [ -f "requirements.txt" ]; then
        print_status "Installing dependencies from requirements.txt..."
        if sudo -u "$AFRETIP_USER" ./venv/bin/python -m pip install -r requirements.txt; then
            print_success "Dependencies installed from requirements.txt"
        else
            print_warning "Failed to install from requirements.txt, setup.py should handle this"
        fi
    fi

    # Install the package (this should also install dependencies via setup.py)
    print_status "Installing AFRETIP package..."
    if sudo -u "$AFRETIP_USER" ./venv/bin/python -m pip install -e .; then
        print_success "Package installed in virtual environment"
    else
        print_error "Package installation failed"

        # Fallback: try installing dependencies manually first
        print_status "Trying manual dependency installation..."

        # Install common dependencies that might be missing
        sudo -u "$AFRETIP_USER" ./venv/bin/python -m pip install structlog typer rich pydantic PyYAML asyncio || true

        # Try package installation again
        if sudo -u "$AFRETIP_USER" ./venv/bin/python -m pip install -e .; then
            print_success "Package installed after manual dependency installation"
        else
            print_error "All installation methods failed"
            exit 1
        fi
    fi

    # Verify the installation by testing imports
    print_status "Verifying installation..."
    if sudo -u "$AFRETIP_USER" ./venv/bin/python -c "import threat_intel; print('✅ Package imports successfully')"; then
        print_success "Package verification successful"
    else
        print_error "Package verification failed - imports not working"

        # List installed packages for debugging
        print_status "Installed packages:"
        sudo -u "$AFRETIP_USER" ./venv/bin/python -m pip list
        exit 1
    fi

    # Create system-wide command wrapper with better error handling
    cat > /usr/local/bin/threat-intel << 'EOF'
#!/bin/bash
set -e

# Change to afretip directory
cd /opt/afretip

# Execute the CLI module
exec ./venv/bin/python -m threat_intel.cli "$@"
EOF
    chmod +x /usr/local/bin/threat-intel

    # Test the CLI works
    print_status "Testing CLI functionality..."
    if sudo -u "$AFRETIP_USER" ./venv/bin/python -m threat_intel.cli --help >/dev/null 2>&1; then
        print_success "CLI module working correctly"

        # Test the wrapper
        if sudo -u "$AFRETIP_USER" threat-intel --help >/dev/null 2>&1; then
            print_success "Command wrapper working correctly"
        else
            print_warning "Command wrapper failed, but direct module access works"
        fi
    else
        print_error "CLI module not working"
        exit 1
    fi

    print_success "AFRETIP package installed with virtual environment"
}

# Set up file permissions for Wazuh integration
setup_permissions() {
    print_status "Setting up Wazuh integration permissions..."

    # Ensure afretip user can read Wazuh archives
    if [ -f "/var/ossec/logs/archives/archives.json" ]; then
        # Add read permissions for group members
        chmod g+r "/var/ossec/logs/archives/archives.json"
        print_success "Set read permissions for archives.json"
    fi

    # Set permissions for archives directory
    if [ -d "/var/ossec/logs/archives" ]; then
        chmod g+rx "/var/ossec/logs/archives"
        print_success "Set read permissions for archives directory"
    fi

    # Ensure afretip user can access Wazuh sockets directory
    if [ -d "/var/ossec/queue/sockets" ]; then
        print_success "Socket access configured via wazuh group membership"
    fi

    # Ensure afretip user can write to Wazuh rules directory (for rule deployment)
    if [ -d "/var/ossec/etc/rules" ]; then
        # Add group write permissions to rules directory
        chmod g+w "/var/ossec/etc/rules"
        print_success "Set write permissions for rules directory"
    fi
}

# Setup configuration
setup_configuration() {
    print_status "Setting up configuration..."

    print_status "Looking for configuration files..."
    print_status "Script directory: $SCRIPT_DIR"
    print_status "Source directory: $SOURCE_DIR"

    # Ensure the target config directory exists
    mkdir -p "$AFRETIP_HOME/config"

    # Priority 1: Use config/config.yaml from source directory (uploaded files)
    if [ -f "$CONFIG_FILE" ]; then
        print_status "Found config/config.yaml in source directory: $CONFIG_FILE"

        # Copy the config file using absolute path
        cp "$CONFIG_FILE" "$AFRETIP_HOME/config/config.yaml"

        # Set proper ownership and permissions
        chown "$AFRETIP_USER:$AFRETIP_GROUP" "$AFRETIP_HOME/config/config.yaml"
        chmod 640 "$AFRETIP_HOME/config/config.yaml"

        print_success "Configuration copied from source config/config.yaml"

    # Priority 2: Use config.yaml from root of source directory
    elif [ -f "$CONFIG_FILE_ROOT" ]; then
        print_status "Found config.yaml in source root: $CONFIG_FILE_ROOT"

        # Copy the config file using absolute path
        cp "$CONFIG_FILE_ROOT" "$AFRETIP_HOME/config/config.yaml"

        # Set proper ownership and permissions
        chown "$AFRETIP_USER:$AFRETIP_GROUP" "$AFRETIP_HOME/config/config.yaml"
        chmod 640 "$AFRETIP_HOME/config/config.yaml"

        print_success "Configuration copied from source config.yaml"

    # Priority 3: Use existing config in target location (from git clone)
    elif [ -f "$AFRETIP_HOME/config/config.yaml" ]; then
        print_status "Configuration already exists at $AFRETIP_HOME/config/config.yaml"

        # Just fix ownership and permissions
        chown "$AFRETIP_USER:$AFRETIP_GROUP" "$AFRETIP_HOME/config/config.yaml"
        chmod 640 "$AFRETIP_HOME/config/config.yaml"

        print_success "Configuration permissions updated"

    # Priority 4: Move config from AFRETIP_HOME root if it exists there
    elif [ -f "$AFRETIP_HOME/config.yaml" ]; then
        print_status "Moving config.yaml from $AFRETIP_HOME/ to $AFRETIP_HOME/config/"

        # Move the file
        mv "$AFRETIP_HOME/config.yaml" "$AFRETIP_HOME/config/config.yaml"

        # Set proper ownership and permissions
        chown "$AFRETIP_USER:$AFRETIP_GROUP" "$AFRETIP_HOME/config/config.yaml"
        chmod 640 "$AFRETIP_HOME/config/config.yaml"

        print_success "Configuration moved to config/ directory"

    # Priority 5: Last resort - create production config from template
    else
        print_warning "No configuration file found in uploaded source"
        print_status "Creating production configuration from template..."

        # Create comprehensive production config

        cat > "$AFRETIP_HOME/config/config.yaml" << 'EOF'
# AFRETIP Production Configuration with Hybrid IOC Detection
wazuh:
  sockets:
    archives: "/var/ossec/queue/sockets/queue"
  connection:
    timeout: 30
    retry_interval: 5
    max_retries: 3
    use_socket: false  # Use file monitoring (more reliable)
  files:
    archives: "/var/ossec/logs/archives/archives.json"

# Enhanced Processing Configuration
processing:
  confidence_threshold: 0.6
  novelty_threshold: 0.7
  batch_size: 100
  max_queue_size: 10000
  enable_pattern_detection: true
  enable_novelty_detection: true
  enable_hybrid_classification: true

# IOC Extraction Configuration - NEW SECTION
extraction:
  confidence_threshold: 0.3
  enable_novelty_scoring: true
  enable_threat_scoring: true
  enable_context_extraction: true
  max_context_length: 100

# Hybrid IOC Classification Configuration
hybrid_classification:
  contextual_suspicion_threshold: 0.8
  reputation_confirmation_threshold: 0.3
  combined_confidence_threshold: 0.65
  enable_reputation_checking: true
  enable_whitelist_checking: true
  enable_behavioral_analysis: true
  reputation_cache_ttl_hours: 1
  max_reputation_checks_per_minute: 4

# Threat Intelligence Configuration
threat_intelligence:
  auto_update_feeds: true
  update_check_interval_minutes: 30
  feeds:
    abuse_ch_malware:
      enabled: true
      url: "https://bazaar.abuse.ch/export/txt/sha256/recent/"
      update_interval_hours: 6
      confidence: 0.95

# Reputation Services Configuration - NEW SECTION
reputation_services:
  virustotal:
    enabled: false
    api_key: ""
    rate_limit_per_minute: 4
    timeout_seconds: 30

# Data storage
storage:
  files:
    raw_logs: "/var/lib/afretip/raw_logs.jsonl"
    extracted_iocs: "/var/lib/afretip/extracted_iocs.jsonl"
    suspicious_findings: "/var/lib/afretip/suspicious_findings.jsonl"
    threat_intelligence_db: "/var/lib/afretip/threat_intelligence.db"

analytics:
  enabled: true
  session_name: "production"
  output_dir: "/var/lib/afretip/analytics"
  collection:
    ioc_metrics: true
    classification_metrics: true
    detection_metrics: true
    performance_metrics: true
  export:
    auto_export: true
    format: "csv"
    retention_days: 90
  research_mode: false
  detailed_logging: true

  storage:
    database_path: "/var/lib/afretip/research_data.db"
    export_directory: "/var/lib/afretip/research_exports"

  auto_export:
    enabled: true
    interval_minutes: 60
    formats: ["json", "csv"]

  performance_monitoring:
    detailed_timing: true
    memory_monitoring: true
    queue_monitoring: true
    error_tracking: true
    hybrid_classification_timing: true

# Automated Rule Deployment (disabled for safety)
deployment:
  enabled: false
  filesystem:
    rules_dir: "/var/ossec/etc/rules"
    custom_rules_file: "afretip_threat_intel_rules.xml"
    backup_existing: true
    file_permissions: "0644"
    owner: "wazuh"
    group: "wazuh"
  restart:
    enabled: false
    method: "signal"
    signal_type: "SIGHUP"
    wazuh_manager_pid_file: "/var/ossec/var/run/wazuh-manager.pid"
    delay_after_deployment: 5
  validation:
    enabled: true
    check_syntax: true
    check_rule_conflicts: true
    timeout: 30

# Rule Generation Configuration
rule_generation:
  minimum_confidence_for_rules: 0.65
  minimum_iocs_for_batch_rules: 3
  max_iocs_per_rule: 10
  max_rules_per_finding: 3
  use_threat_intelligence_context: true
  include_confidence_in_description: true
  rule_priorities:
    confirmed_malicious: 12
    reputation_confirmed_suspicious: 10
    contextually_suspicious: 8
    reputation_confirmed: 7

# SIEM Integration
siem:
  enabled: false
  format: "json"
  output_file: "/var/lib/afretip/siem_output.json"

# Standards Compliance
stix:
  enabled: false
  version: "2.1"
  output_file: "/var/lib/afretip/stix_output.json"
  include_context: true
  include_reputation_data: true

# Logging Configuration
logging:
  level: "INFO"
  file: "/var/log/afretip/threat_detection.log"
  format: "json"
  log_classification_decisions: true
  log_reputation_checks: false
  log_threat_intelligence_updates: true

# Performance Monitoring
monitoring:
  stats_interval: 30
  track_classification_performance: true
  track_reputation_service_latency: true
  track_threat_intelligence_hit_rates: true
  alerts:
    high_error_rate_threshold: 0.1
    slow_classification_threshold: 5.0
    reputation_service_failure_threshold: 0.5

# Whitelist Configuration
whitelist:
  custom_domains:
    - "your-internal-domain.com"
  custom_ips:
    - "10.0.0.0/8"
    - "192.168.1.0/24"
  custom_processes:
    - "your-custom-app.exe"

# Performance Tuning
performance:
  max_concurrent_classifications: 5
  max_concurrent_reputation_checks: 2
  ioc_cache_cleanup_interval: 300
  reputation_cache_cleanup_interval: 1800
  batch_reputation_checks: true
  batch_threat_intel_lookups: true
EOF

        # Set proper ownership and permissions
        chown "$AFRETIP_USER:$AFRETIP_GROUP" "$AFRETIP_HOME/config/config.yaml"
        chmod 640 "$AFRETIP_HOME/config/config.yaml"

        print_success "Production configuration created from template"
    fi

    # Verify the config file exists and show preview
    if [ -f "$AFRETIP_HOME/config/config.yaml" ]; then
        print_success "Configuration file ready at $AFRETIP_HOME/config/config.yaml"

        # Show config file size and first few lines
        CONFIG_SIZE=$(wc -l < "$AFRETIP_HOME/config/config.yaml")
        print_status "Configuration file contains $CONFIG_SIZE lines"
        print_status "Configuration preview (first 10 lines):"
        head -10 "$AFRETIP_HOME/config/config.yaml" | sed 's/^/  /'
        echo "  ..."

    else
        print_error "Failed to create configuration file"
        exit 1
    fi
}

# Create systemd service file
create_systemd_service() {
    print_status "Creating systemd service..."

    cat > /etc/systemd/system/afretip.service << EOF
[Unit]
Description=AFRETIP - Automated First Response Threat Intelligence Pipeline
Documentation=https://git.mif.vu.lt/micac/2025/afretip
After=network.target wazuh-manager.service
Wants=wazuh-manager.service

[Service]
Type=simple
User=$AFRETIP_USER
Group=$AFRETIP_GROUP
WorkingDirectory=$AFRETIP_HOME
Environment=PYTHONPATH=$AFRETIP_HOME
ExecStart=$AFRETIP_HOME/venv/bin/python -m threat_intel.cli start --config $AFRETIP_HOME/config/config.yaml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=afretip

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$AFRETIP_DATA $AFRETIP_LOGS /var/ossec/etc/rules
ReadOnlyPaths=/var/ossec/logs /var/ossec/queue

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    print_success "Systemd service created"
}

# Test installation
test_installation() {
    print_status "Testing installation..."

    # Test package installation
    if sudo -u "$AFRETIP_USER" threat-intel version &>/dev/null; then
        print_success "Package installation: OK"
    else
        print_error "Package installation: FAILED"
        return 1
    fi

    # Test configuration
    if sudo -u "$AFRETIP_USER" threat-intel dry-run --config "$AFRETIP_HOME/config/config.yaml" &>/dev/null; then
        print_success "Configuration test: OK"
    else
        print_warning "Configuration test: FAILED (check permissions)"
    fi

    # Test socket access
    if sudo -u "$AFRETIP_USER" test -S "/var/ossec/queue/sockets/queue"; then
        print_success "Socket access: OK"
    else
        print_warning "Socket access: FAILED (will use file monitoring)"
    fi

    # Test archives file access
    if sudo -u "$AFRETIP_USER" test -r "/var/ossec/logs/archives/archives.json"; then
        print_success "Archives file access: OK"
    else
        print_warning "Archives file access: FAILED"
    fi

    # Test rules directory write access
    if sudo -u "$AFRETIP_USER" test -w "/var/ossec/etc/rules"; then
        print_success "Rules directory write access: OK"
    else
        print_warning "Rules directory write access: FAILED (auto-deployment disabled)"
    fi

    # Test data directory access
    if sudo -u "$AFRETIP_USER" test -w "$AFRETIP_DATA"; then
        print_success "Data directory access: OK"
    else
        print_error "Data directory access: FAILED"
        return 1
    fi

    print_success "Installation tests completed"
}

# Display setup summary
show_summary() {
    echo ""
    echo "=================================================================="
    echo "🎉 AFRETIP Installation Complete!"
    echo "=================================================================="
    echo ""
    echo "System User: $AFRETIP_USER"
    echo "Home Directory: $AFRETIP_HOME"
    echo "Data Directory: $AFRETIP_DATA"
    echo "Logs Directory: $AFRETIP_LOGS"
    echo "Virtual Environment: $AFRETIP_HOME/venv"
    echo ""
    echo "🔧 Available Commands:"
    echo "  threat-intel start      # Start the pipeline"
    echo "  threat-intel test       # Test components"
    echo "  threat-intel status     # Show status"
    echo "  threat-intel dry-run    # Test without running"
    echo "  threat-intel version    # Show version"
    echo ""
    echo "🚀 Quick Start:"
    echo "1. Test installation:"
    echo "   sudo -u $AFRETIP_USER threat-intel dry-run --config $AFRETIP_HOME/config/config.yaml"
    echo ""
    echo "2. Run pipeline manually:"
    echo "   sudo -u $AFRETIP_USER threat-intel start --config $AFRETIP_HOME/config/config.yaml"
    echo ""
    echo "3. Enable automatic startup:"
    echo "   systemctl enable afretip"
    echo "   systemctl start afretip"
    echo ""
    echo "📊 Service Management:"
    echo "  systemctl start afretip     # Start service"
    echo "  systemctl stop afretip      # Stop service"
    echo "  systemctl status afretip    # Check status"
    echo "  journalctl -u afretip -f    # Follow logs"
    echo ""
    echo "📝 Configuration:"
    echo "  Edit: $AFRETIP_HOME/config/config.yaml"
    echo "  Logs: $AFRETIP_LOGS/threat_detection.log"
    echo "  Data: $AFRETIP_DATA/"
    echo ""
    echo "⚠️  Remember to:"
    echo "  - Review configuration before enabling rule deployment"
    echo "  - Monitor logs during initial testing"
    echo "  - Enable deployment.enabled: true when ready for auto-deployment"
    echo ""
}

# Main execution
main() {
    print_status "Starting AFRETIP installation..."

    # Early path validation
    print_status "Script directory: $SCRIPT_DIR"
    print_status "Source directory: $SOURCE_DIR"

    check_root
    check_dependencies
    check_wazuh
    create_user
    create_directories
    clone_repository
    install_package
    setup_permissions
    setup_configuration
    create_systemd_service
    test_installation
    show_summary

    print_success "Installation script completed successfully!"
}

# Run main function
main "$@"
