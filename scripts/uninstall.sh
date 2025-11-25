#!/bin/bash
##############################################################################
# AFRETIP Complete Uninstall Script
# This script completely removes all AFRETIP components from the system
# Updated for enhanced analytics and hybrid IOC classification system
##############################################################################

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
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
    echo -e "${BLUE}$1${NC}"
    echo "=============================================================================="
}

# Check if running as root or with sudo
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root or with sudo"
    exit 1
fi

print_header "🧹 AFRETIP Complete Uninstall Script"

# Check if script might kill itself
SCRIPT_PATH="$(realpath "$0")"
if echo "$SCRIPT_PATH" | grep -q "afretip"; then
    print_warning "Script is running from path containing 'afretip': $SCRIPT_PATH"
    print_status "This is safe - the script has been updated to avoid killing itself"
fi

echo "This will completely remove all AFRETIP components from your system including:"
echo "  • Core threat intelligence pipeline"
echo "  • Analytics and research databases"
echo "  • Hybrid IOC classification system"
echo "  • All data, logs, and configurations"
echo ""

# Ask for confirmation with data warning
echo -e "${RED}⚠️  WARNING: This will permanently delete all threat intelligence data!${NC}"
echo "This includes:"
echo "  • IOC extraction databases"
echo "  • Analytics and performance data"
echo "  • Threat intelligence feeds"
echo "  • Classification training data"
echo "  • All logs and research exports"
echo ""

read -p "Are you sure you want to completely uninstall AFRETIP? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_warning "Uninstall cancelled by user"
    exit 0
fi

# Optional data backup
echo ""
read -p "Do you want to backup analytics data before deletion? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_status "Creating backup of analytics data..."
    BACKUP_DIR="/tmp/afretip_backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"

    # Backup analytics databases
    if [ -d "/var/lib/afretip" ]; then
        cp -r /var/lib/afretip/*.db "$BACKUP_DIR/" 2>/dev/null || true
        cp -r /var/lib/afretip/analytics "$BACKUP_DIR/" 2>/dev/null || true
        cp -r /var/lib/afretip/research_exports "$BACKUP_DIR/" 2>/dev/null || true
        print_success "Analytics data backed up to: $BACKUP_DIR"
    fi
fi

echo ""
print_header "🛑 Step 1: Stopping All Services and Processes"

# Stop systemd service first
print_status "Stopping AFRETIP systemd service..."
if systemctl is-active --quiet afretip; then
    systemctl stop afretip
    print_success "Stopped afretip service"
else
    print_warning "afretip service not running"
fi

# Disable systemd service
if systemctl is-enabled --quiet afretip 2>/dev/null; then
    systemctl disable afretip
    print_success "Disabled afretip service"
fi

# Stop any running AFRETIP processes (excluding this script)
print_status "Stopping AFRETIP processes..."
SCRIPT_PID=$
SCRIPT_NAME="$(basename "$0")"

# Kill threat-intel processes (safe)
pkill -f threat-intel 2>/dev/null || true

# Kill afretip processes but exclude this uninstall script
for pid in $(pgrep -f afretip 2>/dev/null || true); do
    if [ "$pid" != "$SCRIPT_PID" ]; then
        # Check if it's not this uninstall script
        if ! ps -p "$pid" -o cmd= 2>/dev/null | grep -q "$SCRIPT_NAME"; then
            kill "$pid" 2>/dev/null || true
        fi
    fi
done

# Kill python threat_intel processes
pkill -f "python.*threat_intel" 2>/dev/null || true

sleep 3

# Check for remaining processes
REMAINING_PROCESSES=$(ps aux | grep -E "(threat-intel|python.*threat_intel)" | grep -v grep | wc -l)
if [ $REMAINING_PROCESSES -gt 0 ]; then
    print_warning "Force killing remaining processes..."
    pkill -9 -f threat-intel 2>/dev/null || true
    pkill -9 -f "python.*threat_intel" 2>/dev/null || true

    # Force kill remaining afretip processes (excluding this script)
    for pid in $(pgrep -f afretip 2>/dev/null || true); do
        if [ "$pid" != "$SCRIPT_PID" ]; then
            if ! ps -p "$pid" -o cmd= 2>/dev/null | grep -q "$SCRIPT_NAME"; then
                kill -9 "$pid" 2>/dev/null || true
            fi
        fi
    done

    sleep 2
fi

print_success "All processes stopped"

print_header "🗂️ Step 2: Removing System Files and Directories"

# Remove main installation directory
print_status "Removing /opt/afretip..."
if [ -d "/opt/afretip" ]; then
    # Show size before deletion
    INSTALL_SIZE=$(du -sh /opt/afretip 2>/dev/null | cut -f1)
    print_status "Installation directory size: $INSTALL_SIZE"
    rm -rf /opt/afretip
    print_success "Removed /opt/afretip"
else
    print_warning "/opt/afretip directory not found"
fi

# Remove data directory with detailed cleanup
print_status "Removing /var/lib/afretip..."
if [ -d "/var/lib/afretip" ]; then
    # Show data size before deletion
    DATA_SIZE=$(du -sh /var/lib/afretip 2>/dev/null | cut -f1)
    print_status "Data directory size: $DATA_SIZE"

    # List key files being removed
    print_status "Removing analytics and threat intelligence data:"
    [ -f "/var/lib/afretip/threat_intelligence.db" ] && echo "  • Threat Intelligence Database"
    [ -f "/var/lib/afretip/research_data.db" ] && echo "  • Analytics Research Database"
    [ -d "/var/lib/afretip/analytics" ] && echo "  • Analytics Data Directory"
    [ -d "/var/lib/afretip/research_exports" ] && echo "  • Research Export Directory"
    [ -f "/var/lib/afretip/raw_logs.jsonl" ] && echo "  • Raw Logs Archive"
    [ -f "/var/lib/afretip/extracted_iocs.jsonl" ] && echo "  • Extracted IOCs Archive"
    [ -f "/var/lib/afretip/suspicious_findings.jsonl" ] && echo "  • Suspicious Findings Archive"

    rm -rf /var/lib/afretip
    print_success "Removed /var/lib/afretip and all analytics data"
else
    print_warning "/var/lib/afretip directory not found"
fi

# Remove log directory
print_status "Removing /var/log/afretip..."
if [ -d "/var/log/afretip" ]; then
    LOG_SIZE=$(du -sh /var/log/afretip 2>/dev/null | cut -f1)
    print_status "Log directory size: $LOG_SIZE"
    rm -rf /var/log/afretip
    print_success "Removed /var/log/afretip"
else
    print_warning "/var/log/afretip directory not found"
fi

# Remove temporary files and caches
print_status "Removing temporary files and caches..."
rm -rf /tmp/afretip* 2>/dev/null || true
rm -rf /tmp/*threat-intel* 2>/dev/null || true
rm -rf /var/tmp/afretip* 2>/dev/null || true

# Remove any analytics export files in common locations
find /tmp -name "*afretip*" -type f -delete 2>/dev/null || true
find /home -name "*afretip_analytics*" -type f -delete 2>/dev/null || true
find /home -name "*afretip_report*" -type f -delete 2>/dev/null || true

print_success "Temporary files and caches cleaned"

print_header "👤 Step 3: Removing User and Groups"

# Check if afretip user exists and get details
if id "afretip" &>/dev/null; then
    print_status "Removing afretip user and home directory..."

    # Kill any remaining afretip user processes (excluding this script if run by afretip)
    CURRENT_USER=$(whoami)
    if [ "$CURRENT_USER" != "afretip" ]; then
        # Safe to kill all afretip user processes
        pkill -u afretip 2>/dev/null || true
        sleep 1
    else
        # Running as afretip user - kill only specific processes
        pkill -u afretip -f threat-intel 2>/dev/null || true
        pkill -u afretip -f "python.*threat_intel" 2>/dev/null || true
        sleep 1
    fi

    # Remove user and home directory
    userdel -r afretip 2>/dev/null || true
    print_success "Removed afretip user"

    # Clean up any remaining user files
    find /home -name "afretip" -type d -exec rm -rf {} + 2>/dev/null || true
    find /tmp -user afretip -delete 2>/dev/null || true
else
    print_warning "afretip user not found"
fi

# Remove afretip group if it exists
if getent group afretip &>/dev/null; then
    print_status "Removing afretip group..."
    groupdel afretip 2>/dev/null || true
    print_success "Removed afretip group"
else
    print_warning "afretip group not found"
fi

print_header "⚙️ Step 4: Removing System Configuration"

# Remove systemd service files
print_status "Removing systemd service files..."
if [ -f "/etc/systemd/system/afretip.service" ]; then
    rm -f /etc/systemd/system/afretip.service
    systemctl daemon-reload
    print_success "Removed systemd service"
else
    print_warning "No systemd service found"
fi

# Remove any systemd drop-in directories
if [ -d "/etc/systemd/system/afretip.service.d" ]; then
    rm -rf /etc/systemd/system/afretip.service.d
    print_success "Removed systemd drop-in directory"
fi

# Remove binary symlinks and commands
print_status "Removing command line tools..."
if [ -L "/usr/local/bin/threat-intel" ] || [ -f "/usr/local/bin/threat-intel" ]; then
    rm -f /usr/local/bin/threat-intel
    print_success "Removed threat-intel command"
else
    print_warning "threat-intel command not found"
fi

# Remove any additional commands
rm -f /usr/local/bin/afretip 2>/dev/null || true
rm -f /usr/bin/threat-intel 2>/dev/null || true
rm -f /usr/bin/afretip 2>/dev/null || true

# Remove configuration from /etc if any
print_status "Removing system configuration files..."
if [ -d "/etc/afretip" ]; then
    rm -rf /etc/afretip
    print_success "Removed /etc/afretip"
fi

# Remove logrotate configuration
if [ -f "/etc/logrotate.d/afretip" ]; then
    rm -f /etc/logrotate.d/afretip
    print_success "Removed logrotate configuration"
fi

# Remove cron jobs
print_status "Removing cron jobs..."
crontab -u afretip -r 2>/dev/null || true
# Remove system cron jobs
rm -f /etc/cron.d/afretip 2>/dev/null || true
rm -f /etc/cron.daily/afretip* 2>/dev/null || true
rm -f /etc/cron.hourly/afretip* 2>/dev/null || true
print_success "Cron jobs cleaned"

print_header "🐍 Step 5: Cleaning Python Environment"

# Remove global Python packages
print_status "Removing global Python packages..."
pip3 uninstall threat-intel -y 2>/dev/null || true
pip3 uninstall afretip -y 2>/dev/null || true
python3 -m pip uninstall threat-intel -y 2>/dev/null || true
python3 -m pip uninstall afretip -y 2>/dev/null || true
print_success "Global Python packages cleaned"

# Clear Python cache thoroughly
print_status "Clearing Python cache..."
find /opt -name "*.pyc" -delete 2>/dev/null || true
find /opt -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find /var -name "*afretip*.pyc" -delete 2>/dev/null || true
find /var -name "*threat_intel*.pyc" -delete 2>/dev/null || true
find /usr -name "*threat_intel*" -name "*.pyc" -delete 2>/dev/null || true

# Remove virtual environments
find /opt -name "venv" -path "*/afretip/*" -type d -exec rm -rf {} + 2>/dev/null || true
find /home -name "*afretip*" -name "venv" -type d -exec rm -rf {} + 2>/dev/null || true

print_success "Python cache and virtual environments cleared"

print_header "🛡️ Step 6: Cleaning Wazuh Integration"

print_status "Cleaning Wazuh integration..."

# Remove any custom Wazuh rules created by AFRETIP
WAZUH_RULES_DIR="/var/ossec/etc/rules"
if [ -d "$WAZUH_RULES_DIR" ]; then
    # Remove AFRETIP-generated rule files
    rm -f "$WAZUH_RULES_DIR"/afretip_*.xml 2>/dev/null || true
    rm -f "$WAZUH_RULES_DIR"/threat_intel_*.xml 2>/dev/null || true
    rm -f "$WAZUH_RULES_DIR"/*afretip*.xml 2>/dev/null || true
    print_success "Removed AFRETIP-generated Wazuh rules"
else
    print_warning "Wazuh rules directory not found"
fi

# Remove afretip user from wazuh group
if id "wazuh" &>/dev/null && getent group wazuh &>/dev/null; then
    gpasswd -d afretip wazuh 2>/dev/null || true
    print_success "Removed afretip from wazuh group"
fi

print_header "🗄️ Step 7: Database and Analytics Cleanup"

print_status "Performing thorough database cleanup..."

# Remove any SQLite WAL and SHM files
find /var -name "*afretip*.db-wal" -delete 2>/dev/null || true
find /var -name "*afretip*.db-shm" -delete 2>/dev/null || true
find /var -name "*threat_intel*.db*" -delete 2>/dev/null || true
find /var -name "*research_data*.db*" -delete 2>/dev/null || true

# Remove analytics export files from common locations
find /var -name "*analytics*" -path "*/afretip/*" -delete 2>/dev/null || true
find /tmp -name "afretip_analytics_*" -delete 2>/dev/null || true
find /tmp -name "afretip_report_*" -delete 2>/dev/null || true

print_success "Database and analytics cleanup completed"

print_header "🔍 Step 8: Verification"

# Comprehensive verification checks
print_status "Verifying complete removal..."

ISSUES_FOUND=0

# Check user
if id "afretip" &>/dev/null; then
    print_error "❌ afretip user still exists"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    print_success "✅ afretip user removed"
fi

# Check group
if getent group afretip &>/dev/null; then
    print_error "❌ afretip group still exists"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    print_success "✅ afretip group removed"
fi

# Check directories
for dir in "/opt/afretip" "/var/lib/afretip" "/var/log/afretip" "/etc/afretip"; do
    if [ -d "$dir" ]; then
        print_error "❌ Directory still exists: $dir"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    else
        print_success "✅ Directory removed: $dir"
    fi
done

# Check processes (excluding this script)
REMAINING_PROCESSES=$(ps aux | grep -E "(threat-intel|python.*threat_intel)" | grep -v grep | wc -l)
if [ $REMAINING_PROCESSES -gt 0 ]; then
    print_error "❌ AFRETIP processes still running:"
    ps aux | grep -E "(threat-intel|python.*threat_intel)" | grep -v grep
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    print_success "✅ No AFRETIP processes running"
fi

# Check commands
if command -v threat-intel &>/dev/null; then
    print_error "❌ threat-intel command still available"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    print_success "✅ threat-intel command removed"
fi

# Check systemd service
if systemctl list-unit-files | grep -q afretip; then
    print_error "❌ systemd service still registered"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    print_success "✅ systemd service removed"
fi

# Check for remaining files
REMAINING_FILES=$(find /var /opt /etc /usr -name "*afretip*" -o -name "*threat-intel*" 2>/dev/null | wc -l)
if [ $REMAINING_FILES -gt 0 ]; then
    print_warning "⚠️ Found $REMAINING_FILES remaining files:"
    find /var /opt /etc /usr -name "*afretip*" -o -name "*threat-intel*" 2>/dev/null | head -10
    [ $REMAINING_FILES -gt 10 ] && echo "  ... and $((REMAINING_FILES - 10)) more"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    print_success "✅ No remaining files found"
fi

print_header "📋 Uninstall Summary"

if [ $ISSUES_FOUND -eq 0 ]; then
    print_success "🎉 AFRETIP completely uninstalled successfully!"
    print_success "All components removed:"
    echo "  ✅ Threat intelligence pipeline"
    echo "  ✅ Analytics and research databases"
    echo "  ✅ Hybrid IOC classification system"
    echo "  ✅ All configuration and data files"
    echo "  ✅ System integration (Wazuh, systemd)"
    echo ""
    print_success "System is clean and ready for fresh installation"
else
    print_warning "⚠️ Uninstall completed with $ISSUES_FOUND issues"
    print_warning "You may need to manually remove remaining components"
    echo ""
    print_status "To manually clean remaining files, run:"
    echo "    find /var /opt /etc /usr -name '*afretip*' -delete"
    echo "    find /var /opt /etc /usr -name '*threat-intel*' -delete"
fi

echo ""
print_status "Optional cleanup commands:"
echo "  • Remove development files: rm -rf ~/afretip"
echo "  • Remove user virtual envs: rm -rf ~/.local/share/virtualenvs/afretip*"
echo "  • Remove pip cache: pip3 cache purge"
echo ""

print_header "🧹 Optional Development Cleanup"

# Ask if user wants to remove development directory
echo ""
read -p "Do you want to remove the development directory ~/afretip? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    for home_dir in /home/*/afretip; do
        if [ -d "$home_dir" ]; then
            rm -rf "$home_dir"
            print_success "Removed development directory: $home_dir"
        fi
    done

    # Also check root's home
    if [ -d "/root/afretip" ]; then
        rm -rf "/root/afretip"
        print_success "Removed development directory: /root/afretip"
    fi

    if [ ! -d "/home/*/afretip" ] && [ ! -d "/root/afretip" ]; then
        print_warning "No development directories found"
    fi
fi

# Ask about backup cleanup
if [ -n "$BACKUP_DIR" ] && [ -d "$BACKUP_DIR" ]; then
    echo ""
    read -p "Do you want to remove the backup directory $BACKUP_DIR? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$BACKUP_DIR"
        print_success "Backup directory removed"
    else
        print_status "Backup preserved at: $BACKUP_DIR"
    fi
fi

print_header "✅ Uninstall Complete"

echo ""
if [ $ISSUES_FOUND -eq 0 ]; then
    print_success "🚀 System is completely clean and ready for a fresh AFRETIP installation!"
else
    print_warning "🔧 Manual cleanup may be required for remaining components"
fi

echo ""
print_status "To reinstall AFRETIP, run: sudo ./scripts/install.sh"
