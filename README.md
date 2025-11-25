# AFRETIP - Automated First Response Threat Intelligence Pipeline

Automated threat intelligence pipeline for first response that processes Wazuh EDR logs in real-time, extracts IOCs, detects novel threats, and generates defensive rules automatically.

## 🎯 Features

- 🔍 **Real-time threat detection** from Wazuh logs via sockets or files
- 🎯 **Novel IOC discovery** - detects new threats before rules exist
- 🧠 **Pattern-based detection** - identifies 6+ suspicious behavior patterns
- ⚡ **High-performance processing** - async pipeline handles high log volumes
- 🛡️ **Automated defense** - generates and deploys Wazuh rules automatically
- 📊 **Comprehensive scoring** - confidence, novelty, and threat scoring
- 🎨 **Professional CLI** - rich terminal interface with status monitoring

## 🚀 Quick Installation

**One-command installation** (requires Wazuh already installed):

```bash
curl -fsSL <PRIVATE_GITLAB_URL>/main/install.sh | sudo bash
```

**Manual installation:**
```bash
git clone <PRIVATE_GITLAB_URL>
cd afretip
sudo ./install.sh
```

## 🧪 Quick Start

```bash
# Test installation
sudo -u afretip threat-intel version
sudo -u afretip threat-intel dry-run

# Start pipeline
sudo -u afretip threat-intel start

# Check status
sudo -u afretip threat-intel status

# Run as service
sudo systemctl enable afretip
sudo systemctl start afretip
```

## 🏗️ Architecture

```
Wazuh EDR → IOC Extraction → Threat Detection → Rule Generation → Auto-Deploy
    ↓           ↓               ↓               ↓             ↓
Real-time   11 IOC Types   Pattern+Novelty   XML Rules   Active Defense
Streaming   + Scoring      Detection         + Validation  + Hot Reload
```

## 📁 Project Structure

```
afretip/
├── src/threat_intel/   # Main application code
│   ├── analytics/      # Metrics & analysis
│   ├── connectors/     # Data ingestion
│   ├── core/           # Core engine  
│   ├── defence/        # Rule deployment
│   ├── detectors/      # Threat detection
│   ├── enrichment/     # Classification
│   ├── extractors/     # IOC extraction  
│   ├── generators/     # Rule generation
│   └── utils/          # Configuration & logging
├── tests/              # Test suite
├── config/             # Configuration files
└── scripts/            # Installation and utility scripts
```

## ⚙️ Configuration

Configuration is automatically created during installation at `/opt/afretip/config/config.yaml`.

Key settings:
```yaml
wazuh:
  connection:
    use_socket: true          # Real-time socket monitoring
deployment:
  enabled: false              # Enable for auto-rule deployment
processing:
  confidence_threshold: 0.6   # IOC confidence threshold
  novelty_threshold: 0.7      # Novel threat detection threshold
```

## 🛠️ Development

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/ -v

`# Run linting
ruff check src/
ruff format src/

# Type checking
mypy src/`
```
```bash
# Install in development mode
pip install -e .

# Run tests
./scripts/test.sh

# Development commands
threat-intel start           # Start pipeline
threat-intel test           # Test components
threat-intel dry-run        # Test without running
```

## 📊 Service Management

```bash
# Service control
systemctl start afretip      # Start service
systemctl stop afretip       # Stop service
systemctl status afretip     # Check status
journalctl -u afretip -f     # Follow logs

# Manual execution
sudo -u afretip threat-intel start --config /opt/afretip/config/config.yaml
```

## 🔧 CLI Commands

```bash
threat-intel start           # Start the pipeline
threat-intel test            # Test Wazuh connectivity
threat-intel status          # Show component status
threat-intel dry-run         # Validate configuration
threat-intel version         # Show version info
```

## 📈 What It Detects

**IOC Types (11):**
- IP addresses, domains, URLs, email addresses
- File hashes (MD5, SHA1, SHA256), file paths
- Registry keys, processes, command lines

**Threat Patterns:**
- PowerShell obfuscation and hidden execution
- Living-off-the-land tool abuse
- Suspicious file creation in temp directories
- Communication with suspicious TLDs
- Novel/rare IOCs with high threat scores

## 🎓 Research Context

This pipeline addresses key cybersecurity research challenges:
- **Real-time processing** of internal EDR telemetry (not just external feeds)
- **Automated IOC extraction** reducing 45+ minute manual analysis
- **End-to-end automation** from log ingestion to defensive action

## 📋 Requirements

- Ubuntu/Debian Linux
- Wazuh Manager (any recent version)
- Python 3.9+
- Wazuh user must exist

## 📄 License

MIT License - see LICENSE file for details.

---

**Research Project**: Vilnius University