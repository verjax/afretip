import os
from pathlib import Path
from typing import Any, Optional, Union

import structlog
import yaml
from dotenv import load_dotenv

logger = structlog.get_logger(__name__)

# Load environment variables from .env file
load_dotenv()



class ConfigurationError(Exception):
    """Custom exception for configuration errors"""

    pass


def get_default_config_path() -> str:
    # Priority 1: Environment variable
    env_config = os.getenv("AFRETIP_CONFIG")
    if env_config and Path(env_config).exists():
        logger.info("Using config from environment variable", path=env_config)
        return env_config
    elif env_config:
        logger.warning(
            "Config path from environment variable does not exist", path=env_config
        )

    # Priority 2: Production installation
    production_config = "/opt/afretip/config/config.yaml"
    if Path(production_config).exists():
        logger.info("Using production config", path=production_config)
        return production_config

    # Priority 3: Development directory
    dev_config = "config/config-dev.yaml"
    if Path(dev_config).exists():
        logger.info("Using development config", path=dev_config)
        return dev_config

    # Priority 4: Current directory
    current_config = "config.yaml"
    if Path(current_config).exists():
        logger.info("Using current directory config", path=current_config)
        return current_config

    # Default fallback (will be checked later for existence)
    logger.info("No config found, using production default", path=production_config)
    return production_config


def validate_config_structure(config_data: dict[str, Any]) -> list[str]:
    """
    Validate the configuration structure and return list of errors
    """
    errors = []

    # Required top-level sections
    required_sections = ["wazuh", "processing", "logging", "storage"]

    for section in required_sections:
        if section not in config_data:
            errors.append(f"Missing required section: {section}")

    # Validate wazuh section
    if "wazuh" in config_data:
        wazuh_config = config_data["wazuh"]

        if "connection" not in wazuh_config:
            errors.append("Missing wazuh.connection configuration")

        if "sockets" not in wazuh_config and "files" not in wazuh_config:
            errors.append("Missing both wazuh.sockets and wazuh.files configuration")

    # Validate processing section
    if "processing" in config_data:
        processing_config = config_data["processing"]

        confidence_threshold = processing_config.get("confidence_threshold", 0.6)
        if (
            not isinstance(confidence_threshold, (int, float))
            or not 0 <= confidence_threshold <= 1
        ):
            errors.append(
                f"Invalid confidence_threshold: {confidence_threshold} (should be 0-1)"
            )

        novelty_threshold = processing_config.get("novelty_threshold", 0.7)
        if (
            not isinstance(novelty_threshold, (int, float))
            or not 0 <= novelty_threshold <= 1
        ):
            errors.append(
                f"Invalid novelty_threshold: {novelty_threshold} (should be 0-1)"
            )

    # Validate storage section
    if "storage" in config_data:
        storage_config = config_data["storage"]

        if "files" not in storage_config:
            errors.append("Missing storage.files configuration")

    return errors


def load_config(config_path: Optional[str] = None) -> dict[str, Any]:
    """
    Load configuration with improved error handling and validation

    Args:
        config_path: Optional path to config file. If None, uses default resolution.

    Returns:
        Dictionary containing configuration data

    Raises:
        ConfigurationError: If config cannot be loaded or is invalid
    """

    # Use provided path or resolve default
    if config_path is None:
        config_path = get_default_config_path()

    config_file = Path(config_path)

    # Check if config file exists
    if not config_file.exists():
        # Check for example file
        example_file = Path(f"{config_path}.example")
        if example_file.exists():
            raise ConfigurationError(
                f"Config file {config_path} not found. "
                f"Copy {config_path}.example to {config_path} and edit it."
            )
        else:
            raise ConfigurationError(
                f"Config file {config_path} not found. "
                f"Please create a configuration file or run the installer."
            )

    # Load and parse YAML
    try:
        with open(config_file, encoding="utf-8") as f:
            config_data = yaml.safe_load(f) or {}

        logger.info(
            "Configuration loaded successfully",
            path=str(config_file),
            sections=list(config_data.keys()),
        )

    except yaml.YAMLError as e:
        raise ConfigurationError(f"Invalid YAML in config file {config_path}: {e}")
    except Exception as e:
        raise ConfigurationError(f"Error reading config file {config_path}: {e}")

    # Validate configuration structure
    validation_errors = validate_config_structure(config_data)
    if validation_errors:
        error_msg = "Configuration validation failed:\n" + "\n".join(
            f"  • {error}" for error in validation_errors
        )
        raise ConfigurationError(error_msg)

    # Apply default values for missing optional settings
    config_data = apply_config_defaults(config_data)

    # Override API keys from environment variables
    if "reputation_services" in config_data:
        if "virustotal" in config_data["reputation_services"] and os.getenv(
            "VIRUSTOTAL_API_KEY"
        ):
            config_data["reputation_services"]["virustotal"]["api_key"] = os.getenv(
                "VIRUSTOTAL_API_KEY"
            )
        if "abuseipdb" in config_data["reputation_services"] and os.getenv(
            "ABUSEIPDB_API_KEY"
        ):
            config_data["reputation_services"]["abuseipdb"]["api_key"] = os.getenv(
                "ABUSEIPDB_API_KEY"
            )

    return config_data


def apply_config_defaults(config_data: dict[str, Any]) -> dict[str, Any]:
    """Apply default values for missing optional configuration settings"""

    # Processing defaults
    processing_defaults: dict[str, Union[float, int, bool]] = {
        "confidence_threshold": 0.6,
        "novelty_threshold": 0.7,
        "batch_size": 100,
        "max_queue_size": 10000,
        "enable_pattern_detection": True,
        "enable_novelty_detection": True,
        "enable_hybrid_classification": True,
    }

    if "processing" not in config_data:
        config_data["processing"] = {}

    for key, default_value in processing_defaults.items():
        if key not in config_data["processing"]:
            config_data["processing"][key] = default_value

    # Analytics defaults
    analytics_defaults: dict[str, Any] = {
        "enabled": True,
        "session_name": "production",
        "output_dir": "/var/lib/afretip/analytics",
    }

    if "analytics" not in config_data:
        config_data["analytics"] = {}

    for key, default_value in analytics_defaults.items():
        if key not in config_data["analytics"]:
            config_data["analytics"][key] = default_value

    # Deployment defaults
    deployment_defaults: dict[str, Any] = {
        "enabled": False,
        "filesystem": {
            "rules_dir": "/var/ossec/etc/rules",
            "custom_rules_file": "afretip_threat_intel_rules.xml",
            "backup_existing": True,
        },
    }

    if "deployment" not in config_data:
        config_data["deployment"] = {}

    for key, default_value in deployment_defaults.items():
        if key not in config_data["deployment"]:
            config_data["deployment"][key] = default_value

    # Storage defaults
    storage_defaults: dict[str, Any] = {
        "files": {
            "raw_logs": "/var/lib/afretip/raw_logs.jsonl",
            "extracted_iocs": "/var/lib/afretip/extracted_iocs.jsonl",
            "suspicious_findings": "/var/lib/afretip/suspicious_findings.jsonl",
            "threat_intelligence_db": "/var/lib/afretip/threat_intelligence.db",
        }
    }

    if "storage" not in config_data:
        config_data["storage"] = {}

    for key, default_value in storage_defaults.items():
        if key not in config_data["storage"]:
            config_data["storage"][key] = default_value

    # Logging defaults
    logging_defaults: dict[str, Any] = {
        "level": "INFO",
        "file": "/var/log/afretip/threat_detection.log",
        "format": "json",
    }

    if "logging" not in config_data:
        config_data["logging"] = {}

    for key, default_value in logging_defaults.items():
        if key not in config_data["logging"]:
            config_data["logging"][key] = default_value

    return config_data


def get_environment_type() -> str:
    """Determine if we're running in production or development"""

    if Path("/opt/afretip").exists():
        return "production"
    elif Path("src/threat_intel").exists():
        return "development"
    else:
        return "unknown"


def create_example_config(output_path: str) -> bool:
    """Create an example configuration file"""

    example_config = {
        "wazuh": {
            "sockets": {"archives": "/var/ossec/queue/sockets/queue"},
            "connection": {
                "timeout": 30,
                "retry_interval": 5,
                "max_retries": 3,
                "use_socket": False,
            },
            "files": {"archives": "/var/ossec/logs/archives/archives.json"},
        },
        "processing": {
            "confidence_threshold": 0.6,
            "novelty_threshold": 0.7,
            "batch_size": 100,
            "enable_pattern_detection": True,
            "enable_novelty_detection": True,
            "enable_hybrid_classification": True,
        },
        "analytics": {
            "enabled": True,
            "session_name": "production",
            "output_dir": "/var/lib/afretip/analytics",
        },
        "deployment": {
            "enabled": False,
            "filesystem": {
                "rules_dir": "/var/ossec/etc/rules",
                "custom_rules_file": "afretip_threat_intel_rules.xml",
                "backup_existing": True,
            },
        },
        "storage": {
            "files": {
                "raw_logs": "/var/lib/afretip/raw_logs.jsonl",
                "extracted_iocs": "/var/lib/afretip/extracted_iocs.jsonl",
                "suspicious_findings": "/var/lib/afretip/suspicious_findings.jsonl",
                "threat_intelligence_db": "/var/lib/afretip/threat_intelligence.db",
            }
        },
        "logging": {
            "level": "INFO",
            "file": "/var/log/afretip/threat_detection.log",
            "format": "json",
        },
    }

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            yaml.dump(example_config, f, default_flow_style=False, sort_keys=False)

        logger.info("Example configuration created", path=output_path)
        return True

    except Exception as e:
        logger.error(
            "Failed to create example configuration", path=output_path, error=str(e)
        )
        return False
