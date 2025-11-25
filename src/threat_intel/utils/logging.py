import logging
import sys
from pathlib import Path
from typing import Any

import structlog
from structlog.stdlib import LoggerFactory


def setup_logging(config: dict[str, Any]) -> None:
    logging_config = config.get("logging", {})
    log_level = logging_config.get("level", "INFO").upper()
    log_file = logging_config.get("file", "/var/log/afretip/threat_detection.log")
    log_format = logging_config.get("format", "json")

    # Ensure log directory exists
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Configure standard logging
    logging.basicConfig(
        level=getattr(logging, log_level),
        format="%(message)s",
        handlers=[logging.FileHandler(log_file), logging.StreamHandler(sys.stdout)],
    )

    # Configure structlog with proper typing
    if log_format.lower() == "json":
        processors: list[Any] = [
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="ISO"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer(),
        ]
    else:
        processors = [
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="ISO"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.dev.ConsoleRenderer(),
        ]

    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=LoggerFactory(),
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        cache_logger_on_first_use=True,
    )

    # Set log level for structlog
    logging.getLogger().setLevel(getattr(logging, log_level))

    # Ensure the log file is writable
    try:
        with open(log_file, "a") as f:
            f.write("")  # Test write
    except Exception as e:
        print(f"Warning: Cannot write to log file {log_file}: {e}")
        # Fall back to just console logging
        logging.basicConfig(
            level=getattr(logging, log_level),
            format="%(message)s",
            handlers=[logging.StreamHandler(sys.stdout)],
        )
