from typing import Any

__version__ = "1.0.0"
__author__ = "moda.0x"
__description__ = "Automated First Response Threat Intelligence Pipeline"

from .core.models import (
    ExtractedIOC,
    IOCClassification,
    IOCType,
    SuspiciousFinding,
    ThreatLevel,
    WazuhRawLog,
    WazuhRule,
)

__all__ = [
    "__version__",
    "__author__",
    "__description__",
    "IOCType",
    "ThreatLevel",
    "WazuhRawLog",
    "ExtractedIOC",
    "IOCClassification",
    "SuspiciousFinding",
    "WazuhRule",
    # Lazy imports available via functions
    "get_processing_engine",
    "get_analytics_metrics",
    "initialize_analytics",
]


# Lazy imports for components that might have circular dependencies
def get_processing_engine() -> Any:
    """Get ProcessingEngine class (lazy import)"""
    from .core.engine import ProcessingEngine

    return ProcessingEngine


def get_analytics_metrics() -> Any:
    """Get AnalyticsMetrics class (lazy import)"""
    from .analytics.metrics import AnalyticsMetrics

    return AnalyticsMetrics


def initialize_analytics(config: dict[str, Any]) -> Any:
    """Initialize analytics (lazy import)"""
    from .analytics.metrics import initialize_analytics

    return initialize_analytics(config)
