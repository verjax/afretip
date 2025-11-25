from typing import Any

from .models import (
    ConfigurationStatus,
    DeploymentResult,
    ExtractedIOC,
    IOCClassification,
    IOCType,
    ProcessingStats,
    QueueStatus,
    ReputationData,
    SuspiciousFinding,
    ThreatLevel,
    ValidationResult,
    WazuhRawLog,
    WazuhRule,
)

# ProcessingEngine import is delayed to avoid circular dependency with analytics
__all__ = [
    "ExtractedIOC",
    "IOCType",
    "SuspiciousFinding",
    "ThreatLevel",
    "WazuhRawLog",
    "WazuhRule",
    "IOCClassification",
    "ReputationData",
    "DeploymentResult",
    "ProcessingStats",
    "QueueStatus",
    "ValidationResult",
    "ConfigurationStatus",
    "get_processing_engine",
]


def get_processing_engine() -> Any:
    """Get ProcessingEngine class (lazy import to avoid circular dependency)"""
    from .engine import ProcessingEngine

    return ProcessingEngine
