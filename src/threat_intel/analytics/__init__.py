from typing import Any

__all__ = [
    "initialize_analytics",
    "get_analytics",
    "collect_ioc_data",
    "collect_classification_data",
    "collect_detection_data",
    "collect_performance_data",
    "get_analytics_metrics_class",
]


# Lazy imports to avoid circular dependency issues
def initialize_analytics(config: dict[str, Any]) -> Any:
    """Initialize analytics metrics"""
    from .metrics import initialize_analytics

    return initialize_analytics(config)


def get_analytics() -> Any:
    """Get analytics instance"""
    from .metrics import get_analytics

    return get_analytics()


def collect_ioc_data(iocs: Any, processing_time: float) -> Any:
    """Collect IOC data"""
    from .metrics import collect_ioc_data

    return collect_ioc_data(iocs, processing_time)


def collect_classification_data(ioc: Any, classification: Any, **kwargs: Any) -> Any:
    """Collect classification data"""
    from .metrics import collect_classification_data

    return collect_classification_data(ioc, classification, **kwargs)


def collect_detection_data(findings: Any, detection_time: float) -> Any:
    """Collect detection data"""
    from .metrics import collect_detection_data

    return collect_detection_data(findings, detection_time)


def collect_performance_data(logs_processed: int, processing_time: float) -> Any:
    """Collect performance data"""
    from .metrics import collect_performance_data

    return collect_performance_data(logs_processed, processing_time)


def get_analytics_metrics_class() -> Any:
    """Get AnalyticsMetrics class (lazy import)"""
    from .metrics import AnalyticsMetrics

    return AnalyticsMetrics
