import collections
import csv
import json
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import psutil
import structlog

from ..core.models import ExtractedIOC, IOCClassification, SuspiciousFinding, WazuhRule

logger = structlog.get_logger(__name__)


class AnalyticsMetrics:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        analytics_config = config.get("analytics", {})

        # Output directory for analytics data
        self.output_dir = Path(
            analytics_config.get("output_dir", "/var/lib/afretip/analytics")
        )
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Session identifier
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Simple in-memory counters for real-time stats
        self.counters: dict[str, int] = {
            "logs_processed": 0,
            "iocs_extracted": 0,
            "threat_intel_hits": 0,
            "reputation_confirmations": 0,
            "novel_iocs_found": 0,
            "rules_generated": 0,
            "processing_errors": 0,
        }

        # Type-specific counters - Fixed: Ensure string keys
        self.iocs_by_type: collections.defaultdict[str, int] = defaultdict(int)
        self.classifications: collections.defaultdict[str, int] = defaultdict(int)

        # Performance tracking (last 100 measurements)
        self.performance_history: dict[str, collections.deque[float]] = {
            "processing_times": deque(maxlen=100),
            "classification_times": deque(maxlen=100),
            "detection_times": deque(maxlen=100),
        }

        self.system_metrics: collections.deque[dict[str, Any]] = deque(maxlen=50)

        # Data collection for analytics and research
        self.analytics_data: dict[str, list[dict[str, Any]]] = {
            "ioc_classifications": [],
            "detection_results": [],
            "hybrid_analysis": [],
            "performance_samples": [],
            "deployment_results": [],
        }

        # Session start time
        self.session_start = time.time()

        logger.info(
            "Analytics metrics initialized",
            session_id=self.session_id,
            output_dir=str(self.output_dir),
        )

    def collect_ioc_metrics(
        self, iocs: list[ExtractedIOC], processing_time: float
    ) -> None:
        """Collect IOC extraction metrics"""
        self.counters["iocs_extracted"] += len(iocs)
        self.performance_history["processing_times"].append(processing_time)

        # Count by type - Fixed: Ensure string keys
        for ioc in iocs:
            ioc_type_str = str(ioc.type.value)  # Explicit string conversion
            self.iocs_by_type[ioc_type_str] += 1

            # Store for analytics analysis
            self.analytics_data["ioc_classifications"].append(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "ioc_type": ioc_type_str,
                    "ioc_value": ioc.value,
                    "extraction_confidence": ioc.confidence,
                    "threat_score": ioc.threat_score,
                    "novelty_score": ioc.novelty_score,
                    "is_novel": ioc.is_novel,
                    "context": ioc.context,
                    "processing_time_ms": processing_time * 1000,
                }
            )

    def collect_classification_metrics(
        self,
        ioc: ExtractedIOC,
        classification: IOCClassification,
        threat_intel_hit: bool = False,
        reputation_score: float = 0.0,
    ) -> None:
        """Collect hybrid classification metrics - CORE ANALYTICS DATA"""

        # Fixed: Ensure we use string values as dictionary keys
        classification_str = str(
            classification.classification
        )  # Explicit string conversion
        self.classifications[classification_str] += 1

        if threat_intel_hit:
            self.counters["threat_intel_hits"] += 1

        if reputation_score > 0.3:  # Significant reputation score
            self.counters["reputation_confirmations"] += 1

        if ioc.is_novel:
            self.counters["novel_iocs_found"] += 1

        # Store detailed hybrid analysis data
        self.analytics_data["hybrid_analysis"].append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "ioc_type": str(ioc.type.value),  # Explicit string conversion
                "ioc_value": ioc.value,
                "base_confidence": ioc.confidence,
                "threat_score": ioc.threat_score,
                "novelty_score": ioc.novelty_score,
                "is_novel": ioc.is_novel,
                "classification": classification_str,  # Use string variable
                "final_confidence": classification.confidence,
                "threat_level": str(
                    classification.threat_level.value
                ),  # Explicit string conversion
                "should_generate_rule": classification.should_generate_rule,
                "threat_intel_hit": threat_intel_hit,
                "reputation_score": reputation_score,
                "reasoning": classification.reasoning,
            }
        )

    def collect_detection_metrics(
        self, findings: list[SuspiciousFinding], detection_time: float
    ) -> None:
        """Collect threat detection metrics"""
        self.performance_history["detection_times"].append(detection_time)

        for finding in findings:
            self.analytics_data["detection_results"].append(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "finding_type": str(
                        finding.finding_type
                    ),  # Explicit string conversion
                    "confidence": finding.confidence,
                    "threat_level": str(
                        finding.threat_level.value
                    ),  # Explicit string conversion
                    "ioc_count": len(finding.iocs),
                    "pattern_matches": len(finding.pattern_matches),
                    "detection_time_ms": detection_time * 1000,
                    "reasoning": finding.reasoning,
                }
            )

    def collect_performance_metrics(
        self, logs_processed: int, processing_time: float
    ) -> None:
        """Collect processing performance metrics"""
        self.counters["logs_processed"] += logs_processed

        # Sample system performance periodically
        try:
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()

            system_metric = {
                "timestamp": time.time(),
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_used_mb": memory.used / (1024 * 1024),
            }
            self.system_metrics.append(system_metric)

            # Store sample for analysis
            if len(self.analytics_data["performance_samples"]) < 1000:  # Limit samples
                session_time = time.time() - self.session_start
                logs_per_second = (
                    self.counters["logs_processed"] / session_time
                    if session_time > 0
                    else 0.0
                )
                iocs_per_second = (
                    self.counters["iocs_extracted"] / session_time
                    if session_time > 0
                    else 0.0
                )

                self.analytics_data["performance_samples"].append(
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "session_time_seconds": session_time,
                        "logs_per_second": logs_per_second,
                        "iocs_per_second": iocs_per_second,
                        "cpu_percent": cpu_percent,
                        "memory_percent": memory.percent,
                        "processing_time_ms": processing_time * 1000,
                    }
                )

        except Exception as e:
            logger.warning("Failed to collect system metrics", error=str(e))

    def collect_rule_metrics(self, rule: WazuhRule, generation_time: float) -> None:
        """Collect rule generation metrics"""
        self.counters["rules_generated"] += 1

    def record_processing_error(self, error_type: str = "unknown") -> None:
        """Record processing error"""
        self.counters["processing_errors"] += 1

    def get_realtime_stats(self) -> dict[str, Any]:
        """Get real-time statistics for CLI show-stats command"""
        session_time = time.time() - self.session_start

        # Calculate rates
        logs_per_second = (
            self.counters["logs_processed"] / session_time if session_time > 0 else 0.0
        )
        iocs_per_second = (
            self.counters["iocs_extracted"] / session_time if session_time > 0 else 0.0
        )

        # Calculate averages from recent performance data
        recent_processing_times = list(self.performance_history["processing_times"])
        avg_processing_time = (
            sum(recent_processing_times) / len(recent_processing_times)
            if recent_processing_times
            else 0.0
        )

        recent_detection_times = list(self.performance_history["detection_times"])
        avg_detection_time = (
            sum(recent_detection_times) / len(recent_detection_times)
            if recent_detection_times
            else 0.0
        )

        return {
            "session_info": {
                "session_id": self.session_id,
                "runtime_seconds": session_time,
                "runtime_hours": session_time / 3600,
            },
            "processing_stats": {
                "logs_processed": self.counters["logs_processed"],
                "iocs_extracted": self.counters["iocs_extracted"],
                "rules_generated": self.counters["rules_generated"],
                "processing_errors": self.counters["processing_errors"],
            },
            "performance": {
                "logs_per_second": logs_per_second,
                "iocs_per_second": iocs_per_second,
                "avg_processing_time_ms": avg_processing_time * 1000,
                "avg_detection_time_ms": avg_detection_time * 1000,
            },
            "ioc_analysis": {
                "iocs_by_type": dict(self.iocs_by_type),
                "classifications": dict(self.classifications),
                "novel_iocs_found": self.counters["novel_iocs_found"],
                "threat_intel_hits": self.counters["threat_intel_hits"],
                "reputation_confirmations": self.counters["reputation_confirmations"],
            },
        }

    def generate_analytics_report(self) -> dict[str, Any]:
        """Generate analytics report for generate-report CLI command"""
        stats = self.get_realtime_stats()

        # Add summary analysis
        total_iocs = self.counters["iocs_extracted"]
        novel_rate = (
            (self.counters["novel_iocs_found"] / total_iocs * 100)
            if total_iocs > 0
            else 0.0
        )
        threat_intel_rate = (
            (self.counters["threat_intel_hits"] / total_iocs * 100)
            if total_iocs > 0
            else 0.0
        )

        analytics_insights = {
            "hybrid_detection_effectiveness": {
                "total_iocs_analyzed": total_iocs,
                "novel_detection_rate_percent": novel_rate,
                "threat_intel_hit_rate_percent": threat_intel_rate,
                "classification_distribution": dict(self.classifications),
            },
            "analytics_data_collected": {
                "ioc_classification_records": len(
                    self.analytics_data["ioc_classifications"]
                ),
                "hybrid_analysis_records": len(self.analytics_data["hybrid_analysis"]),
                "detection_result_records": len(
                    self.analytics_data["detection_results"]
                ),
                "performance_samples": len(self.analytics_data["performance_samples"]),
            },
        }

        # Combine with real-time stats
        stats["analytics_insights"] = analytics_insights
        return stats

    def collect_deployment_metrics(
        self,
        rules: list[WazuhRule],
        deployment_result: dict[str, Any],
        deployment_time: float,
    ) -> None:
        """Collect rule deployment metrics"""
        for rule in rules:
            self.analytics_data["deployment_results"].append(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "rule_id": rule.rule_id,
                    "rule_level": rule.level,
                    "threat_level": rule.threat_level.value
                    if rule.threat_level
                    else "unknown",
                    "deployment_success": deployment_result.get("success", False),
                    "deployment_time_ms": deployment_time * 1000,
                    "rules_deployed_count": deployment_result.get("rules_deployed", 0),
                    "backup_created": deployment_result.get("backup_created", False),
                    "error_message": deployment_result.get("error", ""),
                    "file_path": deployment_result.get("file_path", ""),
                    "source_finding_id": rule.source_finding_id,
                }
            )

    def export_analytics_data(self, format: str = "csv") -> dict[str, str]:
        """Export analytics data for analysis"""
        exported_files: dict[str, str] = {}

        try:
            if format.lower() == "csv":
                # Export IOC classifications
                ioc_file = (
                    self.output_dir / f"ioc_classifications_{self.session_id}.csv"
                )
                self._export_to_csv(
                    self.analytics_data["ioc_classifications"], ioc_file
                )
                exported_files["ioc_classifications"] = str(ioc_file)

                # Export hybrid analysis
                hybrid_file = self.output_dir / f"hybrid_analysis_{self.session_id}.csv"
                self._export_to_csv(self.analytics_data["hybrid_analysis"], hybrid_file)
                exported_files["hybrid_analysis"] = str(hybrid_file)

                # Export detection results
                detection_file = (
                    self.output_dir / f"detection_results_{self.session_id}.csv"
                )
                self._export_to_csv(
                    self.analytics_data["detection_results"], detection_file
                )
                exported_files["detection_results"] = str(detection_file)

                # Export performance samples
                perf_file = self.output_dir / f"performance_{self.session_id}.csv"
                self._export_to_csv(
                    self.analytics_data["performance_samples"], perf_file
                )
                exported_files["performance"] = str(perf_file)

            elif format.lower() == "json":
                # Export as single JSON file
                json_file = self.output_dir / f"analytics_data_{self.session_id}.json"
                with open(json_file, "w") as f:
                    json.dump(self.analytics_data, f, indent=2)
                exported_files["analytics_data"] = str(json_file)

            logger.info("Analytics data exported", files=exported_files)
            return exported_files

        except Exception as e:
            logger.error("Failed to export analytics data", error=str(e))
            return {"error": str(e)}

    def _export_to_csv(self, data: list[dict[str, Any]], filename: Path) -> None:
        """Export data list to CSV file"""
        if not data:
            return

        with open(filename, "w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)


# Global instance (simple singleton pattern for easy access)
_analytics_instance: Optional[AnalyticsMetrics] = None


def initialize_analytics(config: dict[str, Any]) -> AnalyticsMetrics:
    """Initialize global analytics instance"""
    global _analytics_instance
    _analytics_instance = AnalyticsMetrics(config)
    return _analytics_instance


def get_analytics() -> Optional[AnalyticsMetrics]:
    """Get global analytics instance"""
    return _analytics_instance


# Convenience functions for easy integration
def collect_ioc_data(iocs: list[ExtractedIOC], processing_time: float) -> None:
    """Convenience function to collect IOC metrics"""
    if _analytics_instance:
        _analytics_instance.collect_ioc_metrics(iocs, processing_time)


def collect_classification_data(
    ioc: ExtractedIOC, classification: IOCClassification, **kwargs: Any
) -> None:
    """Convenience function to collect classification metrics"""
    if _analytics_instance:
        _analytics_instance.collect_classification_metrics(
            ioc, classification, **kwargs
        )


def collect_detection_data(
    findings: list[SuspiciousFinding], detection_time: float
) -> None:
    """Convenience function to collect detection metrics"""
    if _analytics_instance:
        _analytics_instance.collect_detection_metrics(findings, detection_time)


def collect_performance_data(logs_processed: int, processing_time: float) -> None:
    """Convenience function to collect performance metrics"""
    if _analytics_instance:
        _analytics_instance.collect_performance_metrics(logs_processed, processing_time)
