from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class IOCType(Enum):
    """Types of Indicators of Compromise"""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    FILE_PATH = "file_path"
    REGISTRY_KEY = "registry_key"
    PROCESS_NAME = "process_name"
    COMMAND_LINE = "command_line"


class ThreatLevel(Enum):
    """Threat severity levels"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class WazuhRawLog(BaseModel):
    """Raw log data from Wazuh"""

    timestamp: Optional[datetime] = None
    rule_id: Optional[int] = None
    rule_level: Optional[int] = None
    description: Optional[str] = None
    full_log: str
    source_system: Optional[str] = None
    source_ip: Optional[str] = None
    user: Optional[str] = None
    agent: Optional[dict[str, Any]] = None
    location: Optional[str] = None
    predecoder: Optional[dict[str, Any]] = None
    decoder: Optional[dict[str, Any]] = None
    log_hash: str = Field(default_factory=lambda: uuid4().hex)

    def model_post_init(self, __context: Any) -> None:
        if self.agent and "name" in self.agent:
            self.source_system = self.agent["name"]

    # Enhanced field storage for comprehensive analysis
    raw_data: dict[str, Any] = Field(default_factory=dict)
    flattened_fields: dict[str, Any] = Field(default_factory=dict)

    def get_field(self, field_path: str) -> Optional[Any]:
        """Get any field using dot notation: 'win.eventdata.commandLine'"""
        return self.flattened_fields.get(field_path)

    def get_all_text(self) -> str:
        """Get all textual content for comprehensive analysis"""
        text_parts = [self.full_log]

        # Add all string values from flattened fields
        for value in self.flattened_fields.values():
            if isinstance(value, str) and value.strip():
                text_parts.append(value)

        return " ".join(text_parts)

    def dict(self, **kwargs: Any) -> dict[str, Any]:
        """Convert to dictionary with proper datetime serialization"""
        data = super().dict(**kwargs)
        if self.timestamp:
            data["timestamp"] = self.timestamp.isoformat()
        return data

class ExtractedIOC(BaseModel):
    """Extracted Indicator of Compromise"""

    id: str = Field(default_factory=lambda: uuid4().hex)
    type: IOCType
    value: str
    confidence: float = Field(ge=0.0, le=1.0)
    context: str
    source_log_hash: str
    extraction_method: str = "regex"
    threat_score: float = Field(default=0.0, ge=0.0, le=1.0)
    novelty_score: float = Field(default=0.0, ge=0.0, le=1.0)
    is_novel: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IOCClassification(BaseModel):
    """Result of IOC classification"""

    classification: Literal["benign", "suspicious", "malicious"]
    confidence: float = Field(ge=0.0, le=1.0)
    should_generate_rule: bool
    threat_level: ThreatLevel
    reasoning: str


class SuspiciousFinding(BaseModel):
    """A suspicious security finding"""

    id: str = Field(default_factory=lambda: uuid4().hex)
    finding_type: Literal[
        "suspicious_pattern", "novel_ioc", "behavioral_anomaly", "hybrid_ioc_detection"
    ]
    confidence: float = Field(ge=0.0, le=1.0)
    threat_level: ThreatLevel
    description: str
    iocs: list[ExtractedIOC]
    source_log_hash: str
    reasoning: str
    pattern_matches: dict[str, int] = Field(default_factory=dict)
    context: dict[str, Any] = Field(default_factory=dict)
    details: dict[str, Any] = Field(default_factory=dict)  # Added for rule generator
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ReputationData(BaseModel):
    """Reputation data for an IOC"""

    service: str
    ioc_value: str
    is_malicious: bool
    reputation_score: float = Field(ge=0.0, le=1.0)
    detections: int = 0
    total_engines: int = 0
    timestamp: Optional[str] = None
    cached: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class WazuhRule(BaseModel):
    rule_id: int
    level: int
    description: str
    groups: list[str]
    regex: Optional[str] = None
    rule_xml: Optional[str] = None
    source_finding_id: str
    ioc_values: list[str] = Field(default_factory=list)
    threat_level: Optional[ThreatLevel] = None
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_wazuh_xml(self) -> str:
        """Convert rule to Wazuh XML format"""
        # Build the rule XML
        rule_parts = [
            f'<rule id="{self.rule_id}" level="{self.level}">',
            f"  <description>{self.description}</description>",
        ]

        # Add regex if present
        if self.regex:
            rule_parts.append(f"  <regex>{self.regex}</regex>")

        # Add groups
        if self.groups:
            groups_str = ",".join(self.groups)
            rule_parts.append(f"  <group>{groups_str}</group>")

        rule_parts.append("</rule>")

        return "\n".join(rule_parts)

    def dict(self, **kwargs: Any) -> dict[str, Any]:
        """Convert to dictionary with proper datetime serialization"""
        data = super().dict(**kwargs)
        data["generated_at"] = self.generated_at.isoformat()
        return data


# Research and statistics models
class StatisticType(Enum):
    """Types of statistics collected"""

    IOC_EXTRACTION = "ioc_extraction"
    THREAT_DETECTION = "threat_detection"
    RULE_GENERATION = "rule_generation"
    RULE_DEPLOYMENT = "rule_deployment"
    SYSTEM_PERFORMANCE = "system_performance"
    ERROR_TRACKING = "error_tracking"


class ResearchSession(BaseModel):
    """Research session metadata"""

    session_id: str = Field(default_factory=lambda: uuid4().hex)
    session_name: str
    start_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    description: Optional[str] = None
    configuration: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ResearchMetric(BaseModel):
    """Individual analytics metric"""

    metric_id: str = Field(default_factory=lambda: uuid4().hex)
    session_id: str
    metric_type: StatisticType
    component: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    data: dict[str, Any]


class IOCExtractionStats(BaseModel):
    """Statistics for IOC extraction"""

    total_logs_processed: int = 0
    total_iocs_extracted: int = 0
    iocs_by_type: dict[str, int] = Field(default_factory=dict)
    extraction_rates: dict[str, float] = Field(default_factory=dict)
    confidence_distribution: dict[str, int] = Field(default_factory=dict)
    processing_times: list[float] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class ThreatDetectionStats(BaseModel):
    """Statistics for threat detection"""

    total_findings: int = 0
    findings_by_type: dict[str, int] = Field(default_factory=dict)
    threat_levels: dict[str, int] = Field(default_factory=dict)
    pattern_matches: dict[str, int] = Field(default_factory=dict)
    confidence_distribution: dict[str, int] = Field(default_factory=dict)
    detection_times: list[float] = Field(default_factory=list)
    novel_threats_found: int = 0


class RuleGenerationStats(BaseModel):
    """Statistics for rule generation"""

    total_rules_generated: int = 0
    rules_by_threat_level: dict[str, int] = Field(default_factory=dict)
    rules_by_ioc_type: dict[str, int] = Field(default_factory=dict)
    generation_times: list[float] = Field(default_factory=list)
    validation_results: dict[str, int] = Field(default_factory=dict)


class RuleDeploymentStats(BaseModel):
    """Statistics for rule deployment"""

    total_deployments: int = 0
    successful_deployments: int = 0
    failed_deployments: int = 0
    deployment_times: list[float] = Field(default_factory=list)
    deployment_errors: list[str] = Field(default_factory=list)


class SystemPerformanceStats(BaseModel):
    """System performance statistics"""

    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_usage: float = 0.0
    throughput: dict[str, float] = Field(default_factory=dict)
    queue_sizes: dict[str, int] = Field(default_factory=dict)
    processing_latency: dict[str, float] = Field(default_factory=dict)


class ErrorTrackingStats(BaseModel):
    """Error tracking statistics"""

    total_errors: int = 0
    errors_by_component: dict[str, int] = Field(default_factory=dict)
    errors_by_type: dict[str, int] = Field(default_factory=dict)
    error_rates: dict[str, float] = Field(default_factory=dict)
    recent_errors: list[dict[str, Any]] = Field(default_factory=list)


class DeploymentMetrics(BaseModel):
    """Deployment analytics metrics"""

    total_deployments: int = 0
    successful_deployments: int = 0
    failed_deployments: int = 0
    average_deployment_time: float = 0.0
    deployment_success_rate: float = 0.0
    rules_deployed_total: int = 0
    backup_creations: int = 0
    deployment_errors: list[str] = Field(default_factory=list)


class DeploymentResult(BaseModel):
    """Result of rule deployment operation"""

    success: bool
    rule_id: Optional[int] = None
    message: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    deployment_time: float = 0.0
    errors: list[str] = Field(default_factory=list)


class ProcessingStats(BaseModel):
    """Processing pipeline statistics"""

    logs_processed: int = 0
    iocs_extracted: int = 0
    threats_detected: int = 0
    rules_generated: int = 0
    rules_deployed: int = 0
    processing_errors: int = 0
    start_time: Optional[datetime] = None
    uptime_seconds: float = 0.0


class QueueStatus(BaseModel):
    """Queue status information"""

    log_queue_size: int = 0
    log_queue_capacity: int = 0
    finding_queue_size: int = 0
    finding_queue_capacity: int = 0


class ValidationResult(BaseModel):
    """Result of rule validation"""

    is_valid: bool
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    suggestions: list[str] = Field(default_factory=list)


class ConfigurationStatus(BaseModel):
    """Configuration status information"""

    component: str
    status: Literal["loaded", "error", "missing"]
    details: str
    path: Optional[str] = None
