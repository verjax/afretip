from typing import Any, Literal, Optional

import structlog

from ..analytics.metrics import collect_detection_data
from ..core.models import (
    ExtractedIOC,
    IOCClassification,
    IOCType,
    SuspiciousFinding,
    ThreatLevel,
    WazuhRawLog,
)
from ..enrichment.ioc_classifier import IOCClassifier
from ..enrichment.reputation_service import ReputationService
from ..enrichment.threat_intel_db import ThreatIntelDB

logger = structlog.get_logger(__name__)


class ThreatDetector:
    def __init__(self, config: Optional[dict[str, Any]] = None) -> None:
        self.config = config or {}
        processing_config = self.config.get("processing", {})

        # Detection thresholds
        self.confidence_threshold = processing_config.get("confidence_threshold", 0.6)
        self.novelty_threshold = processing_config.get("novelty_threshold", 0.7)
        self.pattern_detection_enabled = processing_config.get(
            "enable_pattern_detection", True
        )
        self.novelty_detection_enabled = processing_config.get(
            "enable_novelty_detection", True
        )

        # Initialize enrichment components
        self.ioc_classifier = IOCClassifier(self.config)
        self.threat_intel_db = ThreatIntelDB(self.config)
        self.reputation_service = ReputationService(self.config)

        # IOC frequency tracking for novelty detection
        self.ioc_frequency: dict[str, int] = {}
        self.total_logs_processed = 0

        logger.info(
            "Threat detector initialized",
            confidence_threshold=self.confidence_threshold,
            novelty_threshold=self.novelty_threshold,
            pattern_detection=self.pattern_detection_enabled,
            novelty_detection=self.novelty_detection_enabled,
        )

    async def detect_threats(
        self, iocs: list[ExtractedIOC], source_log: WazuhRawLog
    ) -> list[SuspiciousFinding]:
        """
        Main threat detection method using hybrid approach

        Combines:
        1. Pattern-based detection (suspicious behaviors)
        2. Novelty-based detection (rare/new IOCs)
        3. Threat intelligence correlation
        4. Reputation checking
        """

        findings: list[SuspiciousFinding] = []
        self.total_logs_processed += 1

        if not iocs:
            logger.debug("No IOCs to analyze for threats")
            return findings

        # Update IOC frequency tracking
        self._update_ioc_frequencies(iocs)

        # Process each IOC through hybrid detection
        for ioc in iocs:
            try:
                # Step 1: Update novelty scoring
                if self.novelty_detection_enabled:
                    ioc.novelty_score = self._calculate_novelty_score(ioc)
                    ioc.is_novel = ioc.novelty_score > self.novelty_threshold

                # Step 2: Hybrid classification
                classification = await self.ioc_classifier.classify_ioc(ioc, source_log)

                # Step 3: Generate finding if threat detected
                if (
                    classification.should_generate_rule
                    or classification.confidence >= self.confidence_threshold
                ):
                    finding = await self._create_suspicious_finding(
                        ioc, source_log, classification
                    )
                    findings.append(finding)

                    logger.info(
                        "Threat detected",
                        ioc_value=ioc.value,
                        ioc_type=ioc.type.value,
                        classification=classification.classification,
                        confidence=classification.confidence,
                        threat_level=classification.threat_level.value,
                    )

            except Exception as e:
                logger.error(
                    "Error processing IOC for threats", ioc=ioc.value, error=str(e)
                )
                continue

        # Step 4: Pattern-based detection (if enabled)
        if self.pattern_detection_enabled and findings:
            pattern_findings = await self._detect_suspicious_patterns(source_log, iocs)
            findings.extend(pattern_findings)

        # Collect detection metrics for research
        if findings:
            detection_time = 0.001  # Minimal time for immediate collection
            collect_detection_data(findings, detection_time)

        return findings

    def _update_ioc_frequencies(self, iocs: list[ExtractedIOC]) -> None:
        """Update frequency tracking for novelty detection"""
        for ioc in iocs:
            ioc_key = f"{ioc.type.value}:{ioc.value}"
            self.ioc_frequency[ioc_key] = self.ioc_frequency.get(ioc_key, 0) + 1

    def _calculate_novelty_score(self, ioc: ExtractedIOC) -> float:
        """Calculate novelty score based on frequency"""
        ioc_key = f"{ioc.type.value}:{ioc.value}"
        frequency = self.ioc_frequency.get(ioc_key, 0)

        if self.total_logs_processed == 0:
            return 1.0

        # Higher novelty score for less frequent IOCs
        relative_frequency = frequency / self.total_logs_processed
        novelty_score = max(0.0, 1.0 - (relative_frequency * 10))  # Scale factor of 10

        return min(novelty_score, 1.0)

    async def _create_suspicious_finding(
        self,
        ioc: ExtractedIOC,
        source_log: WazuhRawLog,
        classification: IOCClassification,
    ) -> SuspiciousFinding:
        """Create suspicious finding from classified IOC"""

        # Determine finding type based on classification - use proper literal types
        finding_type: Literal[
            "suspicious_pattern",
            "novel_ioc",
            "behavioral_anomaly",
            "hybrid_ioc_detection",
        ]
        if classification.classification == "malicious":
            finding_type = "novel_ioc"
        elif ioc.is_novel:
            finding_type = "novel_ioc"
        else:
            finding_type = "suspicious_pattern"

        # Combine reasoning
        reasoning_parts = [classification.reasoning]
        if ioc.is_novel:
            reasoning_parts.append(f"Novel IOC (novelty: {ioc.novelty_score:.3f})")

        reasoning = "; ".join(reasoning_parts)

        # Create details for rule generator
        details = {
            "patterns": [finding_type],
            "classification_type": classification.classification,
            "ioc_types": [ioc.type.value],
        }

        return SuspiciousFinding(
            finding_type=finding_type,
            confidence=classification.confidence,
            threat_level=classification.threat_level,
            description=f"Hybrid detection: {classification.classification} {ioc.type.value}",
            iocs=[ioc],
            source_log_hash=source_log.log_hash,
            reasoning=reasoning,
            pattern_matches=self._extract_pattern_matches(source_log),
            context={
                "classification": classification.classification,
                "hybrid_analysis": True,
            },
            details=details,
        )

    async def _detect_suspicious_patterns(
        self, source_log: WazuhRawLog, iocs: list[ExtractedIOC]
    ) -> list[SuspiciousFinding]:
        """Detect suspicious patterns in logs - simplified version"""

        findings = []
        log_text = source_log.full_log.lower()

        # Define suspicious patterns
        suspicious_patterns = {
            "powershell_obfuscation": [
                "powershell",
                "-encoded",
                "-enc",
                "-e ",
                "frombase64",
                "invoke-expression",
                "iex",
                "-windowstyle hidden",
            ],
            "living_off_land": [
                "certutil",
                "bitsadmin",
                "regsvr32",
                "rundll32",
                "mshta",
                "cscript",
                "wscript",
            ],
            "temp_file_creation": ["temp", "tmp", "appdata", "%temp%", "$env:temp"],
            "suspicious_network": [
                "download",
                "curl",
                "wget",
                "invoke-webrequest",
                "net use",
                "copy \\\\",
                "xcopy",
            ],
        }

        # Check for pattern matches
        pattern_matches = {}
        detected_patterns = []
        for pattern_name, keywords in suspicious_patterns.items():
            matches = sum(1 for keyword in keywords if keyword in log_text)
            if matches > 0:
                pattern_matches[pattern_name] = matches
                detected_patterns.append(pattern_name)

        # Create findings for significant pattern matches
        for pattern_name, match_count in pattern_matches.items():
            if match_count >= 2:  # Require at least 2 keyword matches
                confidence = min(0.5 + (match_count * 0.1), 0.9)

                # Create details for rule generator
                details = {
                    "patterns": [pattern_name],
                    "match_count": match_count,
                    "pattern_type": pattern_name,
                }

                finding = SuspiciousFinding(
                    finding_type="suspicious_pattern",
                    confidence=confidence,
                    threat_level=ThreatLevel.MEDIUM,
                    description=f"Suspicious {pattern_name.replace('_', ' ')} pattern detected",
                    iocs=iocs,
                    source_log_hash=source_log.log_hash,
                    reasoning=f"Pattern '{pattern_name}' matched {match_count} indicators",
                    pattern_matches=pattern_matches,
                    context={"pattern_type": pattern_name, "match_count": match_count},
                    details=details,
                )

                findings.append(finding)

        return findings

    async def _detect_adaptive_patterns(
            self, source_log: WazuhRawLog, iocs: list[ExtractedIOC]
    ) -> list[SuspiciousFinding]:
        """
        Advanced adaptive pattern detection for novel threats
        Analyzes all available log fields and IOCs for suspicious combinations
        """
        findings = []

        # Get comprehensive text for analysis
        all_text = source_log.get_all_text().lower()

        # Initialize scoring
        suspicion_score = 0.0
        detected_techniques = []
        threat_indicators = {}

        # 1. COMMAND EXECUTION ANALYSIS
        command_indicators = ["powershell", "cmd", "wscript", "cscript", "rundll32", "regsvr32"]
        if any(cmd in all_text for cmd in command_indicators):
            suspicion_score += 0.25
            detected_techniques.append("command_execution")

            # Enhanced obfuscation detection
            obfuscation_indicators = [
                "-enc", "-encodedcommand", "base64", "hidden", "bypass",
                "invoke-expression", "iex", "downloadstring", "webclient",
                "frombase64string", "convert::frombase64"
            ]
            obfuscation_count = sum(1 for obs in obfuscation_indicators if obs in all_text)
            if obfuscation_count >= 2:
                suspicion_score += 0.4
                detected_techniques.append("command_obfuscation")
                threat_indicators["obfuscation_methods"] = obfuscation_count

        # 2. PERSISTENCE MECHANISM ANALYSIS
        persistence_indicators = ["schtasks", "service", "registry", "startup", "run", "currentversion"]
        persistence_count = sum(1 for pers in persistence_indicators if pers in all_text)
        if persistence_count >= 1:
            suspicion_score += 0.3
            detected_techniques.append("persistence_attempt")
            threat_indicators["persistence_methods"] = persistence_count

            # Check for suspicious persistence locations
            suspicious_locations = ["programdata", "temp", "appdata", "public", "users\\\\public"]
            if any(loc in all_text for loc in suspicious_locations):
                suspicion_score += 0.2
                detected_techniques.append("suspicious_persistence_location")

        # 3. NETWORK ACTIVITY ANALYSIS
        network_indicators = ["download", "http", "https", "tcp", "connect", "socket", "webclient"]
        if any(net in all_text for net in network_indicators):
            suspicion_score += 0.2
            detected_techniques.append("network_activity")

            # Check for IOC domains/IPs in network activity
            network_iocs = [ioc for ioc in iocs if ioc.type in [IOCType.IP, IOCType.DOMAIN, IOCType.URL]]
            if network_iocs:
                suspicion_score += 0.25
                detected_techniques.append("suspicious_network_iocs")
                threat_indicators["network_iocs_count"] = len(network_iocs)

        # 4. FILE SYSTEM ACTIVITY ANALYSIS
        file_indicators = ["copy", "move", "xcopy", "robocopy", "download", "save", "write"]
        if any(file_ind in all_text for file_ind in file_indicators):
            file_iocs = [ioc for ioc in iocs if ioc.type == IOCType.FILE_PATH]
            if file_iocs:
                suspicion_score += 0.2
                detected_techniques.append("suspicious_file_activity")
                threat_indicators["file_iocs_count"] = len(file_iocs)

        # 5. HASH/MALWARE ANALYSIS
        hash_iocs = [ioc for ioc in iocs if ioc.type in [IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]]
        if hash_iocs:
            suspicion_score += 0.3
            detected_techniques.append("file_hash_detection")
            threat_indicators["hash_count"] = len(hash_iocs)

        # 6. REGISTRY ANALYSIS
        registry_indicators = ["hkey", "hklm", "hkcu", "currentversion\\\\run", "software\\\\microsoft"]
        registry_count = sum(1 for reg in registry_indicators if reg in all_text)
        if registry_count >= 1:
            suspicion_score += 0.25
            detected_techniques.append("registry_activity")
            threat_indicators["registry_indicators"] = registry_count

        # 7. PROCESS INJECTION/HOLLOWING INDICATORS
        injection_indicators = ["inject", "hollow", "migrate", "createremotethread", "virtualallocex"]
        if any(inj in all_text for inj in injection_indicators):
            suspicion_score += 0.4
            detected_techniques.append("process_injection")

        # 8. LIVING OFF THE LAND TECHNIQUES
        lolbas_tools = ["certutil", "bitsadmin", "wmic", "mshta", "installutil", "msbuild"]
        lolbas_count = sum(1 for tool in lolbas_tools if tool in all_text)
        if lolbas_count >= 1:
            suspicion_score += 0.3
            detected_techniques.append("living_off_land")
            threat_indicators["lolbas_tools"] = lolbas_count

        # 9. NOVEL IOC BOOST
        novel_iocs = [ioc for ioc in iocs if ioc.is_novel and ioc.novelty_score > 0.7]
        if novel_iocs:
            suspicion_score += 0.3
            detected_techniques.append("novel_indicators")
            threat_indicators["novel_ioc_count"] = len(novel_iocs)

        # 10. HIGH-CONFIDENCE IOC BOOST
        high_confidence_iocs = [ioc for ioc in iocs if ioc.confidence > 0.8]
        if high_confidence_iocs:
            suspicion_score += 0.2
            threat_indicators["high_confidence_iocs"] = len(high_confidence_iocs)

        # GENERATE FINDING IF THRESHOLD MET
        # Use configurable threshold from config
        threshold = self.config.get("processing", {}).get("adaptive_detection_threshold", 0.5)

        if suspicion_score >= threshold:
            # Determine threat level based on score
            if suspicion_score >= 0.8:
                threat_level = ThreatLevel.CRITICAL
            elif suspicion_score >= 0.6:
                threat_level = ThreatLevel.HIGH
            elif suspicion_score >= 0.4:
                threat_level = ThreatLevel.MEDIUM
            else:
                threat_level = ThreatLevel.LOW

            # Create comprehensive finding
            finding = SuspiciousFinding(
                finding_type="behavioral_anomaly",
                confidence=min(suspicion_score, 1.0),
                threat_level=threat_level,
                description=f"Adaptive threat detection: {', '.join(detected_techniques[:3])}{'...' if len(detected_techniques) > 3 else ''}",
                iocs=iocs,
                source_log_hash=source_log.log_hash,
                reasoning=f"Multiple suspicious techniques detected (score: {suspicion_score:.2f}): {', '.join(detected_techniques)}",
                pattern_matches=dict.fromkeys(detected_techniques, 1),
                context={
                    "adaptive_detection": True,
                    "suspicion_score": suspicion_score,
                    "techniques_count": len(detected_techniques),
                    "threat_indicators": threat_indicators,
                },
                details={
                    "techniques": detected_techniques,
                    "suspicion_score": suspicion_score,
                    "adaptive_analysis": True,
                    "indicators": threat_indicators,
                }
            )
            findings.append(finding)

            logger.info(
                "Adaptive threat detection triggered",
                score=suspicion_score,
                techniques=detected_techniques,
                ioc_count=len(iocs),
                threat_level=threat_level.value,
                source_log_hash=source_log.log_hash
            )

        return findings

    def _extract_pattern_matches(self, source_log: WazuhRawLog) -> dict[str, int]:
        """Extract basic pattern matches from log"""
        log_text = source_log.full_log.lower()

        # Basic pattern counting
        patterns = {
            "powershell": log_text.count("powershell"),
            "cmd": log_text.count("cmd"),
            "temp": log_text.count("temp"),
            "download": log_text.count("download"),
            "execute": log_text.count("execute"),
            "hidden": log_text.count("hidden"),
            "encoded": log_text.count("encoded") + log_text.count("base64"),
        }

        # Only return patterns with matches
        return {k: v for k, v in patterns.items() if v > 0}

    async def _analyze_behavioral_patterns(
        self, source_log: WazuhRawLog, iocs: list[ExtractedIOC]
    ) -> list[SuspiciousFinding]:
        """Simplified behavioral analysis"""

        findings = []
        log_text = source_log.full_log.lower()

        # Check for behavioral anomalies
        behavior_indicators = 0
        behavior_descriptions = []

        # Process execution patterns
        if any(
            term in log_text for term in ["powershell", "cmd", "wscript", "cscript"]
        ):
            behavior_indicators += 1
            behavior_descriptions.append("Process execution detected")

        # File system activity
        if any(term in log_text for term in ["temp", "appdata", "startup"]):
            behavior_indicators += 1
            behavior_descriptions.append("Suspicious file system activity")

        # Network activity
        if any(term in log_text for term in ["download", "upload", "http", "ftp"]):
            behavior_indicators += 1
            behavior_descriptions.append("Network communication detected")

        # Create behavioral finding if significant activity detected
        if behavior_indicators >= 2:
            confidence = min(0.4 + (behavior_indicators * 0.15), 0.8)

            # Create details for rule generator
            details = {
                "patterns": ["behavioral_anomaly"],
                "behavior_count": behavior_indicators,
                "behaviors": behavior_descriptions,
            }

            finding = SuspiciousFinding(
                finding_type="behavioral_anomaly",
                confidence=confidence,
                threat_level=ThreatLevel.MEDIUM,
                description="Behavioral anomaly detected",
                iocs=iocs,
                source_log_hash=source_log.log_hash,
                reasoning=f"Multiple behavioral indicators: {', '.join(behavior_descriptions)}",
                pattern_matches={"behavioral_indicators": behavior_indicators},
                context={
                    "behavior_count": behavior_indicators,
                    "behaviors": behavior_descriptions,
                },
                details=details,
            )

            findings.append(finding)

        return findings

    def get_detection_statistics(self) -> dict[str, Any]:
        """Get threat detection statistics"""
        return {
            "total_logs_processed": self.total_logs_processed,
            "unique_iocs_tracked": len(self.ioc_frequency),
            "configuration": {
                "confidence_threshold": self.confidence_threshold,
                "novelty_threshold": self.novelty_threshold,
                "pattern_detection_enabled": self.pattern_detection_enabled,
                "novelty_detection_enabled": self.novelty_detection_enabled,
            },
            "threat_intelligence": self.threat_intel_db.get_statistics(),
            "reputation_service": self.reputation_service.get_cache_stats(),
            "classifier_stats": self.ioc_classifier.get_classification_statistics(),
        }

    def reset_frequency_tracking(self) -> None:
        """Reset IOC frequency tracking"""
        self.ioc_frequency.clear()
        self.total_logs_processed = 0
        logger.info("IOC frequency tracking reset")
