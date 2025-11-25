import ipaddress
from typing import Any, Literal, Optional

import structlog

from ..analytics.metrics import collect_classification_data
from ..core.models import (
    ExtractedIOC,
    IOCClassification,
    IOCType,
    ReputationData,
    ThreatLevel,
    WazuhRawLog,
)
from .reputation_service import ReputationService
from .threat_intel_db import ThreatIntelDB

logger = structlog.get_logger(__name__)


class IOCClassifier:
    """Enhanced hybrid IOC classifier with configurable whitelist support"""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        processing_config = config.get("processing", {})

        # Classification thresholds
        self.confidence_threshold = processing_config.get("confidence_threshold", 0.6)
        self.novelty_threshold = processing_config.get("novelty_threshold", 0.7)
        self.reputation_confirmation_threshold = processing_config.get(
            "reputation_confirmation_threshold", 0.3
        )

        # Initialize components
        self.threat_intel_db = ThreatIntelDB(config)
        self.reputation_service = ReputationService(config)

        # Load whitelist (built-in + optional custom from config)
        self.whitelist = self._load_whitelist()

        logger.info(
            "IOC Classifier initialized with hybrid detection",
            whitelist_domains=len(self.whitelist["domains"]),
            whitelist_ips=len(self.whitelist["ips"]),
            whitelist_processes=len(self.whitelist["processes"]),
        )

    def _load_whitelist(self) -> dict[str, set[str]]:
        """Load whitelist from config + built-in defaults"""

        # Built-in defaults (always included)
        whitelist = {
            "domains": {
                "microsoft.com",
                "google.com",
                "amazon.com",
                "cloudflare.com",
                "office.com",
                "live.com",
                "outlook.com",
                "github.com",
                "windows.com",
                "office365.com",
                "microsoftonline.com",
                "azure.com",
                "azurewebsites.net",
            },
            "ips": {"127.0.0.1", "0.0.0.0", "255.255.255.255", "8.8.8.8", "1.1.1.1"},
            "processes": set(),
        }

        # Check if custom whitelist is enabled
        config_whitelist = self.config.get("whitelist", {})
        whitelist_enabled = config_whitelist.get("enabled", True)  # Default to enabled

        if not whitelist_enabled:
            logger.info("Custom whitelist disabled - using built-in defaults only")
            return whitelist

        logger.info("Custom whitelist enabled - loading from configuration")

        # Add custom domains
        custom_domains = config_whitelist.get("custom_domains", [])
        for domain in custom_domains:
            if isinstance(domain, str) and domain.strip():
                whitelist["domains"].add(domain.lower().strip())

        # Add custom IPs (handle CIDR notation)
        custom_ips = config_whitelist.get("custom_ips", [])
        for ip_or_cidr in custom_ips:
            if isinstance(ip_or_cidr, str) and ip_or_cidr.strip():
                whitelist["ips"].add(ip_or_cidr.strip())

        # Add custom processes
        custom_processes = config_whitelist.get("custom_processes", [])
        for process in custom_processes:
            if isinstance(process, str) and process.strip():
                whitelist["processes"].add(process.lower().strip())

        logger.info(
            "Whitelist loaded",
            total_domains=len(whitelist["domains"]),
            total_ips=len(whitelist["ips"]),
            total_processes=len(whitelist["processes"]),
            custom_domains_added=len(custom_domains),
            custom_ips_added=len(custom_ips),
            custom_processes_added=len(custom_processes),
        )

        return whitelist

    async def classify_ioc(
        self, ioc: ExtractedIOC, source_log: WazuhRawLog
    ) -> IOCClassification:
        """
        Combines:
        1. Whitelist checking (enhanced with config support)
        2. Threat intelligence database lookup
        3. Reputation service checking
        4. IOC characteristics analysis
        """

        # Step 1: Check whitelist first (enhanced)
        if self._is_whitelisted(ioc):
            return IOCClassification(
                classification="benign",
                confidence=0.9,
                should_generate_rule=False,
                threat_level=ThreatLevel.LOW,
                reasoning="IOC found in whitelist (built-in or custom)",
            )

        # Step 2: Check threat intelligence database
        threat_intel_result = self.threat_intel_db.is_malicious(ioc.value, ioc.type)
        threat_intel_hit = threat_intel_result["is_malicious"]

        # Check reputation
        reputation_data = await self.reputation_service.check_reputation(
            ioc.value, ioc.type
        )
        reputation_score = reputation_data.reputation_score if reputation_data else 0.0

        # Perform hybrid analysis
        classification = self._perform_hybrid_analysis(ioc, source_log, reputation_data)

        # 🎯 COLLECT CORE RESEARCH DATA
        collect_classification_data(
            ioc=ioc,
            classification=classification,
            threat_intel_hit=threat_intel_hit,
            reputation_score=reputation_score,
        )

        return classification

    def _perform_hybrid_analysis(
        self,
        ioc: ExtractedIOC,
        source_log: WazuhRawLog,
        reputation_data: Optional[ReputationData],
    ) -> IOCClassification:
        """
        Core hybrid analysis combining multiple factors
        This is the main research contribution
        """

        # Base confidence from IOC extraction
        confidence = ioc.confidence

        # Factor 1: Novelty scoring
        novelty_boost = 0.0
        if ioc.is_novel and ioc.novelty_score > self.novelty_threshold:
            novelty_boost = 0.2
            confidence += novelty_boost

        # Factor 2: Threat score from IOC characteristics
        threat_boost = 0.0
        if ioc.threat_score > 0.7:
            threat_boost = 0.15
            confidence += threat_boost

        # Factor 3: Reputation confirmation
        reputation_boost = 0.0
        reputation_malicious = False
        if reputation_data and reputation_data.is_malicious:
            reputation_boost = 0.25
            confidence += reputation_boost
            reputation_malicious = True

        # Factor 4: Context analysis
        context_boost = self._analyze_context(ioc, source_log)
        confidence += context_boost

        # Normalize confidence
        confidence = min(confidence, 1.0)

        # Determine classification - use proper literal types
        classification_result: Literal["benign", "suspicious", "malicious"]
        if confidence >= self.confidence_threshold:
            if reputation_malicious or ioc.threat_score > 0.8:
                classification_result = "malicious"
                threat_level = ThreatLevel.HIGH
                should_generate_rule = True
            else:
                classification_result = "suspicious"
                threat_level = ThreatLevel.MEDIUM
                should_generate_rule = confidence > 0.75
        else:
            classification_result = "benign"
            threat_level = ThreatLevel.LOW
            should_generate_rule = False

        # Build reasoning
        reasoning_parts = []
        if novelty_boost > 0:
            reasoning_parts.append(f"novel IOC (+{novelty_boost:.2f})")
        if threat_boost > 0:
            reasoning_parts.append(f"suspicious characteristics (+{threat_boost:.2f})")
        if reputation_boost > 0:
            reasoning_parts.append(f"reputation confirmation (+{reputation_boost:.2f})")
        if context_boost > 0:
            reasoning_parts.append(f"suspicious context (+{context_boost:.2f})")

        reasoning = (
            "Hybrid analysis: " + ", ".join(reasoning_parts)
            if reasoning_parts
            else "Basic classification"
        )

        return IOCClassification(
            classification=classification_result,
            confidence=confidence,
            should_generate_rule=should_generate_rule,
            threat_level=threat_level,
            reasoning=reasoning,
        )

    def _analyze_context(self, ioc: ExtractedIOC, source_log: WazuhRawLog) -> float:
        """Analyze log context for additional threat indicators"""
        context_boost = 0.0
        log_text = source_log.full_log.lower()

        # Suspicious command patterns
        suspicious_patterns = [
            "powershell",
            "cmd",
            "download",
            "execute",
            "hidden",
            "bypass",
            "encoded",
            "base64",
            "invoke",
            "script",
            "temp",
            "malware",
        ]

        pattern_matches = sum(
            1 for pattern in suspicious_patterns if pattern in log_text
        )
        if pattern_matches > 0:
            context_boost = min(pattern_matches * 0.05, 0.2)  # Max 0.2 boost

        return context_boost

    def _is_whitelisted(self, ioc: ExtractedIOC) -> bool:
        """Enhanced whitelist checking with CIDR and subdomain support"""
        try:
            if ioc.type == IOCType.DOMAIN:
                domain = ioc.value.lower().strip()

                # Check exact match
                if domain in self.whitelist["domains"]:
                    return True

                # Check if subdomain of whitelisted domain
                for whitelisted_domain in self.whitelist["domains"]:
                    if domain.endswith(f".{whitelisted_domain}"):
                        return True

                return False

            elif ioc.type == IOCType.IP:
                ip = ioc.value.strip()

                # Check exact IP match
                if ip in self.whitelist["ips"]:
                    return True

                # Check CIDR ranges
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    for cidr_or_ip in self.whitelist["ips"]:
                        if "/" in cidr_or_ip:
                            # CIDR notation
                            try:
                                if ip_obj in ipaddress.ip_network(
                                    cidr_or_ip, strict=False
                                ):
                                    return True
                            except (
                                ipaddress.AddressValueError,
                                ipaddress.NetmaskValueError,
                            ):
                                # Invalid CIDR, skip
                                continue
                except ipaddress.AddressValueError:
                    # Invalid IP format
                    pass

                return False

            elif ioc.type == IOCType.PROCESS_NAME:
                process = ioc.value.lower().strip()
                return process in self.whitelist["processes"]

            # Other IOC types not whitelisted by default
            return False

        except Exception as e:
            logger.warning(
                "Error checking whitelist",
                ioc_value=ioc.value,
                ioc_type=ioc.type.value,
                error=str(e),
            )
            return False

    async def add_to_whitelist(self, ioc_value: str, ioc_type: IOCType) -> bool:
        """Add IOC to runtime whitelist (not persistent)"""
        try:
            if ioc_type == IOCType.DOMAIN:
                self.whitelist["domains"].add(ioc_value.lower())
            elif ioc_type == IOCType.IP:
                self.whitelist["ips"].add(ioc_value)
            elif ioc_type == IOCType.PROCESS_NAME:
                self.whitelist["processes"].add(ioc_value.lower())
            else:
                logger.warning(
                    "IOC type not supported for whitelist", ioc_type=ioc_type
                )
                return False

            logger.info(
                "IOC added to runtime whitelist", ioc=ioc_value, ioc_type=ioc_type.value
            )
            return True

        except Exception as e:
            logger.error("Failed to add IOC to whitelist", ioc=ioc_value, error=str(e))
            return False

    async def remove_from_whitelist(self, ioc_value: str, ioc_type: IOCType) -> bool:
        """Remove IOC from runtime whitelist (not persistent)"""
        try:
            removed = False

            if ioc_type == IOCType.DOMAIN:
                if ioc_value.lower() in self.whitelist["domains"]:
                    self.whitelist["domains"].remove(ioc_value.lower())
                    removed = True
            elif ioc_type == IOCType.IP:
                if ioc_value in self.whitelist["ips"]:
                    self.whitelist["ips"].remove(ioc_value)
                    removed = True
            elif ioc_type == IOCType.PROCESS_NAME:
                if ioc_value.lower() in self.whitelist["processes"]:
                    self.whitelist["processes"].remove(ioc_value.lower())
                    removed = True

            if removed:
                logger.info(
                    "IOC removed from runtime whitelist",
                    ioc=ioc_value,
                    ioc_type=ioc_type.value,
                )
            else:
                logger.warning(
                    "IOC not found in whitelist for removal",
                    ioc=ioc_value,
                    ioc_type=ioc_type.value,
                )

            return removed

        except Exception as e:
            logger.error(
                "Failed to remove IOC from whitelist", ioc=ioc_value, error=str(e)
            )
            return False

    async def add_to_threat_intel(
        self,
        ioc_value: str,
        ioc_type: IOCType,
        source: str,
        threat_actor: Optional[str] = None,
        campaign: Optional[str] = None,
        description: Optional[str] = None,
    ) -> bool:
        """Add IOC to threat intelligence database"""
        return await self.threat_intel_db.add_ioc(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            source=source,
            threat_actor=threat_actor,
            campaign=campaign,
            description=description,
            confidence=1.0,
        )

    def get_whitelist_stats(self) -> dict[str, Any]:
        """Get whitelist statistics"""
        config_whitelist = self.config.get("whitelist", {})

        return {
            "whitelist_enabled": config_whitelist.get("enabled", True),
            "total_domains": len(self.whitelist["domains"]),
            "total_ips": len(self.whitelist["ips"]),
            "total_processes": len(self.whitelist["processes"]),
            "custom_domains_configured": len(
                config_whitelist.get("custom_domains", [])
            ),
            "custom_ips_configured": len(config_whitelist.get("custom_ips", [])),
            "custom_processes_configured": len(
                config_whitelist.get("custom_processes", [])
            ),
        }

    def get_classification_statistics(self) -> dict[str, Any]:
        """Get comprehensive classification statistics"""
        threat_intel_stats = self.threat_intel_db.get_statistics()
        reputation_stats = self.reputation_service.get_cache_stats()
        whitelist_stats = self.get_whitelist_stats()

        return {
            "configuration": {
                "confidence_threshold": self.confidence_threshold,
                "novelty_threshold": self.novelty_threshold,
                "reputation_confirmation_threshold": self.reputation_confirmation_threshold,
                "reputation_checking_enabled": self.reputation_service.enabled,
            },
            "threat_intelligence": threat_intel_stats,
            "reputation_service": reputation_stats,
            "whitelist": whitelist_stats,
        }
