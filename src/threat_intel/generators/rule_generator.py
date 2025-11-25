from typing import Any
from xml.etree.ElementTree import Element, tostring

import structlog

from ..core.models import (
    ExtractedIOC,
    IOCType,
    SuspiciousFinding,
    ThreatLevel,
    WazuhRule,
)
from .existing_rule_checker import ExistingRuleChecker

logger = structlog.get_logger(__name__)


class WazuhRuleGenerator:
    def __init__(self, rules_directory: str = "/var/ossec/etc/rules") -> None:
        self.generated_rules: list[WazuhRule] = []
        self.used_rule_ids: set[int] = set()

        # Initialize rule checker for deduplication
        self.rule_checker = ExistingRuleChecker(rules_directory)

        logger.info("Initialized rule generator with existing rule checking")

    def generate_rules_from_finding(
            self, finding: SuspiciousFinding
    ) -> list[WazuhRule]:
        # STEP 1: Check what's already covered
        coverage_info = self.rule_checker.check_finding_coverage(finding)

        # STEP 2: Log coverage status
        if coverage_info["covered_iocs"]:
            logger.info(
                "Some IOCs already covered by existing rules",
                finding_id=finding.id,
                total_iocs=coverage_info["total_iocs"],
                covered_iocs=len(coverage_info["covered_iocs"]),
                uncovered_iocs=len(coverage_info["uncovered_iocs"]),
                covering_rules=list(coverage_info["covering_rules"])
            )

            # Log details about covered IOCs (first 5 to avoid spam)
            for ioc in coverage_info["covered_iocs"][:5]:
                covering_rules = coverage_info["coverage_details"][f"{ioc.type.value}:{ioc.value}"]["rules"]
                logger.info(
                    "Skipping rule generation - IOC already covered",
                    ioc_type=ioc.type.value,
                    ioc_value=ioc.value,
                    covering_rules=covering_rules,
                    finding_id=finding.id
                )

        # STEP 3: Generate rules only for uncovered IOCs
        if not coverage_info["uncovered_iocs"]:
            logger.info(
                "No new rules needed - all IOCs already covered",
                finding_id=finding.id,
                total_iocs=coverage_info["total_iocs"],
                covering_rules=list(coverage_info["covering_rules"])
            )
            return []

        # Create filtered finding with only uncovered IOCs
        filtered_finding = SuspiciousFinding(
            id=finding.id,
            finding_type=finding.finding_type,
            description=f"{finding.description} (new IOCs only)",
            confidence=finding.confidence,
            threat_level=finding.threat_level,
            iocs=coverage_info["uncovered_iocs"],
            details=finding.details,
            source_log_hash=finding.source_log_hash,
            reasoning=finding.reasoning,
            pattern_matches=finding.pattern_matches,
            context=finding.context,
            timestamp=finding.timestamp
        )

        # STEP 4: Generate rules using existing methods
        rules = []
        if filtered_finding.finding_type == "suspicious_pattern":
            rules.extend(self._generate_pattern_rules(filtered_finding))
        elif filtered_finding.finding_type == "novel_ioc":
            rules.extend(self._generate_ioc_rules(filtered_finding))
        elif filtered_finding.finding_type == "behavioral_anomaly":
            rules.extend(self._generate_behavior_rules(filtered_finding))

        # Track generated rules
        self.generated_rules.extend(rules)

        logger.info(
            "Generated rules with deduplication",
            finding_id=finding.id,
            total_iocs=coverage_info["total_iocs"],
            covered_by_existing=len(coverage_info["covered_iocs"]),
            new_rules_generated=len(rules),
            uncovered_iocs=len(coverage_info["uncovered_iocs"])
        )

        return rules

    def refresh_rule_cache(self) -> None:
        """Refresh the existing rules cache (call after deployments)"""
        self.rule_checker.refresh_rules()

    def _generate_pattern_rules(self, finding: SuspiciousFinding) -> list[WazuhRule]:
        rules = []
        wazuh_level = self._threat_to_wazuh_level(finding.threat_level)
        pattern_names = finding.details.get("patterns", ["generic"])

        for pattern_name in pattern_names:
            rule_id = self._get_next_rule_id()

            # Extract IOC values from the finding to build regex
            ioc_values = [ioc.value for ioc in finding.iocs if ioc.value]

            if "powershell" in pattern_name.lower():
                rule = WazuhRule(
                    rule_id=rule_id,
                    level=wazuh_level,
                    description=f"Suspicious PowerShell activity detected: {finding.description}",
                    regex=r"powershell.*(-e|-enc|-encodedcommand|downloadstring|hidden|bypass)",
                    groups=["powershell", "attack", "malware"],
                    threat_level=finding.threat_level,
                    confidence=finding.confidence,
                    source_finding_id=finding.id,
                    ioc_values=ioc_values
                )
            elif "temp_executable" in pattern_name.lower() or "temp" in pattern_name.lower():
                rule = WazuhRule(
                    rule_id=rule_id,
                    level=wazuh_level,
                    description=f"Executable created in temp directory: {finding.description}",
                    regex=r"(\\temp\\|\\tmp\\|/tmp/).*\.(exe|scr|bat|cmd|ps1|sh)",
                    groups=["malware", "file_creation"],
                    threat_level=finding.threat_level,
                    confidence=finding.confidence,
                    source_finding_id=finding.id,
                    ioc_values=ioc_values
                )
            elif "living_off_land" in pattern_name.lower() or "lolbas" in pattern_name.lower():
                rule = WazuhRule(
                    rule_id=rule_id,
                    level=wazuh_level,
                    description=f"Living-off-the-land binary abuse detected: {finding.description}",
                    regex=r"(certutil|bitsadmin|regsvr32|rundll32|mshta|wmic|installutil|msbuild)",
                    groups=["lolbas", "attack", "execution"],
                    threat_level=finding.threat_level,
                    confidence=finding.confidence,
                    source_finding_id=finding.id,
                    ioc_values=ioc_values
                )
            elif "network" in pattern_name.lower() or "suspicious_network" in pattern_name.lower():
                # Build regex from IOCs if available
                if ioc_values:
                    # Escape special regex characters in IOC values
                    escaped_iocs = [self._escape_regex(ioc) for ioc in ioc_values[:10]]
                    ioc_pattern = "|".join(escaped_iocs)
                    regex = f"({ioc_pattern})"
                else:
                    regex = r"(download|curl|wget|invoke-webrequest|net use|copy \\\\)"

                rule = WazuhRule(
                    rule_id=rule_id,
                    level=wazuh_level,
                    description=f"Suspicious network activity detected: {finding.description}",
                    regex=regex,
                    groups=["network", "suspicious", "threat_intel"],
                    threat_level=finding.threat_level,
                    confidence=finding.confidence,
                    source_finding_id=finding.id,
                    ioc_values=ioc_values
                )
            else:
                # Generic suspicious pattern - build regex from IOCs or use generic pattern
                if ioc_values:
                    # Use actual IOC values in regex
                    escaped_iocs = [self._escape_regex(ioc) for ioc in ioc_values[:10]]
                    ioc_pattern = "|".join(escaped_iocs)
                    regex = f"({ioc_pattern})"
                else:
                    # Fallback to generic suspicious indicators
                    regex = r"(malware|trojan|suspicious|backdoor|exploit|payload)"

                rule = WazuhRule(
                    rule_id=rule_id,
                    level=wazuh_level,
                    description=f"Suspicious pattern detected: {finding.description}",
                    regex=regex,
                    groups=["suspicious", "threat_intel"],
                    threat_level=finding.threat_level,
                    confidence=finding.confidence,
                    source_finding_id=finding.id,
                    ioc_values=ioc_values
                )

            rules.append(rule)

        return rules

    # Generate rules for novel IOCs
    def _generate_ioc_rules(self, finding: SuspiciousFinding) -> list[WazuhRule]:
        rules = []

        wazuh_level = self._threat_to_wazuh_level(finding.threat_level)

        # Group IOCs by type for efficient rule creation
        iocs_by_type: dict[IOCType, list[ExtractedIOC]] = {}
        for ioc in finding.iocs:
            if ioc.type not in iocs_by_type:
                iocs_by_type[ioc.type] = []
            iocs_by_type[ioc.type].append(ioc)

        # Create rules for each IOC type
        for ioc_type, iocs in iocs_by_type.items():
            if ioc_type == IOCType.IP:
                rules.extend(self._create_ip_rules(iocs, wazuh_level, finding))
            elif ioc_type == IOCType.DOMAIN:
                rules.extend(self._create_domain_rules(iocs, wazuh_level, finding))
            elif ioc_type in [IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]:
                rules.extend(self._create_hash_rules(iocs, wazuh_level, finding))
            elif ioc_type == IOCType.URL:
                rules.extend(self._create_url_rules(iocs, wazuh_level, finding))

        return rules

    # Create rules for suspicious IP addresses
    def _create_ip_rules(
            self, iocs: list[ExtractedIOC], level: int, finding: SuspiciousFinding
    ) -> list[WazuhRule]:
        if not iocs:
            return []

        rule_id = self._get_next_rule_id()
        ip_pattern = "|".join(
            [ioc.value for ioc in iocs[:10]]
        )  # Limit to 10 IPs per rule

        rule = WazuhRule(
            rule_id=rule_id,
            level=level,
            description="Communication with suspicious IP addresses (Novel IOCs)",
            regex=f"({ip_pattern})",
            groups=["threat_intel", "network", "suspicious_ip"],
            threat_level=finding.threat_level,
            confidence=finding.confidence,
            source_finding_id=finding.id,
        )

        return [rule]

    # Create rules for suspicious domains
    def _create_domain_rules(
            self, iocs: list[ExtractedIOC], level: int, finding: SuspiciousFinding
    ) -> list[WazuhRule]:
        if not iocs:
            return []

        rule_id = self._get_next_rule_id()
        domain_pattern = "|".join([ioc.value.replace(".", r"\.") for ioc in iocs[:10]])

        rule = WazuhRule(
            rule_id=rule_id,
            level=level,
            description="Communication with suspicious domains (Novel IOCs)",
            regex=f"({domain_pattern})",
            groups=["threat_intel", "network", "suspicious_domain"],
            threat_level=finding.threat_level,
            confidence=finding.confidence,
            source_finding_id=finding.id,
        )

        return [rule]

    # Create rules for suspicious file hashes
    def _create_hash_rules(
            self, iocs: list[ExtractedIOC], level: int, finding: SuspiciousFinding
    ) -> list[WazuhRule]:
        if not iocs:
            return []

        rule_id = self._get_next_rule_id()
        hash_pattern = "|".join([ioc.value for ioc in iocs[:5]])  # Limit hashes

        rule = WazuhRule(
            rule_id=rule_id,
            level=level,
            description="Suspicious file hash detected (Novel IOC)",
            regex=f"({hash_pattern})",
            groups=["threat_intel", "malware", "file_hash"],
            threat_level=finding.threat_level,
            confidence=finding.confidence,
            source_finding_id=finding.id,
        )

        return [rule]

    # Create rules for suspicious URLs
    def _create_url_rules(
            self, iocs: list[ExtractedIOC], level: int, finding: SuspiciousFinding
    ) -> list[WazuhRule]:
        if not iocs:
            return []

        rule_id = self._get_next_rule_id()

        # Escape special regex characters in URLs
        escaped_urls = []
        for ioc in iocs[:5]:
            escaped_url = (
                ioc.value.replace(".", r"\.").replace("?", r"\?").replace("+", r"\+")
            )
            escaped_urls.append(escaped_url)

        url_pattern = "|".join(escaped_urls)

        rule = WazuhRule(
            rule_id=rule_id,
            level=level,
            description="Access to suspicious URLs (Novel IOCs)",
            regex=f"({url_pattern})",
            groups=["threat_intel", "network", "suspicious_url"],
            threat_level=finding.threat_level,
            confidence=finding.confidence,
            source_finding_id=finding.id,
        )

        return [rule]

    # Generate rules for anomalous behavior patterns
    def _generate_behavior_rules(self, finding: SuspiciousFinding) -> list[WazuhRule]:
        # TODO: behavioral analysis rules
        return []

    # Convert threat level to Wazuh alert level
    def _threat_to_wazuh_level(self, threat_level: ThreatLevel) -> int:
        mapping = {
            ThreatLevel.LOW: 4,
            ThreatLevel.MEDIUM: 7,
            ThreatLevel.HIGH: 10,
            ThreatLevel.CRITICAL: 12,
        }
        return mapping.get(threat_level, 7)

    # Generate unique rule ID using timestamp + random to avoid conflicts
    def _get_next_rule_id(self) -> int:
        import random
        import time

        max_attempts = 10
        for _ in range(max_attempts):
            timestamp_part = int(time.time()) % 100000
            random_part = random.randint(1, 999)
            rule_id = int(f"1{timestamp_part:05d}{random_part:03d}")

            # Ensure valid range
            if rule_id > 999999:
                rule_id = rule_id % 900000 + 100000

            # Check for collision in current session
            if rule_id not in self.used_rule_ids:
                self.used_rule_ids.add(rule_id)
                return rule_id

        # Fallback to simple increment if all attempts fail
        return 100000 + len(self.generated_rules)

    # Export generated rules to XML file
    def export_rules_xml(self, filename: str) -> bool:
        if not self.generated_rules:
            logger.warning("No rules to export")
            return False

        try:
            root = Element("group", name="threat_intel_rules")

            for rule in self.generated_rules:
                # Use the to_wazuh_xml method from the WazuhRule model
                rule_xml = rule.to_wazuh_xml()
                # Parse just the rule part (skip comment)
                if "<!-- " in rule_xml:
                    xml_part = rule_xml.split("\n", 1)[1]  # Skip comment line
                else:
                    xml_part = rule_xml
                from xml.etree.ElementTree import fromstring

                root.append(fromstring(xml_part))

            xml_content = '<?xml version="1.0" encoding="UTF-8"?>\n'
            xml_content += tostring(root, encoding="unicode")

            with open(filename, "w") as f:
                f.write(xml_content)

            logger.info(
                "Rules exported successfully",
                filename=filename,
                rules_count=len(self.generated_rules),
            )
            return True

        except Exception as e:
            logger.error("Failed to export rules", error=str(e))
            return False

    # Export generated rules to JSON file
    def export_rules_json(self, filename: str) -> bool:
        if not self.generated_rules:
            logger.warning("No rules to export")
            return False

        try:
            import json

            rules_data = []
            for rule in self.generated_rules:
                rules_data.append(rule.model_dump())

            with open(filename, "w") as f:
                json.dump(rules_data, f, indent=2, default=str)

            logger.info(
                "Rules exported to JSON",
                filename=filename,
                rules_count=len(self.generated_rules),
            )
            return True

        except Exception as e:
            logger.error("Failed to export rules to JSON", error=str(e))
            return False

    # Get statistics about generated rules
    def get_rule_statistics(self) -> dict[str, Any]:
        if not self.generated_rules:
            return {"total_rules": 0}

        stats: dict[str, Any] = {
            "total_rules": len(self.generated_rules),
            "rules_by_level": {},
            "rules_by_type": {},
            "rules_by_groups": {},
        }

        for rule in self.generated_rules:
            # Count by level
            level = rule.level
            stats["rules_by_level"][level] = stats["rules_by_level"].get(level, 0) + 1

            # Count by primary group
            if rule.groups:
                primary_group = rule.groups[0]
                stats["rules_by_type"][primary_group] = (
                        stats["rules_by_type"].get(primary_group, 0) + 1
                )

            # Count all groups
            for group in rule.groups:
                stats["rules_by_groups"][group] = (
                        stats["rules_by_groups"].get(group, 0) + 1
                )

        return stats

    def _escape_regex(self, value: str) -> str:
        """Escape special regex characters in IOC values"""
        special_chars = r'\.+*?^$()[]{}|'
        escaped = value
        for char in special_chars:
            escaped = escaped.replace(char, '\\' + char)
        return escaped
