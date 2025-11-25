import re
from pathlib import Path
from typing import Any

import structlog

from ..core.models import ExtractedIOC, SuspiciousFinding

logger = structlog.get_logger(__name__)


class ExistingRuleChecker:
    """Check if rules already exist in Wazuh that cover the same IOCs/patterns"""

    def __init__(self, rules_directory: str = "/var/ossec/etc/rules"):
        self.rules_directory = Path(rules_directory)
        self.existing_rules: dict[int, dict[str, Any]] = {}  # rule_id -> rule_info
        self.ioc_coverage: dict[str, list[int]] = {}  # ioc_value -> [rule_ids]
        self.pattern_coverage: dict[str, list[int]] = {}  # pattern -> [rule_ids]

        self._parse_existing_rules()

    def _parse_existing_rules(self) -> None:
        """Parse all existing Wazuh rule files"""
        logger.info(f"Parsing existing rules from: {self.rules_directory}")

        if not self.rules_directory.exists():
            logger.warning(f"Rules directory not found: {self.rules_directory}")
            return

        total_rules = 0
        for rule_file in self.rules_directory.glob("*.xml"):
            try:
                rules_parsed = self._parse_rule_file(rule_file)
                total_rules += rules_parsed
            except Exception as e:
                logger.warning(f"Failed to parse {rule_file}: {e}")

        logger.info(
            f"Parsed {total_rules} existing rules, IOC coverage for {len(self.ioc_coverage)} IOCs"
        )

    def _parse_rule_file(self, rule_file: Path) -> int:
        """Parse individual rule file and extract IOC patterns"""
        with open(rule_file, encoding="utf-8", errors="ignore") as f:
            content = f.read()

        # Extract rule blocks using regex
        rule_pattern = re.compile(
            r'<rule\s+id=["\'](\d+)["\'][^>]*?>(.*?)</rule>', re.DOTALL | re.IGNORECASE
        )

        rules_parsed = 0
        for match in rule_pattern.finditer(content):
            rule_id = int(match.group(1))
            rule_content = match.group(2)

            # Extract rule info
            rule_info = self._extract_rule_info(rule_content, str(rule_file))
            self.existing_rules[rule_id] = rule_info

            # Extract IOCs and patterns from rule content
            self._extract_iocs_from_rule(rule_id, rule_content)
            self._extract_patterns_from_rule(rule_id, rule_content)

            rules_parsed += 1

        return rules_parsed

    def _extract_rule_info(self, rule_content: str, file_path: str) -> dict[str, Any]:
        """Extract basic rule information"""
        info: dict[str, Any] = {"file_path": file_path}

        # Extract description
        desc_match = re.search(
            r"<description>(.*?)</description>", rule_content, re.DOTALL
        )
        info["description"] = (
            desc_match.group(1).strip() if desc_match else "No description"
        )

        # Extract level
        level_match = re.search(r"<level>(\d+)</level>", rule_content)
        info["level"] = int(level_match.group(1)) if level_match else 0

        return info

    def _extract_iocs_from_rule(self, rule_id: int, rule_content: str) -> None:
        """Extract IOC values from rule content"""

        # Common IOC patterns
        ioc_patterns = {
            "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
            "domain": re.compile(
                r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b"
            ),
            "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
            "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
            "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
        }

        for _ioc_type, pattern in ioc_patterns.items():
            for match in pattern.finditer(rule_content):
                ioc_value = match.group(0)
                if ioc_value not in self.ioc_coverage:
                    self.ioc_coverage[ioc_value] = []
                self.ioc_coverage[ioc_value].append(rule_id)

    def _extract_patterns_from_rule(self, rule_id: int, rule_content: str) -> None:
        """Extract regex patterns from rule content"""

        # Extract regex patterns
        regex_patterns = re.findall(
            r"<regex[^>]*>(.*?)</regex>", rule_content, re.DOTALL
        )
        for pattern in regex_patterns:
            pattern = pattern.strip()
            if pattern:
                if pattern not in self.pattern_coverage:
                    self.pattern_coverage[pattern] = []
                self.pattern_coverage[pattern].append(rule_id)

        # Extract match patterns
        match_patterns = re.findall(
            r"<match[^>]*>(.*?)</match>", rule_content, re.DOTALL
        )
        for pattern in match_patterns:
            pattern = pattern.strip()
            if pattern:
                if pattern not in self.pattern_coverage:
                    self.pattern_coverage[pattern] = []
                self.pattern_coverage[pattern].append(rule_id)

    def check_ioc_coverage(self, ioc: ExtractedIOC) -> tuple[bool, list[int]]:
        """
        Check if an IOC is already covered by existing rules
        Returns: (is_covered, [covering_rule_ids])
        """
        covering_rules: list[int] = []

        # Direct IOC match
        if ioc.value in self.ioc_coverage:
            covering_rules.extend(self.ioc_coverage[ioc.value])

        # Pattern-based matching
        for pattern, rule_ids in self.pattern_coverage.items():
            try:
                # Test if the IOC value matches the pattern
                if re.search(pattern, ioc.value, re.IGNORECASE):
                    covering_rules.extend(rule_ids)
            except re.error:
                # Skip invalid regex patterns
                continue

        # Remove duplicates
        covering_rules = list(set(covering_rules))

        return len(covering_rules) > 0, covering_rules

    def check_finding_coverage(self, finding: SuspiciousFinding) -> dict[str, Any]:
        """
        Check coverage for an entire finding
        Returns detailed coverage information
        """
        coverage_info: dict[str, Any] = {
            "total_iocs": len(finding.iocs),
            "covered_iocs": [],
            "uncovered_iocs": [],
            "covering_rules": set(),
            "coverage_details": {},
        }

        for ioc in finding.iocs:
            is_covered, covering_rules = self.check_ioc_coverage(ioc)

            ioc_key = f"{ioc.type.value}:{ioc.value}"
            coverage_info["coverage_details"][ioc_key] = {
                "covered": is_covered,
                "rules": covering_rules,
            }

            if is_covered:
                coverage_info["covered_iocs"].append(ioc)
                coverage_info["covering_rules"].update(covering_rules)
            else:
                coverage_info["uncovered_iocs"].append(ioc)

        return coverage_info

    def refresh_rules(self) -> None:
        """Refresh the rule cache (call after rule deployments)"""
        logger.info("Refreshing existing rules cache")
        self.existing_rules.clear()
        self.ioc_coverage.clear()
        self.pattern_coverage.clear()
        self._parse_existing_rules()
