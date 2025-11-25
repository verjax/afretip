import re
import time
from typing import Any

import structlog

from ..analytics import collect_ioc_data
from ..core.models import ExtractedIOC, IOCType, WazuhRawLog

logger = structlog.get_logger(__name__)


class IOCExtractor:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        extraction_config = config.get("extraction", {})

        # INCREASED thresholds to reduce false positives
        self.confidence_threshold = extraction_config.get("confidence_threshold", 0.5)  # Raised from 0.3
        self.enable_novelty_scoring = extraction_config.get("enable_novelty_scoring", True)
        self.enable_threat_scoring = extraction_config.get("enable_threat_scoring", True)
        self.enable_context_filtering = extraction_config.get("enable_context_filtering", True)

        # IOC frequency tracking
        self.ioc_frequency: dict[str, int] = {}
        self.total_extractions = 0

        # Compile regex patterns
        self._compile_patterns()

        # Load context-aware filters
        self._load_context_filters()

        logger.info(
            "Enhanced IOC Extractor initialized",
            confidence_threshold=self.confidence_threshold,
            context_filtering=self.enable_context_filtering,
        )

    def _compile_patterns(self) -> None:
        """Compile regex patterns with more restrictive matching"""
        self.patterns = {
            # Network IOCs (more restrictive)
            IOCType.IP: re.compile(
                r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
            ),
            IOCType.DOMAIN: re.compile(
                r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?!exe|dll|bat|cmd|ps1|vbs|js|scr|com|pif)[a-zA-Z]{2,}\b",
                re.IGNORECASE
            ),
            IOCType.URL: re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
            IOCType.EMAIL: re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),

            # File IOCs - Enhanced patterns
            IOCType.HASH_MD5: re.compile(r"\b[a-fA-F0-9]{32}\b"),
            IOCType.HASH_SHA1: re.compile(r"\b[a-fA-F0-9]{40}\b"),
            IOCType.HASH_SHA256: re.compile(r"\b[a-fA-F0-9]{64}\b"),

            # More selective file path pattern - avoid system directories
            IOCType.FILE_PATH: re.compile(
                r'(?:[A-Za-z]:\\|/)(?:[^<>:"|?*\s]+[/\\])*[^<>:"|?*\s]*\.(?:exe|dll|bat|cmd|ps1|vbs|js|jar|zip|scr|com|pif|hta|sct)',
                re.IGNORECASE,
            ),

            # Registry keys
            IOCType.REGISTRY_KEY: re.compile(
                r'(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|HKEY_CLASSES_ROOT|HKCR|HKEY_USERS|HKU|HKEY_CURRENT_CONFIG|HKCC)\\[^\s<>"]+',
                re.IGNORECASE,
            ),

            # More selective process pattern - focus on suspicious tools
            IOCType.PROCESS_NAME: re.compile(
                r"\b(?:powershell|cmd|rundll32|regsvr32|mshta|certutil|bitsadmin|wscript|cscript|installutil|msbuild|wmic|psexec)\.exe\b",
                re.IGNORECASE,
            ),

            # Enhanced command line pattern for obfuscation
            IOCType.COMMAND_LINE: re.compile(
                r'(?:powershell|cmd)\s+(?:-\w+\s+)*.*?(?:-enc|-encodedcommand|-hidden|-bypass)\s*[A-Za-z0-9+/=]+|'
                r'(?:invoke-expression|iex)\s+[^;]+|'
                r'frombase64string\([^)]+\)|'
                r'downloadstring\([^)]+\)|'
                r'new-object\s+net\.webclient',
                re.IGNORECASE
            ),
        }

    def _load_context_filters(self) -> None:
        """Load context-aware filtering rules"""
        self.context_filters = {
            "legitimate_processes": {
                # System processes that should rarely be flagged as IOCs
                "explorer.exe", "svchost.exe", "winlogon.exe", "csrss.exe",
                "dwm.exe", "taskhost.exe", "services.exe", "lsass.exe",
                "spoolsv.exe", "audiodg.exe", "conhost.exe", "smss.exe",
                "wininit.exe", "userinit.exe", "logonui.exe",

                # Common admin tools - only flag in suspicious contexts
                "taskmgr.exe", "regedit.exe", "mmc.exe", "eventvwr.exe",
                "sfc.exe", "dism.exe", "gpupdate.exe", "ipconfig.exe",
            },

            "legitimate_domains": {
                # Microsoft and cloud services
                "microsoft.com", "office.com", "live.com", "outlook.com",
                "office365.com", "microsoftonline.com", "azure.com",
                "onedrive.live.com", "sharepoint.com", "teams.microsoft.com",

                # Other legitimate services
                "google.com", "googledrive.com", "googleapis.com",
                "amazon.com", "amazonaws.com", "cloudflare.com",
                "github.com", "dropbox.com",
            },

            "safe_file_paths": {
                # System directories
                "c:\\windows\\system32", "c:\\windows\\syswow64",
                "c:\\program files", "c:\\program files (x86)",
                "c:\\programdata\\microsoft", "c:\\users\\all users",
                "%systemroot%", "%programfiles%", "%windir%",
                "\\windowspowershell\\v1.0\\powershell.exe",
                "c:\\windows\\system32\\cmd.exe",
                "c:\\windows\\system32\\wscript.exe",
                "c:\\windows\\system32\\cscript.exe",
            },

            "legitimate_contexts": [
                "system maintenance", "windows update", "scheduled task",
                "group policy", "software installation", "backup operation",
                "antivirus scan", "office automation", "cloud sync",
                "user logon", "network configuration", "legitimate admin",
            ],
        }

    async def extract_iocs(self, log: WazuhRawLog) -> list[ExtractedIOC]:
        """Enhanced IOC extraction with context filtering"""
        extraction_start_time = time.time()

        try:
            iocs = []
            log_text = log.full_log

            # Determine log context
            log_context = self._analyze_log_context(log_text)

            # Extract each type of IOC
            for ioc_type, pattern in self.patterns.items():
                matches = pattern.finditer(log_text)

                for match in matches:
                    ioc_value = match.group().strip()

                    # Skip if value is too short
                    if len(ioc_value) < 3:
                        continue

                    # Context-aware filtering
                    if self.enable_context_filtering and self._should_filter_ioc(ioc_value, ioc_type, log_context,
                                                                                 log_text):
                        logger.debug(
                            "IOC filtered due to legitimate context",
                            ioc_value=ioc_value,
                            ioc_type=ioc_type.value,
                            context=log_context
                        )
                        continue

                    # Calculate extraction confidence
                    confidence = self._calculate_extraction_confidence(
                        ioc_value, ioc_type, log_text, log_context
                    )

                    # Skip low confidence extractions (higher threshold)
                    if confidence < self.confidence_threshold:
                        continue

                    # Create IOC object
                    ioc = ExtractedIOC(
                        type=ioc_type,
                        value=ioc_value,
                        confidence=confidence,
                        context=self._extract_context(log_text, match),
                        source_log_hash=log.log_hash,
                        extraction_method="regex_enhanced",
                    )

                    # Calculate threat and novelty scores
                    if self.enable_threat_scoring:
                        ioc.threat_score = self._calculate_threat_score(ioc, log_text, log_context)

                    if self.enable_novelty_scoring:
                        ioc.novelty_score = self._calculate_novelty_score(ioc)
                        ioc.is_novel = ioc.novelty_score > 0.7

                    iocs.append(ioc)

            # Remove duplicates
            unique_iocs = []
            seen_values = set()

            for ioc in iocs:
                ioc_key = f"{ioc.type.value}:{ioc.value}"
                if ioc_key not in seen_values:
                    unique_iocs.append(ioc)
                    seen_values.add(ioc_key)

            # Update frequency tracking
            self.total_extractions += 1
            for ioc in unique_iocs:
                ioc_key = f"{ioc.type.value}:{ioc.value}"
                self.ioc_frequency[ioc_key] = self.ioc_frequency.get(ioc_key, 0) + 1

            extraction_time = time.time() - extraction_start_time

            # Collect research metrics
            collect_ioc_data(unique_iocs, extraction_time)

            logger.debug(
                "Enhanced IOC extraction completed",
                log_hash=log.log_hash,
                iocs_found=len(unique_iocs),
                extraction_time=f"{extraction_time:.3f}s",
                context=log_context,
            )

            return unique_iocs

        except Exception as e:
            extraction_time = time.time() - extraction_start_time
            logger.error(
                "IOC extraction failed",
                log_hash=log.log_hash,
                error=str(e),
                extraction_time=f"{extraction_time:.3f}s",
            )
            collect_ioc_data([], extraction_time)
            return []

    def _analyze_log_context(self, log_text: str) -> str:
        """Analyze log to determine operational context"""
        log_lower = log_text.lower()

        # Check for legitimate contexts
        for context in self.context_filters["legitimate_contexts"]:
            if context in log_lower:
                return context

        # Check for business application context
        business_keywords = [
            "office", "excel", "word", "outlook", "powerpoint", "teams",
            "sharepoint", "onedrive", "business", "enterprise"
        ]

        for keyword in business_keywords:
            if keyword in log_lower:
                return "business_application"

        # Check for administrative context
        admin_keywords = [
            "administrator", "admin", "management", "configuration",
            "installation", "setup", "maintenance"
        ]

        for keyword in admin_keywords:
            if keyword in log_lower:
                return "administrative"

        return "unknown"

    def _should_filter_ioc(self, ioc_value: str, ioc_type: IOCType, context: str, log_text: str) -> bool:
        """Determine if IOC should be filtered based on context"""

        # Always extract hashes - they're always suspicious
        if ioc_type in [IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]:
            return False

        # Process/domain filtering (unchanged, but normalized)
        if ioc_type in [IOCType.PROCESS_NAME, IOCType.DOMAIN]:
            # Normalize process name by stripping common extensions
            executable_extensions = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.scr', '.com']
            process_name = ioc_value.lower()
            for ext in executable_extensions:
                if process_name.endswith(ext):
                    # removesuffix available in py3.9+, fallback safe logic if not present
                    try:
                        process_name = process_name.removesuffix(ext)
                    except AttributeError:
                        if process_name.endswith(ext):
                            process_name = process_name[: -len(ext)]

            if process_name in self.context_filters.get("legitimate_processes", []):
                # Use configured contexts, fallback to defaults
                legitimate_contexts = self.context_filters.get(
                    "legitimate_contexts",
                    ["system maintenance", "windows update", "scheduled task",
                     "business_application", "administrative", "legitimate admin"]
                )
                if context in legitimate_contexts:
                    return True  # Filter out (don't extract)

                # Special handling for PowerShell
                if process_name == "powershell":
                    safe_cmds = [
                        "get-process", "get-service", "get-eventlog",
                        "test-connection", "import-module", "get-childitem", "set-location"
                    ]
                    if log_text:
                        # look at the immediate command context (first 200 chars) to avoid false positives
                        log_line = log_text.lower()[:200].strip()
                        if any(log_line.startswith(cmd) for cmd in safe_cmds):
                            return True  # Filter out legitimate PowerShell

        # Filter legitimate domains
        if ioc_type == IOCType.DOMAIN:
            # Already normalized above, but re-assign for clarity
            domain_lower = ioc_value.lower()

            # Filter out executable-looking "domains"
            executable_extensions = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.scr', '.com']
            if any(domain_lower.endswith(ext) for ext in executable_extensions):
                return True

            # Check against known safe domains
            for legit_domain in self.context_filters.get("legitimate_domains", []):
                if domain_lower == legit_domain or domain_lower.endswith("." + legit_domain):
                    return True  # Filter out legitimate domain

        # Improved FILE_PATH filtering
        if ioc_type == IOCType.FILE_PATH:
            path_lower = ioc_value.lower()

            # Trusted system directories and binaries
            system_dirs = ["\\windows\\system32\\", "\\program files\\", "\\program files (x86)\\", "\\windows\\syswow64\\"]
            system_binaries = ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"]

            # If file is a known system binary in an expected system directory:
            if any(sd in path_lower for sd in system_dirs) and any(path_lower.endswith(bin) for bin in system_binaries):
                # If context indicates maintenance or legit admin operations, filter out (do not extract)
                if context in self.context_filters.get("legitimate_contexts", []):
                    return True
                # Otherwise, do not filter (allow extraction) but lower confidence downstream

            # If file is in ProgramData, AppData, or Users folder and is an exe -> treat as suspicious (do not filter)
            suspicious_location_indicators = ["\\programdata\\", "\\appdata\\", "\\users\\"]
            if any(ind in path_lower for ind in suspicious_location_indicators) and path_lower.endswith(".exe"):
                return False  # do not filter - extract and raise confidence

            # Path is in configured safe paths and context is legitimate -> filter out
            for safe_path in self.context_filters.get("safe_file_paths", []):
                if safe_path in path_lower and context in self.context_filters.get("legitimate_contexts", []):
                    return True

        # Filter local/private IP addresses in business contexts
        if ioc_type == IOCType.IP:
            if context in ["business_application", "cloud sync", "office automation"]:
                if (ioc_value.startswith("192.168.") or
                        ioc_value.startswith("10.") or
                        ioc_value.startswith("172.")):
                    return True  # Filter out internal IPs in business context

        return False  # Don't filter

    def _calculate_extraction_confidence(
            self, ioc_value: str, ioc_type: IOCType, log_text: str, context: str
    ) -> float:
        """Enhanced confidence calculation with context awareness"""
        confidence = 0.5  # Base confidence

        # Context-based confidence adjustment
        if context in ["system maintenance", "windows update", "business_application", "legitimate admin"]:
            confidence *= 0.7  # Reduce confidence in legitimate contexts
        elif context == "unknown":
            confidence += 0.1  # Slightly increase for unknown contexts

        # Type-specific adjustments
        if ioc_type == IOCType.IP:
            # Lower confidence for private IPs
            if any(ioc_value.startswith(prefix) for prefix in ["10.", "192.168.", "172."]):
                confidence -= 0.2
            # Higher confidence for suspicious public IPs
            if not any(ioc_value.startswith(prefix) for prefix in ["10.", "192.168.", "172.", "127."]):
                confidence += 0.1

        elif ioc_type == IOCType.DOMAIN:
            # Higher confidence for suspicious TLDs
            suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".bit", ".onion", ".bad"]
            if any(ioc_value.endswith(tld) for tld in suspicious_tlds):
                confidence += 0.3

            # Lower confidence for common legitimate domains
            common_domains = ["microsoft.com", "google.com", "amazon.com", "office365.com"]
            if any(common in ioc_value.lower() for common in common_domains):
                confidence -= 0.3

        elif ioc_type in [IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]:
            # Hashes are always high confidence
            confidence += 0.4

        elif ioc_type == IOCType.PROCESS_NAME:
            # Higher confidence for known suspicious processes
            suspicious_processes = ["rundll32.exe", "regsvr32.exe", "mshta.exe",
                                    "certutil.exe", "bitsadmin.exe", "psexec.exe"]
            if ioc_value.lower() in suspicious_processes:
                confidence += 0.2

            # Lower confidence for common system processes
            system_processes = ["svchost.exe", "explorer.exe", "winlogon.exe"]
            if ioc_value.lower() in system_processes:
                confidence -= 0.3

        elif ioc_type == IOCType.FILE_PATH:
            path_lower = ioc_value.lower()

            # Low confidence for known system binaries in correct paths
            if "\\windows\\system32\\" in path_lower and any(path_lower.endswith(bin) for bin in ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"]):
                confidence = 0.2

            # Higher confidence for unknown exe in ProgramData/AppData/Users
            if ("\\programdata\\" in path_lower or "\\appdata\\" in path_lower or "\\users\\" in path_lower):
                if path_lower.endswith(".exe") and not any(name in path_lower for name in ["microsoft", "windows"]):
                    confidence += 0.3

            # Suspicious if file name contains RMM or admin-like keywords
            if any(keyword in path_lower for keyword in ["rmm", "remote", "agent", "client", "admin"]):
                confidence += 0.2

        # Suspicious keyword adjustments
        suspicious_keywords = ["malware", "trojan", "suspicious", "blocked", "evil", "payload"]
        if any(keyword in log_text.lower() for keyword in suspicious_keywords):
            confidence += 0.2

        # Legitimate keyword adjustments
        legitimate_keywords = ["office", "microsoft", "windows", "update", "maintenance"]
        if any(keyword in log_text.lower() for keyword in legitimate_keywords):
            confidence -= 0.1

        # Normalize confidence
        return max(0.0, min(1.0, confidence))

    def _calculate_threat_score(self, ioc: ExtractedIOC, log_text: str, context: str) -> float:
        """Enhanced threat scoring with context awareness"""
        # Base threat score from IOC type
        type_scores = {
            IOCType.HASH_MD5: 0.8,
            IOCType.HASH_SHA1: 0.8,
            IOCType.HASH_SHA256: 0.8,
            IOCType.URL: 0.6,
            IOCType.DOMAIN: 0.5,
            IOCType.IP: 0.5,
            IOCType.EMAIL: 0.4,
            IOCType.FILE_PATH: 0.6,
            IOCType.REGISTRY_KEY: 0.7,
            IOCType.PROCESS_NAME: 0.5,
            IOCType.COMMAND_LINE: 0.8,
        }

        threat_score = type_scores.get(ioc.type, 0.3)

        # Context-based threat score adjustment
        if context in ["system maintenance", "windows update", "business_application", "legitimate admin"]:
            threat_score *= 0.5  # Significantly reduce threat score in legitimate contexts

        # Suspicious indicators boost
        threat_indicators = [
            "malware", "trojan", "virus", "backdoor", "rootkit", "keylogger",
            "suspicious", "blocked", "quarantine", "detected", "alert", "evil",
            "payload", "c2", "command", "control"
        ]

        indicator_count = sum(1 for indicator in threat_indicators if indicator in log_text.lower())
        threat_score += min(indicator_count * 0.15, 0.4)

        # Specific IOC characteristics
        if ioc.type == IOCType.DOMAIN:
            if any(ioc.value.endswith(tld) for tld in [".tk", ".ml", ".bit", ".onion", ".bad"]):
                threat_score += 0.3

        if ioc.type == IOCType.COMMAND_LINE:
            if any(keyword in ioc.value.lower() for keyword in ["hidden", "bypass", "encoded", "base64"]):
                threat_score += 0.3

        # FILE_PATH-specific adjustments
        if ioc.type == IOCType.FILE_PATH:
            path_lower = ioc.value.lower()

            # Increase threat for executables in ProgramData/AppData/Users
            if "\\programdata\\" in path_lower or "\\appdata\\" in path_lower or "\\users\\" in path_lower:
                threat_score += 0.2

            # Increase threat for RMM/agent-like names
            if any(keyword in path_lower for keyword in ["rmm", "remote", "agent", "client"]):
                threat_score += 0.2

            # Decrease threat if it's a known system PowerShell in system32
            if path_lower.endswith("powershell.exe") and "\\system32\\" in path_lower:
                threat_score -= 0.3

        return max(0.0, min(1.0, threat_score))

    def _calculate_novelty_score(self, ioc: ExtractedIOC) -> float:
        """Calculate novelty score based on frequency"""
        ioc_key = f"{ioc.type.value}:{ioc.value}"
        frequency = self.ioc_frequency.get(ioc_key, 0)

        if self.total_extractions == 0:
            return 1.0

        # Calculate relative frequency
        relative_frequency = frequency / self.total_extractions

        # Higher novelty for less frequent IOCs
        novelty_score = max(0.0, 1.0 - (relative_frequency * 5))  # Scale factor

        return min(novelty_score, 1.0)

    def _extract_context(self, log_text: str, match: re.Match) -> str:
        """Extract context around the matched IOC"""
        start = max(0, match.start() - 50)
        end = min(len(log_text), match.end() + 50)
        context = log_text[start:end].strip()

        # Clean up context
        context = re.sub(r"\s+", " ", context)
        return context

    def get_extraction_statistics(self) -> dict[str, Any]:
        """Get IOC extraction statistics"""
        type_frequencies: dict[str, int] = {}
        for ioc_key, frequency in self.ioc_frequency.items():
            ioc_type = ioc_key.split(":", 1)[0]
            type_frequencies[ioc_type] = type_frequencies.get(ioc_type, 0) + frequency

        return {
            "total_extractions": self.total_extractions,
            "unique_iocs": len(self.ioc_frequency),
            "ioc_frequencies_by_type": type_frequencies,
            "configuration": {
                "confidence_threshold": self.confidence_threshold,
                "novelty_scoring_enabled": self.enable_novelty_scoring,
                "threat_scoring_enabled": self.enable_threat_scoring,
                "context_filtering_enabled": self.enable_context_filtering,
            },
        }

    def reset_frequency_tracking(self) -> None:
        """Reset IOC frequency tracking"""
        self.ioc_frequency.clear()
        self.total_extractions = 0
        logger.info("IOC frequency tracking reset")
