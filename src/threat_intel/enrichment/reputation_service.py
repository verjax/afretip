import asyncio
import time
from typing import Any, Optional

import httpx
import structlog

from ..core.models import IOCType, ReputationData

logger = structlog.get_logger(__name__)


class ReputationServiceError(Exception):
    """Custom exception for reputation service errors"""

    pass


class ReputationService:
    def __init__(self, config: dict[str, Any]):
        self.config = config

        rep_config = config.get("reputation_services", {})

        # VirusTotal configuration
        vt_config = rep_config.get("virustotal", {})
        self.virustotal_api_key = vt_config.get("api_key", "").strip()
        self.vt_enabled = bool(self.virustotal_api_key)
        self.vt_rate_limit = vt_config.get("rate_limit_per_minute", 4)
        self.vt_timeout = vt_config.get("timeout_seconds", 30)

        # AbuseIPDB configuration
        abuse_config = rep_config.get("abuseipdb", {})
        self.abuseipdb_api_key = abuse_config.get("api_key", "").strip()
        self.abuse_enabled = bool(self.abuseipdb_api_key)
        self.abuse_rate_limit = abuse_config.get("rate_limit_per_minute", 100)
        self.abuse_timeout = abuse_config.get("timeout_seconds", 30)

        # Rate limiting
        self.last_vt_request_time = 0.0
        self.last_abuse_request_time = 0.0
        self.min_vt_interval = (
            60.0 / self.vt_rate_limit if self.vt_rate_limit > 0 else 15.0
        )
        self.min_abuse_interval = (
            60.0 / self.abuse_rate_limit if self.abuse_rate_limit > 0 else 1.0
        )

        # Cache for session (TTL-based)
        self.cache: dict[str, tuple[ReputationData, float]] = {}
        self.cache_ttl = 3600  # 1 hour TTL

        # Error tracking
        self.error_count = 0
        self.max_errors_per_session = 50

        # Service status tracking
        self.vt_consecutive_failures = 0
        self.abuse_consecutive_failures = 0
        self.max_consecutive_failures = 5

        self.enabled = self.vt_enabled or self.abuse_enabled

        if not self.enabled:
            logger.warning(
                "No reputation services configured - reputation checking disabled"
            )
        else:
            enabled_services = []
            if self.vt_enabled:
                enabled_services.append("VirusTotal")
            if self.abuse_enabled:
                enabled_services.append("AbuseIPDB")
            logger.info("Reputation services initialized", services=enabled_services)

    async def check_reputation(
        self, ioc_value: str, ioc_type: IOCType
    ) -> Optional[ReputationData]:
        """
        Check IOC reputation using available services with proper error handling
        """
        if not self.enabled:
            return None

        if self.error_count >= self.max_errors_per_session:
            logger.warning("Too many reputation service errors, skipping checks")
            return None

        # Input validation
        if not ioc_value or not ioc_value.strip():
            logger.warning("Empty IOC value provided for reputation check")
            return None

        ioc_value = ioc_value.strip()

        # Check cache first
        cache_key = f"{ioc_type.value}:{ioc_value}"
        cached_result = self._get_from_cache(cache_key)
        if cached_result:
            logger.debug("Reputation cache hit", ioc=ioc_value)
            return cached_result

        try:
            # Try VirusTotal first (if enabled and not failing)
            if (
                self.vt_enabled
                and self.vt_consecutive_failures < self.max_consecutive_failures
            ):
                result = await self._check_virustotal(ioc_value, ioc_type)
                if result:
                    self._cache_result(cache_key, result)
                    self.vt_consecutive_failures = 0  # Reset on success
                    return result
                else:
                    self.vt_consecutive_failures += 1

            # Try AbuseIPDB for IPs (if enabled and not failing)
            if (
                ioc_type == IOCType.IP
                and self.abuse_enabled
                and self.abuse_consecutive_failures < self.max_consecutive_failures
            ):
                result = await self._check_abuseipdb(ioc_value)
                if result:
                    self._cache_result(cache_key, result)
                    self.abuse_consecutive_failures = 0  # Reset on success
                    return result
                else:
                    self.abuse_consecutive_failures += 1

            # If all services failed, return None
            return None

        except Exception as e:
            self.error_count += 1
            logger.error("Reputation check failed", ioc=ioc_value, error=str(e))
            return None

    def _get_from_cache(self, cache_key: str) -> Optional[ReputationData]:
        """Get result from cache if not expired"""
        if cache_key in self.cache:
            result, timestamp = self.cache[cache_key]
            if time.time() - timestamp < self.cache_ttl:
                # Mark as cached
                result.cached = True
                return result
            else:
                # Remove expired entry
                del self.cache[cache_key]
        return None

    def _cache_result(self, cache_key: str, result: ReputationData) -> None:
        """Cache result with timestamp"""
        self.cache[cache_key] = (result, time.time())

    async def _rate_limit_vt(self) -> None:
        """Rate limiting for VirusTotal"""
        current_time = time.time()
        time_since_last = current_time - self.last_vt_request_time

        if time_since_last < self.min_vt_interval:
            sleep_time = self.min_vt_interval - time_since_last
            logger.debug("VirusTotal rate limiting", sleep_time=sleep_time)
            await asyncio.sleep(sleep_time)

        self.last_vt_request_time = time.time()

    async def _rate_limit_abuse(self) -> None:
        """Rate limiting for AbuseIPDB"""
        current_time = time.time()
        time_since_last = current_time - self.last_abuse_request_time

        if time_since_last < self.min_abuse_interval:
            sleep_time = self.min_abuse_interval - time_since_last
            logger.debug("AbuseIPDB rate limiting", sleep_time=sleep_time)
            await asyncio.sleep(sleep_time)

        self.last_abuse_request_time = time.time()

    async def _check_virustotal(
        self, ioc_value: str, ioc_type: IOCType
    ) -> Optional[ReputationData]:
        """Check reputation via VirusTotal with comprehensive error handling"""
        try:
            await self._rate_limit_vt()

            # Route to appropriate VT endpoint
            if ioc_type == IOCType.IP:
                return await self._check_ip_virustotal(ioc_value)
            elif ioc_type == IOCType.DOMAIN:
                return await self._check_domain_virustotal(ioc_value)
            elif ioc_type == IOCType.URL:
                return await self._check_url_virustotal(ioc_value)
            elif ioc_type in [IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]:
                return await self._check_hash_virustotal(ioc_value)
            else:
                logger.debug("IOC type not supported by VirusTotal", ioc_type=ioc_type)
                return None

        except Exception as e:
            logger.error("VirusTotal check failed", ioc=ioc_value, error=str(e))
            return None

    async def _check_ip_virustotal(self, ip: str) -> Optional[ReputationData]:
        """Check IP reputation via VirusTotal API v2"""
        url = "https://www.virustotal.com/vtapi/v2/ip-address/report"

        try:
            async with httpx.AsyncClient(timeout=self.vt_timeout) as client:
                response = await client.get(
                    url, params={"apikey": self.virustotal_api_key, "ip": ip}
                )

                if response.status_code == 200:
                    data = response.json()
                    return self._parse_virustotal_response(data, ip, "virustotal")
                elif response.status_code == 204:
                    logger.debug("VirusTotal rate limit exceeded", ip=ip)
                    return None
                elif response.status_code == 403:
                    logger.warning("VirusTotal API key invalid or blocked")
                    return None
                else:
                    logger.warning(
                        "VirusTotal API error", status=response.status_code, ip=ip
                    )
                    return None

        except httpx.TimeoutException:
            logger.warning("VirusTotal API timeout", ip=ip)
            return None
        except httpx.NetworkError as e:
            logger.warning("VirusTotal network error", ip=ip, error=str(e))
            return None
        except Exception as e:
            logger.error("VirusTotal IP check failed", ip=ip, error=str(e))
            return None

    async def _check_domain_virustotal(self, domain: str) -> Optional[ReputationData]:
        """Check domain reputation via VirusTotal API v2"""
        url = "https://www.virustotal.com/vtapi/v2/domain/report"

        try:
            async with httpx.AsyncClient(timeout=self.vt_timeout) as client:
                response = await client.get(
                    url, params={"apikey": self.virustotal_api_key, "domain": domain}
                )

                if response.status_code == 200:
                    data = response.json()
                    return self._parse_virustotal_response(data, domain, "virustotal")
                elif response.status_code == 204:
                    logger.debug("VirusTotal rate limit exceeded", domain=domain)
                    return None
                elif response.status_code == 403:
                    logger.warning("VirusTotal API key invalid or blocked")
                    return None
                else:
                    logger.warning(
                        "VirusTotal API error",
                        status=response.status_code,
                        domain=domain,
                    )
                    return None

        except httpx.TimeoutException:
            logger.warning("VirusTotal API timeout", domain=domain)
            return None
        except httpx.NetworkError as e:
            logger.warning("VirusTotal network error", domain=domain, error=str(e))
            return None
        except Exception as e:
            logger.error("VirusTotal domain check failed", domain=domain, error=str(e))
            return None

    async def _check_url_virustotal(
        self, url_to_check: str
    ) -> Optional[ReputationData]:
        """Check URL reputation via VirusTotal API v2"""
        url = "https://www.virustotal.com/vtapi/v2/url/report"

        try:
            async with httpx.AsyncClient(timeout=self.vt_timeout) as client:
                response = await client.get(
                    url,
                    params={
                        "apikey": self.virustotal_api_key,
                        "resource": url_to_check,
                    },
                )

                if response.status_code == 200:
                    data = response.json()
                    return self._parse_virustotal_response(
                        data, url_to_check, "virustotal"
                    )
                elif response.status_code == 204:
                    logger.debug("VirusTotal rate limit exceeded", url=url_to_check)
                    return None
                elif response.status_code == 403:
                    logger.warning("VirusTotal API key invalid or blocked")
                    return None
                else:
                    logger.warning(
                        "VirusTotal API error",
                        status=response.status_code,
                        url=url_to_check,
                    )
                    return None

        except httpx.TimeoutException:
            logger.warning("VirusTotal API timeout", url=url_to_check)
            return None
        except httpx.NetworkError as e:
            logger.warning("VirusTotal network error", url=url_to_check, error=str(e))
            return None
        except Exception as e:
            logger.error("VirusTotal URL check failed", url=url_to_check, error=str(e))
            return None

    async def _check_hash_virustotal(self, file_hash: str) -> Optional[ReputationData]:
        """Check file hash reputation via VirusTotal API v2"""
        url = "https://www.virustotal.com/vtapi/v2/file/report"

        try:
            async with httpx.AsyncClient(timeout=self.vt_timeout) as client:
                response = await client.get(
                    url,
                    params={"apikey": self.virustotal_api_key, "resource": file_hash},
                )

                if response.status_code == 200:
                    data = response.json()
                    return self._parse_virustotal_response(
                        data, file_hash, "virustotal"
                    )
                elif response.status_code == 204:
                    logger.debug("VirusTotal rate limit exceeded", hash=file_hash)
                    return None
                elif response.status_code == 403:
                    logger.warning("VirusTotal API key invalid or blocked")
                    return None
                else:
                    logger.warning(
                        "VirusTotal API error",
                        status=response.status_code,
                        hash=file_hash,
                    )
                    return None

        except httpx.TimeoutException:
            logger.warning("VirusTotal API timeout", hash=file_hash)
            return None
        except httpx.NetworkError as e:
            logger.warning("VirusTotal network error", hash=file_hash, error=str(e))
            return None
        except Exception as e:
            logger.error("VirusTotal hash check failed", hash=file_hash, error=str(e))
            return None

    async def _check_abuseipdb(self, ip: str) -> Optional[ReputationData]:
        """Check IP reputation via AbuseIPDB with error handling"""
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.abuseipdb_api_key, "Accept": "application/json"}

        try:
            await self._rate_limit_abuse()

            async with httpx.AsyncClient(timeout=self.abuse_timeout) as client:
                response = await client.get(
                    url,
                    headers=headers,
                    params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                )

                if response.status_code == 200:
                    data = response.json()
                    return self._parse_abuseipdb_response(data, ip)
                elif response.status_code == 429:
                    logger.debug("AbuseIPDB rate limit exceeded", ip=ip)
                    return None
                elif response.status_code == 401:
                    logger.warning("AbuseIPDB API key invalid")
                    return None
                else:
                    logger.warning(
                        "AbuseIPDB API error", status=response.status_code, ip=ip
                    )
                    return None

        except httpx.TimeoutException:
            logger.warning("AbuseIPDB API timeout", ip=ip)
            return None
        except httpx.NetworkError as e:
            logger.warning("AbuseIPDB network error", ip=ip, error=str(e))
            return None
        except Exception as e:
            logger.error("AbuseIPDB check failed", ip=ip, error=str(e))
            return None

    def _parse_virustotal_response(
        self, data: dict[str, Any], ioc_value: str, service: str
    ) -> Optional[ReputationData]:
        """Parse VirusTotal response into ReputationData"""
        try:
            response_code = data.get("response_code", 0)

            if response_code != 1:
                # Not found or error
                return ReputationData(
                    service=service,
                    ioc_value=ioc_value,
                    is_malicious=False,
                    reputation_score=0.0,
                    detections=0,
                    total_engines=0,
                    timestamp=str(time.time()),
                    cached=False,
                )

            # Parse detection results
            positives = data.get("positives", 0)
            total = data.get("total", 0)

            if total == 0:
                reputation_score = 0.0
            else:
                reputation_score = positives / total

            is_malicious = reputation_score > 0.1  # 10% threshold

            return ReputationData(
                service=service,
                ioc_value=ioc_value,
                is_malicious=is_malicious,
                reputation_score=reputation_score,
                detections=positives,
                total_engines=total,
                timestamp=str(time.time()),
                cached=False,
                metadata={
                    "scan_date": data.get("scan_date"),
                    "permalink": data.get("permalink"),
                },
            )

        except Exception as e:
            logger.error("Failed to parse VirusTotal response", error=str(e))
            return None

    def _parse_abuseipdb_response(
        self, data: dict[str, Any], ioc_value: str
    ) -> Optional[ReputationData]:
        """Parse AbuseIPDB response into ReputationData"""
        try:
            if "data" not in data:
                return None

            abuse_data = data["data"]

            abuse_confidence = abuse_data.get("abuseConfidencePercentage", 0)
            is_public = abuse_data.get("isPublic", True)
            is_whitelisted = abuse_data.get("isWhitelisted", False)

            # Convert abuse confidence to reputation score
            reputation_score = abuse_confidence / 100.0
            is_malicious = (
                reputation_score > 0.25 and not is_whitelisted
            )  # 25% threshold

            return ReputationData(
                service="abuseipdb",
                ioc_value=ioc_value,
                is_malicious=is_malicious,
                reputation_score=reputation_score,
                detections=abuse_data.get("totalReports", 0),
                total_engines=1,  # AbuseIPDB is one service
                timestamp=str(time.time()),
                cached=False,
                metadata={
                    "country_code": abuse_data.get("countryCode"),
                    "usage_type": abuse_data.get("usageType"),
                    "isp": abuse_data.get("isp"),
                    "is_public": is_public,
                    "is_whitelisted": is_whitelisted,
                    "last_reported": abuse_data.get("lastReportedAt"),
                },
            )

        except Exception as e:
            logger.error("Failed to parse AbuseIPDB response", error=str(e))
            return None

    def get_cache_stats(self) -> dict[str, Any]:
        """Get cache and service statistics"""
        current_time = time.time()
        valid_entries = sum(
            1
            for _, timestamp in self.cache.values()
            if current_time - timestamp < self.cache_ttl
        )

        return {
            "enabled": self.enabled,
            "services": {
                "virustotal": {
                    "enabled": self.vt_enabled,
                    "consecutive_failures": self.vt_consecutive_failures,
                    "rate_limit_per_minute": self.vt_rate_limit,
                },
                "abuseipdb": {
                    "enabled": self.abuse_enabled,
                    "consecutive_failures": self.abuse_consecutive_failures,
                    "rate_limit_per_minute": self.abuse_rate_limit,
                },
            },
            "cache": {
                "total_entries": len(self.cache),
                "valid_entries": valid_entries,
                "ttl_seconds": self.cache_ttl,
            },
            "errors": {
                "total_errors": self.error_count,
                "max_errors_per_session": self.max_errors_per_session,
            },
        }

    def clear_cache(self) -> int:
        """Clear the reputation cache"""
        count = len(self.cache)
        self.cache.clear()
        logger.info("Reputation cache cleared", entries_removed=count)
        return count

    def reset_error_counters(self) -> None:
        """Reset error counters"""
        self.error_count = 0
        self.vt_consecutive_failures = 0
        self.abuse_consecutive_failures = 0
        logger.info("Reputation service error counters reset")
