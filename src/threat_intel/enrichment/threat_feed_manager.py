import asyncio
import csv
import time
from datetime import datetime
from typing import Any

import aiohttp
import structlog

from ..core.models import IOCType
from .threat_intel_db import ThreatIntelDB

logger = structlog.get_logger(__name__)


class ThreatFeedManager:
    """Manages automated threat intelligence feed ingestion"""

    def __init__(self, config: dict[str, Any], threat_intel_db: ThreatIntelDB):
        self.threat_intel_db = threat_intel_db
        self.config = config
        self.feed_cache = {}
        self.last_update_times = {}
        self.running = False

        logger.info("Threat Feed Manager initialized",
                    feeds_configured=len(self.config.get('feeds', {})))

    async def start_feed_updates(self):
        """Start automated feed update process"""
        if not self.config.get('auto_update_feeds', False):
            logger.info("Automatic feed updates disabled")
            return

        self.running = True
        logger.info("Starting automated threat feed updates")

        # Initial feed load
        await self.update_all_feeds()

        # Start periodic update task
        asyncio.create_task(self._periodic_update_task())

    async def stop_feed_updates(self):
        """Stop automated feed updates"""
        self.running = False
        logger.info("Stopped threat feed updates")

    async def _periodic_update_task(self):
        """Periodic task to check and update feeds"""
        check_interval = self.config.get('update_check_interval_minutes', 30) * 60

        while self.running:
            try:
                await asyncio.sleep(check_interval)
                await self.update_all_feeds()
            except Exception as e:
                logger.error("Error in periodic update task", error=str(e))

    async def update_all_feeds(self):
        """Update all enabled feeds that are due for refresh"""
        feeds = self.config.get('feeds', {})

        for feed_name, feed_config in feeds.items():
            if not feed_config.get('enabled', False):
                continue

            if self._is_feed_due_for_update(feed_name, feed_config):
                await self.update_feed(feed_name, feed_config)

    def _is_feed_due_for_update(self, feed_name: str, feed_config: dict[str, Any]) -> bool:
        """Check if feed needs updating based on interval"""
        if feed_name not in self.last_update_times:
            return True

        last_update = self.last_update_times[feed_name]
        update_interval = feed_config.get('update_interval_hours', 24) * 3600

        return time.time() - last_update > update_interval

    async def update_feed(self, feed_name: str, feed_config: dict[str, Any]):
        """Download and process a single threat feed"""
        url = feed_config.get('url')
        confidence = feed_config.get('confidence', 0.8)

        if not url:
            logger.warning("No URL configured for feed", feed=feed_name)
            return

        try:
            logger.info("Updating threat feed", feed=feed_name, url=url)

            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=60)) as response:
                    if response.status == 200:
                        content = await response.text()
                        await self._process_feed_content(feed_name, content, confidence)
                        self.last_update_times[feed_name] = time.time()
                        logger.info("Successfully updated feed", feed=feed_name)
                    else:
                        logger.error("Failed to download feed",
                                     feed=feed_name, status=response.status)

        except Exception as e:
            logger.error("Error updating feed", feed=feed_name, error=str(e))

    async def _process_feed_content(self, feed_name: str, content: str, confidence: float):
        """Process downloaded feed content and extract IOCs"""
        if 'malware' in feed_name:
            await self._process_hash_feed(content, confidence, feed_name)
        elif 'urlhaus' in feed_name:
            await self._process_url_feed(content, confidence, feed_name)
        elif 'ipblocklist' in feed_name or 'feodo' in feed_name:
            await self._process_ip_feed(content, confidence, feed_name)
        elif 'ssl' in feed_name:
            await self._process_ssl_feed(content, confidence, feed_name)
        else:
            logger.warning("Unknown feed type", feed=feed_name)

    async def _process_hash_feed(self, content: str, confidence: float, source: str):
        """Process hash-based feeds (SHA256, MD5, etc.)"""
        iocs_added = 0

        for line in content.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Determine hash type by length
            if len(line) == 32:
                ioc_type = IOCType.HASH_MD5
            elif len(line) == 40:
                ioc_type = IOCType.HASH_SHA1
            elif len(line) == 64:
                ioc_type = IOCType.HASH_SHA256
            else:
                continue

            # Add to threat intelligence database
            success = await self.threat_intel_db.add_ioc(
                ioc_value=line,
                ioc_type=ioc_type,
                source=source,
                description=f"Malicious hash from {source}",
                confidence=confidence
            )

            if success:
                iocs_added += 1

        logger.info("Processed hash feed", source=source, iocs_added=iocs_added)

    async def _process_url_feed(self, content: str, confidence: float, source: str):
        """Process URL-based feeds (URLhaus CSV format)"""
        iocs_added = 0

        try:
            # Parse CSV content
            lines = content.strip().split('\n')
            reader = csv.reader(lines)

            # Skip header if present
            header = next(reader, None)
            if header and 'url' not in header[0].lower():
                # Reset reader if no header found
                reader = csv.reader(lines)

            for row in reader:
                if not row or row[0].startswith('#'):
                    continue

                # URLhaus CSV format: id,dateadded,url,url_status,threat,tags,urlhaus_link
                if len(row) >= 3:
                    url = row[2].strip()
                    if url and url.startswith(('http://', 'https://')):
                        success = await self.threat_intel_db.add_ioc(
                            ioc_value=url,
                            ioc_type=IOCType.URL,
                            source=source,
                            description=f"Malicious URL from {source}",
                            confidence=confidence
                        )

                        if success:
                            iocs_added += 1

        except Exception as e:
            logger.error("Error processing URL feed", source=source, error=str(e))

        logger.info("Processed URL feed", source=source, iocs_added=iocs_added)

    async def _process_ip_feed(self, content: str, confidence: float, source: str):
        """Process IP-based feeds"""
        iocs_added = 0

        for line in content.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Handle both plain IPs and CIDR notation
            ip = line.split('/')[0]  # Remove CIDR if present

            # Basic IP validation
            if self._is_valid_ip(ip):
                success = await self.threat_intel_db.add_ioc(
                    ioc_value=ip,
                    ioc_type=IOCType.IP,
                    source=source,
                    description=f"Malicious IP from {source}",
                    confidence=confidence
                )

                if success:
                    iocs_added += 1

        logger.info("Processed IP feed", source=source, iocs_added=iocs_added)

    async def _process_ssl_feed(self, content: str, confidence: float, source: str):
        """Process SSL blacklist feeds"""
        iocs_added = 0

        try:
            lines = content.strip().split('\n')
            reader = csv.reader(lines)

            for row in reader:
                if not row or row[0].startswith('#'):
                    continue

                # SSL blacklist format typically has IP in first column
                if len(row) >= 1:
                    ip = row[0].strip()
                    if self._is_valid_ip(ip):
                        success = await self.threat_intel_db.add_ioc(
                            ioc_value=ip,
                            ioc_type=IOCType.IP,
                            source=source,
                            description=f"SSL blacklist IP from {source}",
                            confidence=confidence
                        )

                        if success:
                            iocs_added += 1

        except Exception as e:
            logger.error("Error processing SSL feed", source=source, error=str(e))

        logger.info("Processed SSL feed", source=source, iocs_added=iocs_added)

    def _is_valid_ip(self, ip: str) -> bool:
        """Basic IP address validation"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False

        try:
            for part in parts:
                num = int(part)
                if not 0 <= num <= 255:
                    return False
            return True
        except ValueError:
            return False

    def get_feed_status(self) -> dict[str, Any]:
        """Get status of all configured feeds"""
        feeds = self.config.get('feeds', {})
        status = {}

        for feed_name, feed_config in feeds.items():
            last_update = self.last_update_times.get(feed_name, 0)

            status[feed_name] = {
                'enabled': feed_config.get('enabled', False),
                'url': feed_config.get('url', ''),
                'confidence': feed_config.get('confidence', 0.8),
                'update_interval_hours': feed_config.get('update_interval_hours', 24),
                'last_update': datetime.fromtimestamp(last_update).isoformat() if last_update else 'Never',
                'due_for_update': self._is_feed_due_for_update(feed_name, feed_config)
            }

        return status
