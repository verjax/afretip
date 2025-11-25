import asyncio
import time
from typing import TYPE_CHECKING, Any, Optional

import structlog

# Fix circular import by using TYPE_CHECKING
if TYPE_CHECKING:
    from ..analytics.metrics import AnalyticsMetrics

from ..connectors.wazuh_connector import WazuhConnector
from ..core.models import WazuhRawLog
from ..defence.wazuh_deployer import WazuhDeployer
from ..detectors.threat_detector import ThreatDetector
from ..enrichment.ioc_classifier import IOCClassifier
from ..enrichment.threat_feed_manager import ThreatFeedManager
from ..enrichment.threat_intel_db import ThreatIntelDB
from ..extractors.ioc_extractor import IOCExtractor
from ..generators.rule_generator import WazuhRuleGenerator

logger = structlog.get_logger(__name__)


class ProcessingEngine:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.running = False

        # Processing configuration
        processing_config = config.get("processing", {})
        self.batch_size = processing_config.get("batch_size", 10)
        self.processing_interval = processing_config.get("processing_interval", 1.0)

        # Initialize components
        self.wazuh_connector = WazuhConnector(config)
        self.ioc_extractor = IOCExtractor(config)
        self.ioc_classifier = IOCClassifier(config)
        self.threat_intel_db = ThreatIntelDB(config)
        self.threat_detector = ThreatDetector(config)
        self.rule_generator = WazuhRuleGenerator()
        self.rule_generator = WazuhRuleGenerator(
            rules_directory=config.get("deployment", {})
            .get("filesystem", {})
            .get("rules_dir", "/var/ossec/etc/rules")
        )
        self.wazuh_deployer = WazuhDeployer(config, rule_generator=self.rule_generator)

        # Initialize automated threat feed manager
        self.threat_feed_manager = ThreatFeedManager(
            config=self.config,
            threat_intel_db=self.threat_intel_db
        )

        analytics_config = config.get("analytics", {})
        if analytics_config.get("enabled", False):
            from ..analytics.metrics import initialize_analytics

            self.analytics_metrics: Optional[AnalyticsMetrics] = initialize_analytics(
                config
            )
            logger.info("Analytics metrics enabled for data collection")
        else:
            self.analytics_metrics = None
            logger.info("Analytics metrics disabled")

        # Processing queues
        self.log_queue: asyncio.Queue[WazuhRawLog] = asyncio.Queue(maxsize=1000)
        self.finding_queue: asyncio.Queue = asyncio.Queue(maxsize=500)

        # Rule deployment batching
        self.pending_rules: list = []  # Accumulate rules for batch deployment
        self.last_deployment_time = time.time()
        self.deployment_interval = config.get("deployment", {}).get(
            "batch_interval_seconds", 60
        )  # Deploy every 60 seconds by default
        self.deployment_batch_size = config.get("deployment", {}).get(
            "batch_size", 10
        )  # Or when 10 rules accumulated

        # Performance tracking
        self.performance_metrics: dict[str, Any] = {
            "logs_processed": 0,
            "iocs_extracted": 0,
            "threats_detected": 0,
            "rules_generated": 0,
            "rules_deployed": 0,
            "processing_errors": 0,
            "start_time": 0.0,
        }

        logger.info(
            "Processing engine initialized",
            deployment_batching=True,
            batch_interval=self.deployment_interval,
            batch_size=self.deployment_batch_size
        )

    async def start(self) -> None:
        """Start the processing engine"""
        if self.running:
            logger.warning("Processing engine already running")
            return

        self.running = True
        self.performance_metrics["start_time"] = time.time()

        logger.info("Starting threat intelligence processing engine")

        try:
            # Start threat feed updates first
            logger.info("Starting automated threat feed updates")
            await self.threat_feed_manager.start_feed_updates()

            # Start all processing tasks concurrently
            tasks = [
                asyncio.create_task(self._log_ingestion_task()),
                asyncio.create_task(self._log_processing_task()),
                asyncio.create_task(self._threat_processing_task()),
                asyncio.create_task(self._performance_monitoring_task()),
            ]

            # Wait for any task to complete (should run indefinitely)
            done, pending = await asyncio.wait(
                tasks, return_when=asyncio.FIRST_COMPLETED
            )

            # Cancel remaining tasks
            for task in pending:
                task.cancel()

            # Check for exceptions
            for task in done:
                try:
                    await task
                except Exception as e:
                    logger.error("Task completed with error", error=str(e))

        except KeyboardInterrupt:
            logger.info("Received interrupt signal, shutting down...")
        except Exception as e:
            logger.error("Processing engine error", error=str(e))
            raise
        finally:
            await self.stop()

    async def stop(self) -> None:
        """Stop the processing engine"""
        if not self.running:
            return

        logger.info("Stopping processing engine")

        # Deploy any pending rules before shutdown
        if self.pending_rules:
            deployment_config = self.config.get("deployment", {})
            if deployment_config.get("enabled", False):
                logger.info(
                    "Deploying pending rules before shutdown",
                    pending_count=len(self.pending_rules)
                )
                try:
                    await self.wazuh_deployer.deploy_rules(self.pending_rules)
                except Exception as e:
                    logger.error("Failed to deploy pending rules on shutdown", error=str(e))

        # Stop threat feed updates
        await self.threat_feed_manager.stop_feed_updates()

        self.running = False

        # Export analytics data if metrics enabled
        if self.analytics_metrics:
            try:
                exported_files = self.analytics_metrics.export_analytics_data(
                    format="csv"
                )
                logger.info("Analytics data exported on shutdown", files=exported_files)
            except Exception as e:
                logger.warning("Error exporting analytics data", error=str(e))

        logger.info("Processing engine stopped")

    async def _log_ingestion_task(self) -> None:
        """Task for ingesting logs from Wazuh"""
        logger.info("Starting log ingestion task")

        try:
            async for log in self.wazuh_connector.start_streaming():
                if not self.running:
                    break

                try:
                    await self.log_queue.put(log)

                except asyncio.QueueFull:
                    logger.warning("Log queue full, dropping log")
                    self.performance_metrics["processing_errors"] += 1

                    # Record error in analytics metrics
                    if self.analytics_metrics:
                        self.analytics_metrics.record_processing_error("queue_full")

        except Exception as e:
            logger.error("Log ingestion task error", error=str(e))
            self.performance_metrics["processing_errors"] += 1

            if self.analytics_metrics:
                self.analytics_metrics.record_processing_error("ingestion_error")

    async def _log_processing_task(self) -> None:
        """Task for processing logs and extracting IOCs"""
        logger.info("Starting log processing task")

        while self.running:
            try:
                logs: list[WazuhRawLog] = []
                deadline = time.time() + self.processing_interval

                while len(logs) < self.batch_size and time.time() < deadline:
                    try:
                        log = await asyncio.wait_for(
                            self.log_queue.get(),
                            timeout=max(0.1, deadline - time.time()),
                        )
                        logs.append(log)
                    except asyncio.TimeoutError:
                        break

                if logs:
                    await self._process_log_batch(logs)
                else:
                    await asyncio.sleep(0.1)

            except Exception as e:
                logger.error("Log processing task error", error=str(e))
                self.performance_metrics["processing_errors"] += 1

                if self.analytics_metrics:
                    self.analytics_metrics.record_processing_error("processing_error")

                await asyncio.sleep(1.0)

    async def _process_log_batch(self, logs: list[WazuhRawLog]) -> None:
        """Process a batch of logs"""
        batch_start_time = time.time()

        for log in logs:
            try:
                log_start_time = time.time()

                # Extract IOCs from log
                iocs = await self.ioc_extractor.extract_iocs(log)

                # Update performance metrics
                self.performance_metrics["logs_processed"] += 1
                self.performance_metrics["iocs_extracted"] += len(iocs)

                log_processing_time = time.time() - log_start_time

                # Collect analytics performance metrics - lazy import
                if self.analytics_metrics:
                    from ..analytics.metrics import collect_performance_data

                    collect_performance_data(1, log_processing_time)

                if iocs:
                    # Detect threats
                    findings = await self.threat_detector.detect_threats(iocs, log)

                    # Update performance metrics
                    self.performance_metrics["threats_detected"] += len(findings)

                    # Queue findings for rule generation
                    for finding in findings:
                        try:
                            await self.finding_queue.put(finding)
                        except asyncio.QueueFull:
                            logger.warning("Finding queue full, dropping finding")
                            self.performance_metrics["processing_errors"] += 1

                            if self.analytics_metrics:
                                self.analytics_metrics.record_processing_error(
                                    "finding_queue_full"
                                )

            except Exception as e:
                logger.error(
                    "Error processing log", log_hash=log.log_hash, error=str(e)
                )
                self.performance_metrics["processing_errors"] += 1

                if self.analytics_metrics:
                    self.analytics_metrics.record_processing_error(
                        "log_processing_error"
                    )

                continue

        batch_processing_time = time.time() - batch_start_time
        logger.debug(
            "Processed log batch",
            count=len(logs),
            processing_time=batch_processing_time,
        )

    async def _threat_processing_task(self) -> None:
        """Task for processing threats and generating rules"""
        logger.info("Starting threat processing task")

        while self.running:
            try:
                try:
                    finding = await asyncio.wait_for(
                        self.finding_queue.get(), timeout=1.0
                    )
                except asyncio.TimeoutError:
                    # Check if it's time to deploy accumulated rules
                    await self._check_and_deploy_rules()
                    continue

                # Generate rule for finding
                generation_start = time.time()
                rules = self.rule_generator.generate_rules_from_finding(finding)
                generation_time = time.time() - generation_start

                if rules:
                    # Update performance metrics
                    self.performance_metrics["rules_generated"] += len(rules)

                    # Collect analytics metrics for rule generation
                    if self.analytics_metrics:
                        for rule in rules:
                            self.analytics_metrics.collect_rule_metrics(
                                rule, generation_time
                            )

                    # Add to pending rules batch
                    deployment_config = self.config.get("deployment", {})
                    if deployment_config.get("enabled", False):
                        self.pending_rules.extend(rules)
                        logger.debug(
                            "Added rules to deployment batch",
                            rules_added=len(rules),
                            pending_total=len(self.pending_rules)
                        )

                        # Check if we should deploy now
                        await self._check_and_deploy_rules()

            except Exception as e:
                logger.error("Threat processing task error", error=str(e))
                self.performance_metrics["processing_errors"] += 1

                if self.analytics_metrics:
                    self.analytics_metrics.record_processing_error(
                        "threat_processing_error"
                    )

                await asyncio.sleep(1.0)

    async def _check_and_deploy_rules(self) -> None:
        """Check if rules should be deployed based on batch size or time interval"""
        if not self.pending_rules:
            return

        current_time = time.time()
        time_since_last_deployment = current_time - self.last_deployment_time

        # Deploy if batch is large enough OR time interval passed
        should_deploy = (
            len(self.pending_rules) >= self.deployment_batch_size or
            time_since_last_deployment >= self.deployment_interval
        )

        if should_deploy:
            logger.info(
                "Deploying rule batch",
                rules_count=len(self.pending_rules),
                reason="batch_size" if len(self.pending_rules) >= self.deployment_batch_size else "time_interval"
            )

            try:
                deployment_result = await self.wazuh_deployer.deploy_rules(
                    self.pending_rules
                )

                if deployment_result.get("success", False):
                    deployed_count = deployment_result.get("rules_deployed", 0)
                    self.performance_metrics["rules_deployed"] += deployed_count

                    if self.analytics_metrics:
                        self.analytics_metrics.collect_deployment_metrics(
                            self.pending_rules,
                            deployment_result,
                            deployment_result.get("deployment_time", 0)
                        )

                    logger.info(
                        "Rule batch deployed successfully",
                        rules_deployed=deployed_count
                    )

                    # Clear pending rules after successful deployment
                    self.pending_rules = []
                    self.last_deployment_time = current_time
                else:
                    logger.error(
                        "Rule batch deployment failed",
                        error=deployment_result.get("error", "Unknown error")
                    )

            except Exception as e:
                logger.error("Rule deployment failed", error=str(e))
                self.performance_metrics["processing_errors"] += 1

                if self.analytics_metrics:
                    self.analytics_metrics.record_processing_error(
                        "deployment_error"
                    )

    async def _performance_monitoring_task(self) -> None:
        """Task for monitoring performance and recording metrics"""
        logger.info("Starting performance monitoring task")

        while self.running:
            try:
                await asyncio.sleep(30.0)  # Record metrics every 30 seconds

                # Log current performance metrics
                uptime = time.time() - self.performance_metrics["start_time"]
                logger.info(
                    "Performance metrics",
                    uptime=f"{uptime:.1f}s",
                    logs_processed=self.performance_metrics["logs_processed"],
                    iocs_extracted=self.performance_metrics["iocs_extracted"],
                    threats_detected=self.performance_metrics["threats_detected"],
                    rules_generated=self.performance_metrics["rules_generated"],
                    rules_deployed=self.performance_metrics["rules_deployed"],
                    processing_errors=self.performance_metrics["processing_errors"],
                    log_queue_size=self.log_queue.qsize(),
                    finding_queue_size=self.finding_queue.qsize(),
                    pending_rules=len(self.pending_rules)  # Show pending rules
                )

            except Exception as e:
                logger.error("Performance monitoring error", error=str(e))

    async def process_single_log(self, log: WazuhRawLog) -> dict[str, Any]:
        """Process a single log and return results (for testing)"""
        results = {
            "log_hash": log.log_hash,
            "iocs": [],
            "findings": [],
            "rules": [],
            "processing_time": 0.0,
        }

        start_time = time.time()

        try:
            # Extract IOCs
            iocs = await self.ioc_extractor.extract_iocs(log)
            results["iocs"] = [ioc.dict() for ioc in iocs]

            if iocs:
                # Detect threats
                findings = await self.threat_detector.detect_threats(iocs, log)
                results["findings"] = [finding.dict() for finding in findings]

                # Generate rules
                rules = []
                for finding in findings:
                    generated_rules = self.rule_generator.generate_rules_from_finding(
                        finding
                    )
                    rules.extend(generated_rules)

                results["rules"] = [rule.dict() for rule in rules]

            results["processing_time"] = time.time() - start_time

        except Exception as e:
            logger.error("Error processing single log", error=str(e))
            results["error"] = str(e)
            results["processing_time"] = time.time() - start_time

        return results

    def get_performance_summary(self) -> dict[str, Any]:
        """Get current performance summary"""
        uptime = 0.0
        if self.performance_metrics["start_time"]:
            uptime = time.time() - self.performance_metrics["start_time"]

        # Calculate rates
        logs_per_second = 0.0
        iocs_per_second = 0.0
        if uptime > 0:
            logs_per_second = self.performance_metrics["logs_processed"] / uptime
            iocs_per_second = self.performance_metrics["iocs_extracted"] / uptime

        summary = {
            "status": "running" if self.running else "stopped",
            "uptime_seconds": uptime,
            "performance_metrics": dict(self.performance_metrics),
            "processing_rates": {
                "logs_per_second": logs_per_second,
                "iocs_per_second": iocs_per_second,
            },
            "queue_status": {
                "log_queue_size": self.log_queue.qsize(),
                "log_queue_capacity": self.log_queue.maxsize,
                "finding_queue_size": self.finding_queue.qsize(),
                "finding_queue_capacity": self.finding_queue.maxsize,
            },
            "deployment_status": {
                "pending_rules": len(self.pending_rules),
                "last_deployment": self.last_deployment_time,
                "deployment_interval": self.deployment_interval,
                "deployment_batch_size": self.deployment_batch_size
            }
        }

        # Add analytics metrics if available
        if self.analytics_metrics:
            summary["analytics_metrics"] = self.analytics_metrics.get_realtime_stats()

        return summary

    def get_threat_feed_status(self) -> dict[str, Any]:
        """Get current threat feed status"""
        return self.threat_feed_manager.get_feed_status()

    async def update_threat_feeds_manually(self) -> dict[str, Any]:
        """Manually trigger threat feed updates"""
        logger.info("Manual threat feed update triggered")
        await self.threat_feed_manager.update_all_feeds()
        return self.get_threat_feed_status()
