import asyncio
import grp
import os
import pwd
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

import structlog

from ..core.models import WazuhRule

logger = structlog.get_logger(__name__)


class WazuhDeployer:
    def __init__(self, config: dict[str, Any], rule_generator: Optional[Any] = None):
        self.config = config
        self.rule_generator = rule_generator

        deployment_config = config.get("deployment", {})
        filesystem_config = deployment_config.get("filesystem", {})

        self.rules_dir = filesystem_config.get("rules_dir", "/var/ossec/etc/rules")
        self.custom_rules_file = os.path.join(
            self.rules_dir,
            filesystem_config.get("custom_rules_file", "threat_intel_rules.xml"),
        )
        self.backup_existing = filesystem_config.get("backup_existing", True)
        self.file_permissions = filesystem_config.get("file_permissions", "0644")
        self.owner = filesystem_config.get("owner", "ossec")
        self.group = filesystem_config.get("group", "ossec")

        restart_config = deployment_config.get("restart", {})
        self.restart_enabled = restart_config.get("enabled", False)
        self.restart_method = restart_config.get("method", "signal")
        self.signal_type = restart_config.get("signal_type", "SIGHUP")
        self.wazuh_manager_pid_file = restart_config.get(
            "wazuh_manager_pid_file", "/var/ossec/var/run/wazuh-manager.pid"
        )
        self.restart_delay = restart_config.get("delay_after_deployment", 5)

        validation_config = deployment_config.get("validation", {})
        self.validation_enabled = validation_config.get("enabled", True)
        self.check_syntax = validation_config.get("check_syntax", True)
        self.check_conflicts = validation_config.get("check_rule_conflicts", True)
        self.validation_timeout = validation_config.get("timeout", 30)

        self.deployment_enabled = deployment_config.get("enabled", False)

    async def deploy_rules(self, rules: list[WazuhRule]) -> dict[str, Any]:
        start_time = time.time()
        validation_result: dict[str, Any] = {"valid": False}

        if not self.deployment_enabled:
            deployment_time = time.time() - start_time
            logger.warning("Rule deployment is disabled in configuration")
            return {
                "success": False,
                "error": "Deployment disabled in configuration",
                "rules_deployed": 0,
                "deployment_time": deployment_time,
                "validation_passed": validation_result.get("valid", False),
                "file_path": "",
                "backup_created": False,
                "rules_validated": 0,
            }

        if not rules:
            deployment_time = time.time() - start_time
            logger.warning("No rules provided for deployment")
            return {
                "success": False,
                "error": "No rules provided",
                "rules_deployed": 0,
                "deployment_time": deployment_time,
                "validation_passed": validation_result.get("valid", False),
                "file_path": "",
                "backup_created": False,
                "rules_validated": 0,
            }

        try:
            if self.validation_enabled:
                validation_result = await self._validate_rules(rules)
                if not validation_result["valid"]:
                    deployment_time = time.time() - start_time
                    return {
                        "success": False,
                        "error": f"Rule validation failed: {validation_result['error']}",
                        "rules_deployed": 0,
                        "deployment_time": deployment_time,
                        "validation_passed": validation_result.get("valid", False),
                        "file_path": "",
                        "backup_created": False,
                        "rules_validated": len(rules),
                    }

            if self.backup_existing:
                backup_result = await self._backup_existing_rules()
                if not backup_result["success"]:
                    logger.warning(
                        "Failed to backup existing rules", error=backup_result["error"]
                    )

            xml_content = self._generate_rules_xml(rules)

            write_result = await self._write_rules_file(xml_content)
            if not write_result["success"]:
                deployment_time = time.time() - start_time
                return {
                    "success": False,
                    "error": f"Failed to write rules file: {write_result['error']}",
                    "rules_deployed": 0,
                    "deployment_time": deployment_time,
                    "validation_passed": validation_result.get("valid", False),
                    "file_path": self.custom_rules_file,
                    "backup_created": self.backup_existing,
                    "rules_validated": len(rules),
                }

            await self._set_file_permissions()

            if self.restart_enabled:
                await asyncio.sleep(self.restart_delay)
                reload_result = await self._reload_wazuh()
                if not reload_result["success"]:
                    logger.warning(
                        "Failed to reload Wazuh", error=reload_result["error"]
                    )

            logger.info(
                "Successfully deployed rules",
                rules_count=len(rules),
                file_path=self.custom_rules_file,
            )
            deployment_time = time.time() - start_time

            # Refresh rule cache after successful deployment
            if self.rule_generator:
                try:
                    self.rule_generator.refresh_rule_cache()
                    logger.info("Refreshed rule cache after successful deployment")
                except Exception as e:
                    logger.warning(f"Failed to refresh rule cache: {e}")

            return {
                "success": True,
                "rules_deployed": len(rules),
                "file_path": self.custom_rules_file,
                "backup_created": self.backup_existing,
                "deployment_time": deployment_time,
                "validation_passed": validation_result.get("valid", False),
                "rules_validated": len(rules),
            }

        except Exception as e:
            deployment_time = time.time() - start_time
            logger.error("Rule deployment failed", error=str(e))
            return {
                "success": False,
                "error": str(e),
                "rules_deployed": 0,
                "deployment_time": deployment_time,
                "validation_passed": validation_result.get("valid", False),
                "file_path": self.custom_rules_file,
                "backup_created": False,
                "rules_validated": 0,
            }

    async def _validate_rules(self, rules: list[WazuhRule]) -> dict[str, Any]:
        try:
            if self.check_conflicts:
                rule_ids = [rule.rule_id for rule in rules]
                if len(rule_ids) != len(set(rule_ids)):
                    return {
                        "valid": False,
                        "error": "Duplicate rule IDs found in generated rules",
                    }

                existing_conflicts = await self._check_existing_rule_conflicts(rule_ids)
                if existing_conflicts:
                    return {
                        "valid": False,
                        "error": f"Rule ID conflicts with existing rules: {existing_conflicts}",
                    }

            if self.check_syntax:
                xml_content = self._generate_rules_xml(rules)
                syntax_valid = await self._validate_xml_syntax(xml_content)
                if not syntax_valid:
                    return {
                        "valid": False,
                        "error": "Generated XML contains syntax errors",
                    }

            return {"valid": True}

        except Exception as e:
            return {"valid": False, "error": f"Validation error: {str(e)}"}

    async def _backup_existing_rules(self) -> dict[str, Any]:
        try:
            if not os.path.exists(self.custom_rules_file):
                return {"success": True, "message": "No existing rules file to backup"}

            timestamp = int(time.time())
            backup_file = f"{self.custom_rules_file}.backup.{timestamp}"

            shutil.copy2(self.custom_rules_file, backup_file)

            logger.info("Backed up existing rules", backup_file=backup_file)

            return {"success": True, "backup_file": backup_file}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _generate_rules_xml(self, rules: list[WazuhRule]) -> str:
        xml_parts = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            "<!-- Generated by Threat Intelligence Pipeline -->",
            '<group name="threat_intel">',
        ]

        for rule in rules:
            rule_xml = rule.to_wazuh_xml()
            xml_parts.append(f"  {rule_xml}")

        xml_parts.append("</group>")

        return "\n".join(xml_parts)

    async def _write_rules_file(self, xml_content: str) -> dict[str, Any]:
        try:
            rule_file = Path(self.custom_rules_file)

            # If file exists, read and merge existing rules
            if rule_file.exists():
                with open(rule_file, encoding='utf-8') as f:
                    existing_content = f.read()

                # Extract existing rules (between <group> tags)
                import re
                existing_rules_match = re.search(
                    r'<group name="threat_intel">(.*?)</group>',
                    existing_content,
                    re.DOTALL
                )
                existing_rules = existing_rules_match.group(1).strip() if existing_rules_match else ""

                # Extract new rules from incoming content
                new_rules_match = re.search(
                    r'<group name="threat_intel">(.*?)</group>',
                    xml_content,
                    re.DOTALL
                )
                new_rules = new_rules_match.group(1).strip() if new_rules_match else ""

                # Combine (new rules after existing)
                combined_rules = existing_rules + "\n" + new_rules

                # Rebuild complete XML with correct indentation
                xml_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<!-- Generated by Threat Intelligence Pipeline -->
<group name="threat_intel">
{combined_rules}
</group>'''

            # Write the combined content
            os.makedirs(rule_file.parent, exist_ok=True)
            with open(rule_file, "w", encoding="utf-8") as f:
                f.write(xml_content)

            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _set_file_permissions(self) -> None:
        try:
            os.chmod(self.custom_rules_file, int(self.file_permissions, 8))

            if os.geteuid() == 0:
                try:
                    uid = pwd.getpwnam(self.owner).pw_uid
                    gid = grp.getgrnam(self.group).gr_gid
                    os.chown(self.custom_rules_file, uid, gid)
                except (KeyError, OSError) as e:
                    logger.warning("Failed to set file ownership", error=str(e))

        except Exception as e:
            logger.warning("Failed to set file permissions", error=str(e))

    async def _reload_wazuh(self) -> dict[str, Any]:
        try:
            if self.restart_method == "signal":
                return await self._reload_via_signal()
            elif self.restart_method == "systemctl":
                return await self._reload_via_systemctl()
            else:
                return {
                    "success": False,
                    "error": f"Unknown restart method: {self.restart_method}",
                }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _reload_via_signal(self) -> dict[str, Any]:
        try:
            if not os.path.exists(self.wazuh_manager_pid_file):
                return {
                    "success": False,
                    "error": f"Wazuh manager PID file not found: {self.wazuh_manager_pid_file}",
                }

            with open(self.wazuh_manager_pid_file) as f:
                pid = int(f.read().strip())

            signal_num = getattr(signal, self.signal_type)
            os.kill(pid, signal_num)

            logger.info(
                "Sent reload signal to Wazuh manager", pid=pid, signal=self.signal_type
            )

            return {"success": True}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _reload_via_systemctl(self) -> dict[str, Any]:
        try:
            result = subprocess.run(
                ["systemctl", "reload", "wazuh-manager"],
                capture_output=True,
                text=True,
                timeout=self.validation_timeout,
            )

            if result.returncode == 0:
                logger.info("Successfully reloaded Wazuh via systemctl")
                return {"success": True}
            else:
                return {
                    "success": False,
                    "error": f"systemctl reload failed: {result.stderr}",
                }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "systemctl reload timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _check_existing_rule_conflicts(self, rule_ids: list[int]) -> list[int]:
        conflicts: list[int] = []

        if os.path.exists(self.custom_rules_file):
            try:
                with open(self.custom_rules_file) as f:
                    content = f.read()

                    for rule_id in rule_ids:
                        if f'id="{rule_id}"' in content:
                            conflicts.append(rule_id)

            except Exception as e:
                logger.warning("Failed to check existing rule conflicts", error=str(e))

        return conflicts

    async def _validate_xml_syntax(self, xml_content: str) -> bool:
        try:
            from xml.etree import ElementTree

            ElementTree.fromstring(xml_content)
            return True
        except Exception:
            return False

    def get_deployment_status(self) -> dict[str, Any]:
        return {
            "deployment_enabled": self.deployment_enabled,
            "rules_file": self.custom_rules_file,
            "rules_file_exists": os.path.exists(self.custom_rules_file),
            "rules_dir": self.rules_dir,
            "rules_dir_exists": os.path.exists(self.rules_dir),
            "backup_enabled": self.backup_existing,
            "reload_enabled": self.restart_enabled,
            "reload_method": self.restart_method,
        }
