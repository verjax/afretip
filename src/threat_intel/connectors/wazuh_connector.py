import asyncio
import json
import socket
from collections.abc import AsyncGenerator
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import aiofiles
import structlog

from ..core.models import WazuhRawLog

logger = structlog.get_logger(__name__)


class WazuhConnector:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.wazuh_config = config["wazuh"]
        self.running = False
        self.connection = None
        self.error_count = 0
        self.max_errors = 100

    async def connect_socket(self, socket_path: str) -> Optional[socket.socket]:
        try:
            if not Path(socket_path).exists():
                logger.warning("Socket not found", path=socket_path)
                return None

            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

            sock.connect(socket_path)
            logger.info("Connected to Wazuh socket", path=socket_path)

            sock.setblocking(False)
            return sock

        except Exception as e:
            logger.error("Failed to connect to socket", path=socket_path, error=str(e))
            return None

    async def stream_from_socket(
            self, socket_path: str
    ) -> AsyncGenerator[WazuhRawLog, None]:
        sock = await self.connect_socket(socket_path)
        if not sock:
            return

        self.running = True
        buffer = b""

        try:
            while self.running:
                try:
                    loop = asyncio.get_event_loop()
                    data = await loop.run_in_executor(
                        None, self._recv_socket_data, sock
                    )

                    if not data:
                        await asyncio.sleep(0.1)
                        continue

                    buffer += data
                    self.error_count = 0

                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        if line.strip():
                            raw_log = await self._parse_log_line(line)
                            if raw_log:
                                yield raw_log

                except OSError:
                    await asyncio.sleep(0.1)
                except Exception as e:
                    self.error_count += 1
                    logger.warning(
                        "Socket streaming error",
                        error=str(e),
                        error_count=self.error_count,
                    )

                    if self.error_count >= self.max_errors:
                        logger.error("Too many socket errors, stopping")
                        break

                    await asyncio.sleep(1)

        except Exception as e:
            logger.error("Socket streaming fatal error", error=str(e))
        finally:
            if sock:
                sock.close()

    def _recv_socket_data(self, sock: socket.socket) -> bytes:
        try:
            return sock.recv(65535)
        except OSError:
            return b""

    async def stream_from_file(
            self, file_path: str
    ) -> AsyncGenerator[WazuhRawLog, None]:
        try:
            if not Path(file_path).exists():
                logger.error("Wazuh archives file not found", file=file_path)
                return

            logger.info("Starting file monitoring", file=file_path)

            async with aiofiles.open(file_path) as f:
                await f.seek(0, 2)

                while self.running:
                    line = await f.readline()
                    if line:
                        raw_log = await self._parse_log_line(line.encode())
                        if raw_log:
                            yield raw_log
                        self.error_count = 0
                    else:
                        await asyncio.sleep(0.5)

        except Exception as e:
            logger.error("File streaming error", file=file_path, error=str(e))

    async def _parse_log_line(self, line: bytes) -> Optional[WazuhRawLog]:
        try:
            line_str = line.decode("utf-8").strip()
            if not line_str:
                return None

            try:
                log_data = json.loads(line_str)
                return self.parse_raw_log(log_data)
            except json.JSONDecodeError:
                return self.parse_text_log(line_str)

        except Exception as e:
            self.error_count += 1
            if self.error_count <= 10:
                logger.warning(
                    "Error parsing log line", error=str(e), line_preview=line[:100]
                )
            return None

    def parse_raw_log(self, log_data: dict[str, Any]) -> Optional[WazuhRawLog]:
        try:
            # Skip AFRETIP's own logs
            location = log_data.get("location", "")
            if "afretip" in location.lower():
                return None

            # Skip logs with threat_intel logger
            if "logger" in log_data:
                logger_name = str(log_data.get("logger", ""))
                if "threat_intel" in logger_name:
                    return None

            # Skip logs from Wazuh manager itself (only process agent logs)
            agent = log_data.get("agent", {})
            if isinstance(agent, dict):
                agent_name = agent.get("name", "")
                manager_names = ["seminarioST", "localhost", "wazuh-manager", "(local)"]
                if any(name in agent_name for name in manager_names):
                    return None

            timestamp = None
            if "timestamp" in log_data:
                timestamp_str = log_data["timestamp"]
                if timestamp_str.endswith("Z"):
                    timestamp_str = timestamp_str[:-1] + "+00:00"
                try:
                    timestamp = datetime.fromisoformat(timestamp_str)
                except ValueError:
                    timestamp = datetime.utcnow()

            rule_info = log_data.get("rule", {})
            rule_id = rule_info.get("id") if isinstance(rule_info, dict) else None
            rule_level = rule_info.get("level") if isinstance(rule_info, dict) else None
            description = (
                rule_info.get("description") if isinstance(rule_info, dict) else None
            )

            full_log = log_data.get("full_log")
            if not full_log:
                full_log = json.dumps(log_data)

            flattened_fields = self._flatten_wazuh_json(log_data)

            return WazuhRawLog(
                timestamp=timestamp,
                rule_id=rule_id,
                rule_level=rule_level,
                description=description,
                full_log=full_log,
                source_system=self._extract_source_system(log_data),
                source_ip=log_data.get("source_ip"),
                user=self._extract_user(log_data),
                agent=log_data.get("agent"),
                location=log_data.get("location"),
                predecoder=log_data.get("predecoder"),
                decoder=log_data.get("decoder"),
                raw_data=log_data,
                flattened_fields=flattened_fields,
            )

        except Exception as e:
            logger.debug("Failed to parse log data", error=str(e))
            return None

    def _flatten_wazuh_json(self, data: dict, prefix: str = "") -> dict[str, Any]:
        """Flatten nested JSON structures for universal field access"""
        flattened = {}

        for key, value in data.items():
            new_key = f"{prefix}.{key}" if prefix else key

            if isinstance(value, dict):
                flattened.update(self._flatten_wazuh_json(value, new_key))
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        flattened.update(self._flatten_wazuh_json(item, f"{new_key}.{i}"))
                    else:
                        flattened[f"{new_key}.{i}"] = str(item) if item is not None else ""
            else:
                flattened[new_key] = str(value) if value is not None else ""

        return flattened

    def _extract_source_system(self, log_data: dict[str, Any]) -> str:
        agent = log_data.get("agent")
        if isinstance(agent, dict):
            name = agent.get("name")
            if name:
                return str(name)
        elif isinstance(agent, str):
            return agent

        manager = log_data.get("manager", {})
        if isinstance(manager, dict):
            name = manager.get("name")
            if name:
                return str(name)

        predecoder = log_data.get("predecoder", {})
        if isinstance(predecoder, dict):
            hostname = predecoder.get("hostname")
            if hostname:
                return str(hostname)

        location = log_data.get("location")
        if location:
            return str(location)

        return "unknown"

    def _extract_user(self, log_data: dict[str, Any]) -> Optional[str]:
        data = log_data.get("data", {})
        if isinstance(data, dict):
            user = data.get("srcuser") or data.get("dstuser") or data.get("user")
            if user:
                return str(user).split("(")[0]

        decoder = log_data.get("decoder", {})
        if isinstance(decoder, dict):
            user = decoder.get("user")
            if user:
                return str(user)

        return None

    def parse_text_log(self, log_text: str) -> Optional[WazuhRawLog]:
        if not log_text.strip():
            return None

        return WazuhRawLog(
            timestamp=datetime.utcnow(),
            full_log=log_text.strip(),
            source_system="text_log",
        )

    async def start_streaming(self) -> AsyncGenerator[WazuhRawLog, None]:
        self.running = True
        logger.info("Starting log streaming")

        if self.wazuh_config["connection"]["use_socket"]:
            socket_path = self.wazuh_config["sockets"]["archives"]
            logger.info("Using socket monitoring", path=socket_path)
            async for log in self.stream_from_socket(socket_path):
                yield log
        else:
            file_path = self.wazuh_config["files"]["archives"]
            logger.info("Using file monitoring", path=file_path)
            async for log in self.stream_from_file(file_path):
                yield log

    def stop(self) -> None:
        self.running = False
        logger.info("Stopping Wazuh connector")
