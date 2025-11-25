import sqlite3
import time
from pathlib import Path
from typing import Any, Optional, Union

import structlog

from ..core.models import IOCType

logger = structlog.get_logger(__name__)


class ThreatIntelDB:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        storage_config = config.get("storage", {})

        # Database setup
        self.db_path = storage_config.get("files", {}).get(
            "threat_intelligence_db", "/var/lib/afretip/threat_intelligence.db"
        )

        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)

        # Initialize database
        self._init_database()

        # Load some basic threat intel data
        self._load_initial_data()

        logger.info("Threat intelligence database initialized", db_path=self.db_path)

    def _init_database(self) -> None:
        """Initialize SQLite database with proper schema"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Create threat_iocs table with proper formatting
                conn.execute("""
                             CREATE TABLE IF NOT EXISTS threat_iocs
                             (
                                 id
                                 INTEGER
                                 PRIMARY
                                 KEY
                                 AUTOINCREMENT,
                                 ioc_value
                                 TEXT
                                 NOT
                                 NULL,
                                 ioc_type
                                 TEXT
                                 NOT
                                 NULL,
                                 source
                                 TEXT
                                 NOT
                                 NULL,
                                 threat_actor
                                 TEXT,
                                 campaign
                                 TEXT,
                                 description
                                 TEXT,
                                 confidence
                                 REAL
                                 DEFAULT
                                 1.0,
                                 created_at
                                 TEXT
                                 NOT
                                 NULL,
                                 UNIQUE
                             (
                                 ioc_value,
                                 ioc_type,
                                 source
                             )
                                 )
                             """)

                # Create indexes for performance
                conn.execute("""
                             CREATE INDEX IF NOT EXISTS idx_ioc_lookup
                                 ON threat_iocs(ioc_value, ioc_type)
                             """)

                conn.execute("""
                             CREATE INDEX IF NOT EXISTS idx_source
                                 ON threat_iocs(source)
                             """)

                conn.execute("""
                             CREATE INDEX IF NOT EXISTS idx_created_at
                                 ON threat_iocs(created_at)
                             """)

                conn.commit()
                logger.info("Threat intelligence database schema initialized")

        except Exception as e:
            logger.error("Failed to initialize threat intel database", error=str(e))
            raise

    def _load_initial_data(self) -> None:
        """Load basic threat intelligence data"""
        try:
            # Check if we already have data
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT COUNT(*) FROM threat_iocs")
                count = cursor.fetchone()[0]

            if count > 0:
                logger.info("Threat intel database already populated", ioc_count=count)
                return

            # Add some basic known bad IOCs for testing
            initial_iocs = [
                # Known malicious IPs (using real examples from threat feeds)
                (
                    "185.220.100.250",
                    "ip",
                    "manual",
                    None,
                    None,
                    "Known malicious IP",
                    1.0,
                ),
                ("194.187.249.150", "ip", "manual", None, None, "Tor exit node", 0.8),
                (
                    "45.133.1.95",
                    "ip",
                    "manual",
                    None,
                    None,
                    "Suspicious hosting provider",
                    0.7,
                ),
                # Known malicious domains
                (
                    "malware-test.com",
                    "domain",
                    "manual",
                    None,
                    None,
                    "Test malicious domain",
                    1.0,
                ),
                (
                    "phishing-example.tk",
                    "domain",
                    "manual",
                    None,
                    None,
                    "Phishing domain",
                    0.9,
                ),
                (
                    "suspicious-download.bit",
                    "domain",
                    "manual",
                    None,
                    None,
                    "Cryptocurrency mining",
                    0.8,
                ),
                # Known malicious hashes (real malware samples)
                (
                    "d41d8cd98f00b204e9800998ecf8427e",
                    "hash_md5",
                    "manual",
                    None,
                    None,
                    "Empty file hash",
                    0.3,
                ),
                (
                    "5d41402abc4b2a76b9719d911017c592",
                    "hash_md5",
                    "manual",
                    None,
                    None,
                    "Simple test hash",
                    0.5,
                ),
                (
                    "adc83b19e793491b1c6ea0fd8b46cd9f32e592fc",
                    "hash_sha1",
                    "manual",
                    None,
                    None,
                    "Another test hash",
                    0.5,
                ),
                # Suspicious file paths
                (
                    "c:\\temp\\malware.exe",
                    "file_path",
                    "manual",
                    None,
                    None,
                    "Malware in temp",
                    0.9,
                ),
                (
                    "/tmp/suspicious.sh",
                    "file_path",
                    "manual",
                    None,
                    None,
                    "Suspicious script",
                    0.8,
                ),
                # Suspicious URLs
                (
                    "http://malicious-site.tk/payload.exe",
                    "url",
                    "manual",
                    None,
                    None,
                    "Malware download",
                    1.0,
                ),
                (
                    "https://phishing-bank.com/login",
                    "url",
                    "manual",
                    None,
                    None,
                    "Phishing site",
                    0.95,
                ),
            ]

            current_time = str(time.time())

            with sqlite3.connect(self.db_path) as conn:
                for ioc_data in initial_iocs:
                    try:
                        conn.execute(
                            """
                            INSERT
                            OR IGNORE INTO threat_iocs
                            (ioc_value, ioc_type, source, threat_actor, campaign, description, confidence, created_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (*ioc_data, current_time),
                        )
                    except Exception as e:
                        logger.warning(
                            "Failed to insert initial IOC",
                            ioc=ioc_data[0],
                            error=str(e),
                        )
                        continue

                conn.commit()

            logger.info(
                "Initial threat intelligence data loaded", count=len(initial_iocs)
            )

        except Exception as e:
            logger.error("Failed to load initial threat intel data", error=str(e))

    def is_malicious(self, ioc_value: str, ioc_type: IOCType) -> dict[str, Any]:
        """Check if IOC is known malicious with proper error handling"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(
                    """
                    SELECT *
                    FROM threat_iocs
                    WHERE ioc_value = ?
                      AND ioc_type = ?
                    ORDER BY confidence DESC LIMIT 1
                    """,
                    (ioc_value, ioc_type.value),
                )

                row = cursor.fetchone()

                if row:
                    return {
                        "is_malicious": True,
                        "source": row["source"],
                        "confidence": row["confidence"],
                        "threat_actor": row["threat_actor"],
                        "campaign": row["campaign"],
                        "description": row["description"],
                        "created_at": row["created_at"],
                    }
                else:
                    return {"is_malicious": False, "source": None, "confidence": 0.0}

        except sqlite3.Error as e:
            logger.error("Database error checking IOC", ioc=ioc_value, error=str(e))
            return {"is_malicious": False, "source": None, "confidence": 0.0}
        except Exception as e:
            logger.error("Unexpected error checking IOC", ioc=ioc_value, error=str(e))
            return {"is_malicious": False, "source": None, "confidence": 0.0}

    async def add_ioc(
        self,
        ioc_value: str,
        ioc_type: IOCType,
        source: str,
        threat_actor: Optional[str] = None,
        campaign: Optional[str] = None,
        description: Optional[str] = None,
        confidence: float = 1.0,
    ) -> bool:
        """Add IOC to threat intelligence database with proper error handling"""
        try:
            # Validate inputs
            if not ioc_value or not ioc_value.strip():
                logger.warning("Empty IOC value provided")
                return False

            if not 0.0 <= confidence <= 1.0:
                logger.warning("Invalid confidence value", confidence=confidence)
                confidence = max(0.0, min(1.0, confidence))

            current_time = str(time.time())

            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO threat_iocs
                    (ioc_value, ioc_type, source, threat_actor, campaign, description, confidence, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ioc_value.strip(),
                        ioc_type.value,
                        source,
                        threat_actor,
                        campaign,
                        description,
                        confidence,
                        current_time,
                    ),
                )

                conn.commit()

            logger.info(
                "IOC added to threat intel database",
                ioc=ioc_value,
                ioc_type=ioc_type.value,
                source=source,
                confidence=confidence,
            )
            return True

        except sqlite3.Error as e:
            logger.error(
                "Database error adding IOC to threat intel database",
                ioc=ioc_value,
                error=str(e),
            )
            return False
        except Exception as e:
            logger.error(
                "Unexpected error adding IOC to threat intel database",
                ioc=ioc_value,
                error=str(e),
            )
            return False

    async def remove_ioc(self, ioc_value: str, ioc_type: IOCType, source: str) -> bool:
        """Remove IOC from threat intelligence database with proper error handling"""
        try:
            if not ioc_value or not ioc_value.strip():
                logger.warning("Empty IOC value provided for removal")
                return False

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    """
                    DELETE
                    FROM threat_iocs
                    WHERE ioc_value = ?
                      AND ioc_type = ?
                      AND source = ?
                    """,
                    (ioc_value.strip(), ioc_type.value, source),
                )

                conn.commit()

                if cursor.rowcount > 0:
                    logger.info(
                        "IOC removed from threat intel database",
                        ioc=ioc_value,
                        ioc_type=ioc_type.value,
                        source=source,
                    )
                    return True
                else:
                    logger.warning(
                        "IOC not found for removal",
                        ioc=ioc_value,
                        ioc_type=ioc_type.value,
                        source=source,
                    )
                    return False

        except sqlite3.Error as e:
            logger.error(
                "Database error removing IOC from threat intel database",
                ioc=ioc_value,
                error=str(e),
            )
            return False
        except Exception as e:
            logger.error(
                "Unexpected error removing IOC from threat intel database",
                ioc=ioc_value,
                error=str(e),
            )
            return False

    def get_statistics(self) -> dict[str, Any]:
        """Get basic threat intelligence database statistics with error handling"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Total IOCs
                cursor = conn.execute("SELECT COUNT(*) FROM threat_iocs")
                total_iocs = cursor.fetchone()[0]

                # IOCs by type
                cursor = conn.execute("""
                                      SELECT ioc_type, COUNT(*)
                                      FROM threat_iocs
                                      GROUP BY ioc_type
                                      """)
                iocs_by_type = dict(cursor.fetchall())

                # IOCs by source
                cursor = conn.execute("""
                                      SELECT source, COUNT(*)
                                      FROM threat_iocs
                                      GROUP BY source
                                      """)
                iocs_by_source = dict(cursor.fetchall())

                # Recent additions (last 24 hours)
                twenty_four_hours_ago = str(time.time() - 86400)
                cursor = conn.execute(
                    "SELECT COUNT(*) FROM threat_iocs WHERE created_at > ?",
                    (twenty_four_hours_ago,),
                )
                recent_additions = cursor.fetchone()[0]

                return {
                    "total_iocs": total_iocs,
                    "iocs_by_type": iocs_by_type,
                    "iocs_by_source": iocs_by_source,
                    "recent_additions_24h": recent_additions,
                    "database_path": self.db_path,
                    "database_size_mb": self._get_database_size(),
                }

        except sqlite3.Error as e:
            logger.error("Database error getting threat intel statistics", error=str(e))
            return {
                "total_iocs": 0,
                "iocs_by_type": {},
                "iocs_by_source": {},
                "recent_additions_24h": 0,
                "database_path": self.db_path,
                "error": str(e),
            }
        except Exception as e:
            logger.error(
                "Unexpected error getting threat intel statistics", error=str(e)
            )
            return {
                "total_iocs": 0,
                "iocs_by_type": {},
                "iocs_by_source": {},
                "recent_additions_24h": 0,
                "database_path": self.db_path,
                "error": str(e),
            }

    def search_iocs(
        self,
        ioc_type: Optional[IOCType] = None,
        source: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Search IOCs with optional filters and pagination"""
        try:
            query = "SELECT * FROM threat_iocs WHERE 1=1"
            params: list[Union[str, int]] = []

            if ioc_type:
                query += " AND ioc_type = ?"
                params.append(ioc_type.value)

            if source:
                query += " AND source = ?"
                params.append(source)

            query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params.extend([str(limit), str(offset)])

            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(query, params)

                return [dict(row) for row in cursor.fetchall()]

        except sqlite3.Error as e:
            logger.error("Database error searching IOCs", error=str(e))
            return []
        except Exception as e:
            logger.error("Unexpected error searching IOCs", error=str(e))
            return []

    def _get_database_size(self) -> float:
        """Get database file size in MB"""
        try:
            size_bytes = Path(self.db_path).stat().st_size
            return round(size_bytes / (1024 * 1024), 2)
        except Exception:
            return 0.0

    def vacuum_database(self) -> bool:
        """Vacuum database to optimize storage"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("VACUUM")
                conn.commit()

            logger.info("Database vacuumed successfully")
            return True
        except Exception as e:
            logger.error("Failed to vacuum database", error=str(e))
            return False
