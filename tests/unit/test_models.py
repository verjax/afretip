"""
Test data models.
"""

from datetime import datetime, timezone

from src.threat_intel.core.models import ExtractedIOC, IOCType, WazuhRawLog


def test_wazuh_raw_log_creation():
    """Test WazuhRawLog model creation"""
    log = WazuhRawLog(
        timestamp=datetime.now(timezone.utc),
        full_log="test log message",
        agent={"name": "test-server"}
    )

    assert log.full_log == "test log message"
    assert log.source_system == "test-server"
    assert log.log_hash  # Should be generated

def test_extracted_ioc_creation():
    """Test ExtractedIOC model creation"""
    ioc = ExtractedIOC(
        type=IOCType.IP,
        value="192.168.1.1",
        confidence=0.8,
        context="test context",
        source_log_hash="test_hash"
    )

    assert ioc.type == IOCType.IP
    assert ioc.value == "192.168.1.1"
    assert ioc.confidence == 0.8
    assert ioc.id  # Should be generated
