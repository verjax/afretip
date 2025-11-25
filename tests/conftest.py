import pytest


@pytest.fixture
def sample_wazuh_log():
    """Sample Wazuh log for testing"""
    return {
        "timestamp": "2024-06-06T10:30:00Z",
        "agent": {"name": "test-server", "ip": "192.168.1.100"},
        "location": "Windows Security",
        "full_log": 'powershell.exe -WindowStyle Hidden -Command "test command"',
        "predecoder": {"program_name": "powershell.exe"},
    }


@pytest.fixture
def config():
    """Test configuration"""
    return {
        "processing": {
            "confidence_threshold": 0.6,
            "novelty_threshold": 0.7,
            "batch_size": 10,
        },
        "logging": {"level": "DEBUG"},
    }
