#!/usr/bin/env python3
"""
AFRETIP Experimental Testing Framework
Comprehensive evaluation of hybrid threat detection capabilities
"""
import csv
import glob
import json
import os
import sqlite3
import statistics
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any

import psutil
import yaml


class AFRETIPExperiment:
    def __init__(self):
        self.results = []
        self.config_path = "config/config-dev.yaml"
        self.experiment_start = datetime.now()

        # Load actual config for database paths
        try:
            with open(self.config_path) as f:
                self.config = yaml.safe_load(f)
        except Exception as e:
            print(f"Warning: Could not load config: {e}")
            self.config = {}

    def setup_experiment(self):
        """Initialize experiment environment"""
        print("🧪 Setting up AFRETIP Experimental Framework")

        # Create results directories
        Path("experiments/results/raw").mkdir(parents=True, exist_ok=True)
        Path("experiments/results/processed").mkdir(parents=True, exist_ok=True)
        Path("experiments/results/analysis").mkdir(parents=True, exist_ok=True)

        # Initialize baseline data
        self.baseline_metrics = self.collect_baseline_metrics()

    def get_system_resources(self):
        """Get actual system resource information"""
        try:
            return {
                "cpu_cores": psutil.cpu_count(logical=True),
                "cpu_cores_physical": psutil.cpu_count(logical=False),
                "memory_gb": round(psutil.virtual_memory().total / (1024 ** 3), 2),
                "memory_available_gb": round(psutil.virtual_memory().available / (1024 ** 3), 2),
                "disk_total_gb": round(psutil.disk_usage('/').total / (1024 ** 3), 2),
                "disk_free_gb": round(psutil.disk_usage('/').free / (1024 ** 3), 2),
                "platform": f"{psutil.platform.system()} {psutil.platform.release()}",
                "python_version": sys.version.split()[0],
                "cpu_freq_mhz": psutil.cpu_freq().current if psutil.cpu_freq() else "Unknown",
                "load_average": os.getloadavg() if hasattr(os, 'getloadavg') else "N/A"
            }
        except Exception as e:
            # Fallback if psutil fails
            return {
                "cpu_cores": "Unknown",
                "memory_gb": "Unknown",
                "platform": "Unknown",
                "error": str(e)
            }

    def count_existing_rules(self):
        """Count existing Wazuh rules from actual rule files"""
        try:
            rule_count = 0

            # Check standard Wazuh rules directory
            wazuh_rules_dir = "/var/ossec/etc/rules"
            if Path(wazuh_rules_dir).exists():
                rule_count += self._count_rules_in_directory(wazuh_rules_dir)

            # Check local rules directory (for development)
            local_rules_dir = "./data/rules"
            if Path(local_rules_dir).exists():
                rule_count += self._count_rules_in_directory(local_rules_dir)

            return rule_count

        except Exception as e:
            print(f"Warning: Failed to count existing rules: {e}")
            return 0

    def _count_rules_in_directory(self, directory):
        """Count rules in XML files within a directory"""
        rule_count = 0

        try:
            xml_files = glob.glob(os.path.join(directory, "*.xml"))

            for xml_file in xml_files:
                try:
                    tree = ET.parse(xml_file)
                    root = tree.getroot()

                    # Count <rule> elements
                    rules = root.findall('.//rule')
                    rule_count += len(rules)

                except ET.ParseError:
                    # Skip malformed XML files
                    continue
                except Exception:
                    # Skip files we can't read
                    continue

        except Exception:
            pass

        return rule_count

    def get_ioc_db_size(self):
        """Get actual IOC database size and statistics"""
        try:
            db_path = self.config.get("storage", {}).get("files", {}).get(
                "threat_intelligence_db", "./data/threat_intelligence.db"
            )

            if not Path(db_path).exists():
                return {
                    "total_iocs": 0,
                    "database_exists": False,
                    "database_size_mb": 0
                }

            # Get database file size
            db_size_bytes = Path(db_path).stat().st_size
            db_size_mb = round(db_size_bytes / (1024 * 1024), 2)

            # Query actual IOC count
            with sqlite3.connect(db_path) as conn:
                cursor = conn.execute("SELECT COUNT(*) FROM threat_iocs")
                total_iocs = cursor.fetchone()[0]

                # Get IOCs by type
                cursor = conn.execute("""
                                      SELECT ioc_type, COUNT(*)
                                      FROM threat_iocs
                                      GROUP BY ioc_type
                                      """)
                iocs_by_type = dict(cursor.fetchall())

                # Get IOCs by source
                cursor = conn.execute("""
                                      SELECT source, COUNT(*)
                                      FROM threat_iocs
                                      GROUP BY source
                                      """)
                iocs_by_source = dict(cursor.fetchall())

            return {
                "total_iocs": total_iocs,
                "database_exists": True,
                "database_size_mb": db_size_mb,
                "iocs_by_type": iocs_by_type,
                "iocs_by_source": iocs_by_source
            }

        except Exception as e:
            print(f"Warning: Failed to get IOC database size: {e}")
            return {
                "total_iocs": 0,
                "database_exists": False,
                "database_size_mb": 0,
                "error": str(e)
            }

    def get_current_memory_usage(self):
        """Get current memory usage of the process"""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()

            return {
                "rss_mb": round(memory_info.rss / (1024 ** 2), 2),  # Resident Set Size
                "vms_mb": round(memory_info.vms / (1024 ** 2), 2),  # Virtual Memory Size
                "percent": round(process.memory_percent(), 2),  # Percentage of total memory
                "available_mb": round(psutil.virtual_memory().available / (1024 ** 2), 2)
            }
        except Exception as e:
            return {"error": str(e)}

    def get_current_cpu_usage(self):
        """Get current CPU usage"""
        try:
            # Get CPU usage over 1 second interval
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_per_core = psutil.cpu_percent(interval=1, percpu=True)

            return {
                "total_percent": cpu_percent,
                "per_core_percent": cpu_per_core,
                "load_average": os.getloadavg() if hasattr(os, 'getloadavg') else None
            }
        except Exception as e:
            return {"error": str(e)}

    def get_disk_usage(self):
        """Get current disk usage"""
        try:
            disk_usage = psutil.disk_usage('/')

            return {
                "total_gb": round(disk_usage.total / (1024 ** 3), 2),
                "used_gb": round(disk_usage.used / (1024 ** 3), 2),
                "free_gb": round(disk_usage.free / (1024 ** 3), 2),
                "percent_used": round((disk_usage.used / disk_usage.total) * 100, 2)
            }
        except Exception as e:
            return {"error": str(e)}

    def collect_baseline_metrics(self):
        """Collect baseline performance metrics with real data"""
        print("📊 Collecting baseline metrics...")

        baseline = {
            "timestamp": datetime.now().isoformat(),
            "system_resources": self.get_system_resources(),
            "memory_usage": self.get_current_memory_usage(),
            "cpu_usage": self.get_current_cpu_usage(),
            "disk_usage": self.get_disk_usage(),
            "wazuh_rules": {
                "existing_rule_count": self.count_existing_rules(),
                "rules_directory_exists": Path("/var/ossec/etc/rules").exists()
            },
            "ioc_database": self.get_ioc_db_size(),
            "process_info": {
                "pid": os.getpid(),
                "python_executable": sys.executable,
                "working_directory": os.getcwd()
            }
        }

        return baseline

    def run_single_test(self, test_file: Path, test_category: str) -> dict[str, Any]:
        """Run single log test and collect comprehensive metrics"""
        print(f"🔍 Testing: {test_file.name}")

        start_time = time.time()
        start_memory = self.get_current_memory_usage()

        # Run dry-run test
        cmd = [
            "threat-intel", "dry-run",
            "--config", self.config_path,
            "--log-sample", str(test_file)
        ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300
            )

            processing_time = time.time() - start_time
            end_memory = self.get_current_memory_usage()

            # Parse results from output
            metrics = self.parse_test_output(result.stdout, result.stderr)

            test_result = {
                "test_file": test_file.name,
                "test_category": test_category,
                "timestamp": datetime.now().isoformat(),
                "processing_time": processing_time,
                "success": result.returncode == 0,
                "metrics": metrics,
                "memory_delta_mb": end_memory.get("rss_mb", 0) - start_memory.get("rss_mb", 0),
                "peak_memory_mb": end_memory.get("rss_mb", 0),
                "raw_output": result.stdout,
                "errors": result.stderr
            }

            return test_result

        except subprocess.TimeoutExpired:
            return {
                "test_file": test_file.name,
                "test_category": test_category,
                "timestamp": datetime.now().isoformat(),
                "processing_time": 300,
                "success": False,
                "metrics": {},
                "raw_output": "",
                "errors": "Test timeout after 300 seconds"
            }

    def parse_test_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Extract metrics from test output"""
        metrics = {
            "iocs_extracted": 0,
            "findings_generated": 0,
            "rules_generated": 0,
            "ioc_extraction_time": 0.0,
            "threat_classifications": {},
            "confidence_scores": [],
            "threat_levels": {},
            "rule_generation_efficiency": 0.0
        }

        lines = stdout.split('\n')

        for line in lines:
            # Extract IOC count
            if "IOCs extracted:" in line:
                try:
                    metrics["iocs_extracted"] = int(line.split(":")[-1].strip())
                except ValueError:
                    pass

            # Extract findings count
            elif "Findings generated:" in line:
                try:
                    metrics["findings_generated"] = int(line.split(":")[-1].strip())
                except ValueError:
                    pass

            # Extract rules count
            elif "Rules generated:" in line:
                try:
                    metrics["rules_generated"] = int(line.split(":")[-1].strip())
                except ValueError:
                    pass

            # Extract processing time
            elif "Processing time:" in line:
                try:
                    time_str = line.split(":")[-1].strip().replace("s", "")
                    metrics["ioc_extraction_time"] = float(time_str)
                except ValueError:
                    pass

            # Extract threat classifications
            elif "classification=" in line and "confidence=" in line:
                # Parse: classification=suspicious confidence=0.8 threat_level=medium
                parts = line.split()
                for part in parts:
                    if part.startswith("classification="):
                        classification = part.split("=")[1]
                        metrics["threat_classifications"][classification] = \
                            metrics["threat_classifications"].get(classification, 0) + 1
                    elif part.startswith("confidence="):
                        try:
                            confidence = float(part.split("=")[1])
                            metrics["confidence_scores"].append(confidence)
                        except ValueError:
                            pass
                    elif part.startswith("threat_level="):
                        threat_level = part.split("=")[1]
                        metrics["threat_levels"][threat_level] = \
                            metrics["threat_levels"].get(threat_level, 0) + 1

        # Calculate efficiency metrics
        if metrics["findings_generated"] > 0:
            metrics["rule_generation_efficiency"] = \
                metrics["rules_generated"] / metrics["findings_generated"]

        return metrics

    def run_comprehensive_tests(self):
        """Run all test scenarios"""
        print("🚀 Starting Comprehensive AFRETIP Evaluation")

        test_categories = {
            "malicious": "experiments/malicious",
            "benign": "experiments/benign"
        }

        all_results = []

        for category, directory in test_categories.items():
            category_path = Path(directory)
            if not category_path.exists():
                print(f"⚠️  Directory not found: {directory}")
                continue

            # Find all JSON test files
            test_files = list(category_path.rglob("*.json"))
            print(f"📁 Found {len(test_files)} test files in {category}")

            for test_file in test_files:
                result = self.run_single_test(test_file, category)
                all_results.append(result)

                # Save individual result
                result_file = Path(f"experiments/results/raw/{test_file.stem}_result.json")
                with open(result_file, 'w') as f:
                    json.dump(result, f, indent=2)

        self.results = all_results
        return all_results

    def test_concurrent_processing(self):
        """Test concurrent processing capability"""
        try:
            # Test with multiple logs simultaneously
            test_files = list(Path("experiments/malicious").rglob("*.json"))[:5]

            start_time = time.time()
            start_memory = self.get_current_memory_usage()
            start_cpu = self.get_current_cpu_usage()

            # Process multiple files
            concurrent_results = []
            for test_file in test_files:
                result = self.run_single_test(test_file, "concurrent_test")
                concurrent_results.append(result)

            end_time = time.time()
            end_memory = self.get_current_memory_usage()
            end_cpu = self.get_current_cpu_usage()

            return {
                "total_time": end_time - start_time,
                "files_processed": len(test_files),
                "throughput": len(test_files) / (end_time - start_time),
                "memory_delta_mb": end_memory.get("rss_mb", 0) - start_memory.get("rss_mb", 0),
                "peak_memory_mb": end_memory.get("rss_mb", 0),
                "avg_cpu_usage": (start_cpu.get("total_percent", 0) + end_cpu.get("total_percent", 0)) / 2
            }
        except Exception as e:
            return {"error": str(e)}

    def test_memory_usage(self):
        """Test memory usage patterns"""
        try:
            baseline_memory = self.get_current_memory_usage()

            # Process a large log
            large_test = Path("experiments/malicious/rmm_abuse/rmm_01_encoded_powershell.json")
            if large_test.exists():
                result = self.run_single_test(large_test, "memory_test")
                peak_memory = self.get_current_memory_usage()

                return {
                    "baseline_memory_mb": baseline_memory.get("rss_mb", 0),
                    "peak_memory_mb": peak_memory.get("rss_mb", 0),
                    "memory_increase_mb": peak_memory.get("rss_mb", 0) - baseline_memory.get("rss_mb", 0),
                    "processing_time": result.get("processing_time", 0)
                }
            else:
                return {"error": "No test file available"}
        except Exception as e:
            return {"error": str(e)}

    def test_throughput(self):
        """Test processing throughput"""
        try:
            test_files = list(Path("experiments").rglob("*.json"))[:10]

            start_time = time.time()
            processed_count = 0

            for test_file in test_files:
                result = self.run_single_test(test_file, "throughput_test")
                if result["success"]:
                    processed_count += 1

            end_time = time.time()
            total_time = end_time - start_time

            return {
                "total_files": len(test_files),
                "processed_successfully": processed_count,
                "total_time": total_time,
                "throughput_files_per_second": processed_count / total_time if total_time > 0 else 0,
                "success_rate": processed_count / len(test_files) if test_files else 0
            }
        except Exception as e:
            return {"error": str(e)}

    def test_scalability(self):
        """Test scalability with increasing load"""
        try:
            scalability_results = []
            test_counts = [1, 5, 10]

            for count in test_counts:
                test_files = list(Path("experiments").rglob("*.json"))[:count]

                start_time = time.time()
                start_memory = self.get_current_memory_usage()

                for test_file in test_files:
                    self.run_single_test(test_file, "scalability_test")

                end_time = time.time()
                end_memory = self.get_current_memory_usage()

                scalability_results.append({
                    "file_count": count,
                    "processing_time": end_time - start_time,
                    "memory_usage_mb": end_memory.get("rss_mb", 0),
                    "memory_delta_mb": end_memory.get("rss_mb", 0) - start_memory.get("rss_mb", 0)
                })

            return scalability_results
        except Exception as e:
            return {"error": str(e)}

    def run_performance_tests(self):
        """Run performance and scalability tests"""
        print("⚡ Running Performance Tests")

        performance_results = {
            "concurrent_processing": self.test_concurrent_processing(),
            "memory_usage": self.test_memory_usage(),
            "throughput": self.test_throughput(),
            "scalability": self.test_scalability()
        }

        return performance_results

    def analyze_detection_effectiveness(self):
        """Analyze detection rates across categories"""
        malicious_results = [r for r in self.results if r["test_category"] == "malicious"]
        benign_results = [r for r in self.results if r["test_category"] == "benign"]

        malicious_detected = sum(1 for r in malicious_results if r["metrics"]["findings_generated"] > 0)
        benign_flagged = sum(1 for r in benign_results if r["metrics"]["findings_generated"] > 0)

        return {
            "true_positive_rate": malicious_detected / len(malicious_results) if malicious_results else 0,
            "false_positive_rate": benign_flagged / len(benign_results) if benign_results else 0,
            "total_malicious_tests": len(malicious_results),
            "total_benign_tests": len(benign_results),
            "malicious_detected": malicious_detected,
            "benign_flagged": benign_flagged
        }

    def analyze_classification_accuracy(self):
        """Analyze classification accuracy"""
        all_confidence_scores = []
        classifications = {"suspicious": 0, "malicious": 0, "benign": 0}

        for result in self.results:
            scores = result["metrics"]["confidence_scores"]
            all_confidence_scores.extend(scores)

            for classification, count in result["metrics"]["threat_classifications"].items():
                classifications[classification] = classifications.get(classification, 0) + count

        return {
            "average_confidence": statistics.mean(all_confidence_scores) if all_confidence_scores else 0,
            "median_confidence": statistics.median(all_confidence_scores) if all_confidence_scores else 0,
            "confidence_std_dev": statistics.stdev(all_confidence_scores) if len(all_confidence_scores) > 1 else 0,
            "classification_distribution": classifications,
            "total_classifications": sum(classifications.values())
        }

    def analyze_performance_metrics(self):
        """Analyze performance metrics"""
        processing_times = [r["processing_time"] for r in self.results if r["success"]]
        memory_deltas = [r.get("memory_delta_mb", 0) for r in self.results if r["success"]]

        return {
            "average_processing_time": statistics.mean(processing_times) if processing_times else 0,
            "median_processing_time": statistics.median(processing_times) if processing_times else 0,
            "max_processing_time": max(processing_times) if processing_times else 0,
            "min_processing_time": min(processing_times) if processing_times else 0,
            "average_memory_delta_mb": statistics.mean(memory_deltas) if memory_deltas else 0,
            "total_successful_tests": len(processing_times),
            "total_failed_tests": len(self.results) - len(processing_times)
        }

    def analyze_false_positives(self):
        """Analyze false positive patterns"""
        benign_results = [r for r in self.results if r["test_category"] == "benign"]
        false_positives = [r for r in benign_results if r["metrics"]["findings_generated"] > 0]

        fp_patterns = {}
        for fp in false_positives:
            for classification in fp["metrics"]["threat_classifications"]:
                fp_patterns[classification] = fp_patterns.get(classification, 0) + 1

        return {
            "false_positive_count": len(false_positives),
            "false_positive_rate": len(false_positives) / len(benign_results) if benign_results else 0,
            "false_positive_patterns": fp_patterns,
            "total_benign_tests": len(benign_results)
        }

    def analyze_rule_quality(self):
        """Analyze generated rule quality"""
        total_rules = sum(r["metrics"]["rules_generated"] for r in self.results)
        total_findings = sum(r["metrics"]["findings_generated"] for r in self.results)

        efficiency_scores = [r["metrics"]["rule_generation_efficiency"] for r in self.results
                             if r["metrics"]["rule_generation_efficiency"] > 0]

        return {
            "total_rules_generated": total_rules,
            "total_findings": total_findings,
            "overall_rule_efficiency": total_rules / total_findings if total_findings > 0 else 0,
            "average_efficiency": statistics.mean(efficiency_scores) if efficiency_scores else 0,
            "rules_per_test": total_rules / len(self.results) if self.results else 0
        }

    def compare_with_baseline(self):
        """Compare results with baseline metrics"""
        if not hasattr(self, 'baseline_metrics'):
            return {"error": "No baseline metrics available"}

        current_resources = self.get_system_resources()
        current_memory = self.get_current_memory_usage()

        return {
            "baseline_memory_mb": self.baseline_metrics["memory_usage"]["rss_mb"],
            "current_memory_mb": current_memory["rss_mb"],
            "memory_increase_mb": current_memory["rss_mb"] - self.baseline_metrics["memory_usage"]["rss_mb"],
            "baseline_ioc_count": self.baseline_metrics["ioc_database"]["total_iocs"],
            "current_ioc_count": self.get_ioc_db_size()["total_iocs"],
            "system_resources": current_resources
        }

    def analyze_results(self):
        """Comprehensive analysis of all test results"""
        print("📊 Analyzing Results")

        analysis = {
            "detection_effectiveness": self.analyze_detection_effectiveness(),
            "classification_accuracy": self.analyze_classification_accuracy(),
            "performance_metrics": self.analyze_performance_metrics(),
            "false_positive_analysis": self.analyze_false_positives(),
            "rule_quality_assessment": self.analyze_rule_quality(),
            "comparison_with_baseline": self.compare_with_baseline()
        }

        return analysis

    def generate_comprehensive_report(self):
        """Generate complete experimental report"""
        print("📝 Generating Comprehensive Report")

        report = {
            "experiment_metadata": {
                "start_time": self.experiment_start.isoformat(),
                "end_time": datetime.now().isoformat(),
                "total_tests": len(self.results),
                "afretip_version": "1.0.0",
                "configuration": self.config_path
            },
            "baseline_metrics": self.baseline_metrics,
            "test_results": self.results,
            "analysis": self.analyze_results(),
            "performance_tests": self.run_performance_tests()
        }

        # Save comprehensive report
        report_file = f"experiments/results/comprehensive_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        # Generate CSV summary for easy analysis
        self.generate_csv_summary(report)

        return report

    def generate_csv_summary(self, report):
        """Generate CSV files for statistical analysis"""

        # Test results summary
        with open("experiments/results/test_summary.csv", 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                "test_file", "category", "success", "iocs_extracted",
                "findings_generated", "rules_generated", "processing_time",
                "avg_confidence", "rule_efficiency", "memory_delta_mb"
            ])

            for result in self.results:
                metrics = result["metrics"]
                avg_confidence = statistics.mean(metrics["confidence_scores"]) if metrics["confidence_scores"] else 0

                writer.writerow([
                    result["test_file"],
                    result["test_category"],
                    result["success"],
                    metrics["iocs_extracted"],
                    metrics["findings_generated"],
                    metrics["rules_generated"],
                    result["processing_time"],
                    avg_confidence,
                    metrics["rule_generation_efficiency"],
                    result.get("memory_delta_mb", 0)
                ])


if __name__ == "__main__":
    experiment = AFRETIPExperiment()
    experiment.setup_experiment()

    # Run comprehensive tests
    results = experiment.run_comprehensive_tests()

    # Generate analysis and report
    report = experiment.generate_comprehensive_report()

    print("✅ Experiment completed! Report saved to experiments/results/")
    print(f"📊 Total tests: {len(results)}")
    print("📈 Analysis available in comprehensive report")
