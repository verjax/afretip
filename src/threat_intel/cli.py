import asyncio
import json
import os
import shutil
import socket
import subprocess
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .analytics.metrics import get_analytics, initialize_analytics
from .core.engine import ProcessingEngine
from .core.models import IOCType, WazuhRawLog
from .utils.config import ConfigurationError, get_default_config_path, load_config
from .utils.logging import setup_logging

app = typer.Typer(
    name="threat-intel",
    help="AFRETIP - Automated First Response Threat Intelligence Pipeline",
)
console = Console()


@app.command()
def start(
        config: str = typer.Option(
            None, help="Configuration file path (auto-detected if not provided)"
        ),
) -> None:
    """Start the threat intelligence pipeline"""
    console.print(
        "🚀 [bold green]Starting AFRETIP Threat Intelligence Pipeline[/bold green]"
    )

    try:
        config_path = config if config else get_default_config_path()
        console.print(f"📄 Loading configuration from: {config_path}")

        config_data = load_config(config_path)
        setup_logging(config_data)

        console.print("✅ Configuration loaded and validated successfully")

        # Initialize and start the engine
        engine = ProcessingEngine(config_data)
        console.print("🔧 Processing engine initialized")
        console.print("🚀 Starting pipeline... (Press Ctrl+C to stop)")

        asyncio.run(engine.start())

    except ConfigurationError as e:
        console.print(f"❌ [bold red]Configuration Error:[/bold red] {e}")
        console.print("\n💡 [blue]Suggestions:[/blue]")
        console.print("   • Run the installer: sudo ./scripts/install.sh")
        console.print("   • Create config manually: threat-intel create-config")
        console.print("   • Check file permissions and paths")
        raise typer.Exit(1)
    except KeyboardInterrupt:
        console.print("\n🛑 [yellow]Pipeline stopped by user[/yellow]")
        raise typer.Exit(0)
    except Exception as e:
        console.print(f"❌ [bold red]Fatal Error:[/bold red] {e}")
        console.print("\n🔍 [blue]Debug Info:[/blue]")
        console.print(
            f"   • Config path attempted: {config if config else 'auto-detected'}"
        )
        console.print("   • Check logs for detailed error information")
        raise typer.Exit(1)


@app.command()
def test(
        config: str = typer.Option(
            None, help="Configuration file path (auto-detected if not provided)"
        ),
) -> None:
    """Test the pipeline configuration and connectivity"""
    console.print(
        "🧪 [bold blue]Testing AFRETIP Configuration & Connectivity[/bold blue]"
    )

    try:
        # Use standardized config resolution
        config_path = config if config else get_default_config_path()
        console.print(f"📄 Testing configuration: {config_path}")

        config_data = load_config(config_path)
        console.print("✅ Configuration loaded and validated successfully")

        # Test Wazuh connectivity
        _test_wazuh_connectivity(config_data)

        # Test deployment configuration
        _test_deployment_config(config_data)

        # Test storage directories
        _test_storage_directories(config_data)

        # Test analytics configuration
        _test_analytics_config(config_data)

        console.print("\n🎉 [bold green]All tests completed successfully![/bold green]")
        console.print("✅ Your AFRETIP installation appears to be working correctly")

    except ConfigurationError as e:
        console.print(f"❌ [bold red]Configuration Error:[/bold red] {e}")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"❌ [bold red]Test failed:[/bold red] {e}")
        raise typer.Exit(1)


def _test_wazuh_connectivity(config_data: dict) -> None:
    """Test Wazuh connectivity"""
    console.print("\n🔌 [cyan]Testing Wazuh Connectivity...[/cyan]")

    wazuh_config = config_data.get("wazuh", {})
    use_socket = wazuh_config.get("connection", {}).get("use_socket", True)

    if use_socket:
        socket_path = wazuh_config.get("sockets", {}).get("archives")
        if socket_path and os.path.exists(socket_path):
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                s.connect(socket_path)
                s.close()
                console.print("✅ Wazuh socket connection successful")
            except Exception as e:
                console.print(f"⚠️ Wazuh socket exists but connection failed: {e}")
        else:
            console.print(f"⚠️ Wazuh socket path not found: {socket_path}")
    else:
        console.print("ℹ️ Socket monitoring disabled, using file monitoring")

    file_path = wazuh_config.get("files", {}).get("archives")
    if file_path and os.path.exists(file_path):
        console.print("✅ Wazuh archives file accessible")
    else:
        if not use_socket:
            console.print(f"❌ Archives file not accessible: {file_path}")
        else:
            console.print("ℹ️ File fallback not configured (socket mode)")


def _test_deployment_config(config_data: dict) -> None:
    """Test deployment configuration"""
    console.print("\n🚀 [cyan]Testing Rule Deployment Configuration...[/cyan]")

    deployment_config = config_data.get("deployment", {})
    if deployment_config.get("enabled", False):
        rules_dir = Path(
            deployment_config.get("filesystem", {}).get(
                "rules_dir", "/var/ossec/etc/rules"
            )
        )
        if rules_dir.exists() and rules_dir.is_dir():
            try:
                test_file = rules_dir / ".afretip_test"
                test_file.touch()
                test_file.unlink()
                console.print("✅ Rules directory writable")
            except PermissionError:
                console.print("❌ No write permission to rules directory")
            except Exception as e:
                console.print(f"⚠️ Rules directory test failed: {e}")
        else:
            console.print(f"❌ Rules directory not found: {rules_dir}")
    else:
        console.print("ℹ️ Rule deployment disabled in configuration")


def _test_storage_directories(config_data: dict) -> None:
    """Test storage directory configuration"""
    console.print("\n📁 [cyan]Testing Storage Directories...[/cyan]")

    storage_config = config_data.get("storage", {})
    files_config = storage_config.get("files", {})

    for file_type, file_path in files_config.items():
        data_dir = Path(file_path).parent
        try:
            data_dir.mkdir(parents=True, exist_ok=True)
            console.print(f"✅ Storage directory for {file_type}: {data_dir}")
        except Exception as e:
            console.print(f"❌ Cannot create storage directory for {file_type}: {e}")


def _test_analytics_config(config_data: dict) -> None:
    """Test analytics configuration"""
    console.print("\n📊 [cyan]Testing Analytics Configuration...[/cyan]")

    analytics_config = config_data.get("analytics", {})
    if analytics_config.get("enabled", False):
        output_dir = Path(
            analytics_config.get("output_dir", "/var/lib/afretip/analytics")
        )
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            console.print(f"✅ Analytics output directory: {output_dir}")
        except Exception as e:
            console.print(f"❌ Cannot create analytics directory: {e}")
    else:
        console.print("ℹ️ Analytics disabled in configuration")


@app.command()
def dry_run(
        config: str = typer.Option(
            None, help="Configuration file path (auto-detected if not provided)"
        ),
        log_sample: str = typer.Option(None, help="Process a sample log file for testing"),
) -> None:
    """Perform a dry run to validate configuration without starting the full pipeline"""
    console.print("🧪 [bold blue]Performing AFRETIP Dry Run[/bold blue]")

    try:
        # Use standardized config resolution
        config_path = config if config else get_default_config_path()
        console.print(f"📄 Using configuration: {config_path}")

        config_data = load_config(config_path)
        console.print("✅ Configuration structure validated")

        # If log sample provided, process it
        if log_sample:
            console.print(f"📄 Processing sample log: {log_sample}")
            asyncio.run(_process_sample_log(config_data, log_sample))
        else:
            # Run basic tests
            test(config_path)

        console.print("\n🎉 [bold green]Dry run successful![/bold green]")
        console.print("✅ The pipeline should work correctly with this configuration")

    except ConfigurationError as e:
        console.print(f"❌ [bold red]Configuration Error:[/bold red] {e}")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"❌ [bold red]Dry run failed:[/bold red] {e}")
        raise typer.Exit(1)


async def _process_sample_log(config_data: dict, log_file: str) -> None:
    """Process a sample log file for testing"""
    try:
        if not os.path.exists(log_file):
            console.print(f"❌ Sample log file not found: {log_file}")
            return

        console.print("🔧 Initializing processing engine...")
        engine = ProcessingEngine(config_data)

        # Read sample log
        with open(log_file) as f:
            log_content = f.read().strip()

        # Create WazuhRawLog object
        if log_content.startswith("{"):
            # JSON log
            log_data = json.loads(log_content)
            raw_log = WazuhRawLog(
                full_log=log_content,
                rule_id=log_data.get("rule", {}).get("id"),
                rule_level=log_data.get("rule", {}).get("level"),
                description=log_data.get("rule", {}).get("description"),
                source_system="sample_test",
            )
        else:
            # Text log
            raw_log = WazuhRawLog(full_log=log_content, source_system="sample_test")

        console.print("⚙️ Processing sample log...")
        result = await engine.process_single_log(raw_log)

        # Display results
        console.print("\n📊 [bold green]Sample Log Processing Results:[/bold green]")
        console.print(f"  • IOCs extracted: {len(result.get('iocs', []))}")
        console.print(f"  • Findings generated: {len(result.get('findings', []))}")
        console.print(f"  • Rules generated: {len(result.get('rules', []))}")
        console.print(f"  • Processing time: {result.get('processing_time', 0):.3f}s")

        if result.get("iocs"):
            console.print(
                "\n📍 [bold cyan]Extracted IOCs (showing first 5):[/bold cyan]"
            )
            for ioc in result["iocs"][:5]:
                console.print(
                    f"  • {ioc['type']}: {ioc['value']} (confidence: {ioc['confidence']:.2f})"
                )

        if result.get("error"):
            console.print(f"\n⚠️ [yellow]Processing Error:[/yellow] {result['error']}")

    except Exception as e:
        console.print(f"❌ Error processing sample log: {e}")


@app.command()
def validate_config(
        config: str = typer.Option(
            None, help="Configuration file path (auto-detected if not provided)"
        ),
) -> None:
    """Validate configuration file syntax and structure"""
    console.print("📋 [bold blue]Validating AFRETIP Configuration[/bold blue]")

    try:
        # Use standardized config resolution
        config_path = config if config else get_default_config_path()
        console.print(f"📄 Validating: {config_path}")

        config_data = load_config(config_path)

        console.print("✅ Configuration file syntax is valid")
        console.print("✅ All required sections are present")
        console.print("✅ Configuration values are within valid ranges")

        # Show configuration summary
        _show_config_summary(config_data)

        console.print(
            "\n🎉 [bold green]Configuration validation successful![/bold green]"
        )

    except ConfigurationError as e:
        console.print("❌ [bold red]Configuration Validation Failed:[/bold red]")
        console.print(f"   {e}")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"❌ [bold red]Validation error:[/bold red] {e}")
        raise typer.Exit(1)


def _show_config_summary(config_data: dict) -> None:
    """Show a summary of the configuration"""
    console.print("\n📋 [bold blue]Configuration Summary:[/bold blue]")

    # Wazuh configuration
    wazuh_config = config_data.get("wazuh", {})
    use_socket = wazuh_config.get("connection", {}).get("use_socket", True)
    console.print(f"  • Wazuh Mode: {'Socket' if use_socket else 'File'} monitoring")

    # Processing configuration
    processing_config = config_data.get("processing", {})
    console.print(
        f"  • Confidence Threshold: {processing_config.get('confidence_threshold', 0.6)}"
    )
    console.print(
        f"  • Novelty Threshold: {processing_config.get('novelty_threshold', 0.7)}"
    )

    # Analytics
    analytics_config = config_data.get("analytics", {})
    analytics_status = (
        "Enabled" if analytics_config.get("enabled", False) else "Disabled"
    )
    console.print(f"  • Analytics: {analytics_status}")

    # Deployment
    deployment_config = config_data.get("deployment", {})
    deployment_status = (
        "Enabled" if deployment_config.get("enabled", False) else "Disabled"
    )
    console.print(f"  • Rule Deployment: {deployment_status}")


@app.command()
def create_config(
        output: str = typer.Option("config.yaml", help="Output configuration file path"),
        force: bool = typer.Option(False, help="Overwrite existing file"),
) -> None:
    """Create an example configuration file"""
    from .utils.config import create_example_config

    console.print("📄 [bold blue]Creating AFRETIP Configuration File[/bold blue]")

    output_path = Path(output)

    if output_path.exists() and not force:
        console.print(f"❌ File already exists: {output_path}")
        console.print("Use --force to overwrite")
        raise typer.Exit(1)

    if create_example_config(str(output_path)):
        console.print(f"✅ Configuration file created: {output_path}")
        console.print("\n📍 [blue]Next steps:[/blue]")
        console.print("   1. Edit the configuration file to match your environment")
        console.print("   2. Validate: threat-intel validate-config")
        console.print("   3. Test: threat-intel test")
        console.print("   4. Start: threat-intel start")
    else:
        console.print(f"❌ Failed to create configuration file: {output_path}")
        raise typer.Exit(1)


@app.command()
def test_classification(
        ioc_value: str = typer.Argument(..., help="IOC value to test"),
        ioc_type: str = typer.Option(
            "ip", help="IOC type (ip, domain, url, hash_md5, etc.)"
        ),
        config: str = typer.Option(
            None, help="Configuration file path (auto-detected if not provided)"
        ),
) -> None:
    """Test IOC classification with the hybrid detection system"""
    console.print("🧠 [bold blue]Testing IOC Classification[/bold blue]")
    console.print(f"🎯 IOC: {ioc_value} (type: {ioc_type})")

    try:
        # Use standardized config resolution
        config_path = config if config else get_default_config_path()
        config_data = load_config(config_path)

        # Validate IOC type
        try:
            ioc_type_enum = IOCType(ioc_type.lower())
        except ValueError:
            valid_types = [t.value for t in IOCType]
            console.print(f"❌ Invalid IOC type: {ioc_type}")
            console.print(f"Valid types: {', '.join(valid_types)}")
            raise typer.Exit(1)

        asyncio.run(_test_classification_async(config_data, ioc_value, ioc_type_enum))

    except ConfigurationError as e:
        console.print(f"❌ [bold red]Configuration Error:[/bold red] {e}")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"❌ [bold red]Classification test failed:[/bold red] {e}")
        raise typer.Exit(1)


async def _test_classification_async(
        config_data: dict, ioc_value: str, ioc_type: IOCType
) -> None:
    """Test IOC classification asynchronously"""
    try:
        from .core.models import ExtractedIOC, WazuhRawLog
        from .enrichment.ioc_classifier import IOCClassifier

        console.print("🔧 Initializing classifier...")

        # Create test IOC
        test_ioc = ExtractedIOC(
            type=ioc_type,
            value=ioc_value,
            confidence=0.8,
            context=f"Test classification for {ioc_value}",
            source_log_hash="test_classification",
            extraction_method="manual_test",
        )

        # Create test log
        test_log = WazuhRawLog(
            full_log=f"Test log containing {ioc_value}",
            source_system="test_classification",
        )

        # Initialize classifier
        classifier = IOCClassifier(config_data)

        console.print("⚙️ Performing classification...")
        classification = await classifier.classify_ioc(test_ioc, test_log)

        console.print("\n📊 [bold green]Classification Results:[/bold green]")
        console.print(f"  • Classification: {classification.classification}")
        console.print(f"  • Confidence: {classification.confidence:.3f}")
        console.print(f"  • Threat Level: {classification.threat_level.value}")
        console.print(
            f"  • Should Generate Rule: {classification.should_generate_rule}"
        )
        console.print(f"  • Reasoning: {classification.reasoning}")

    except ImportError as e:
        console.print(f"❌ Failed to import classification components: {e}")
    except Exception as e:
        console.print(f"❌ Classification test error: {e}")


@app.command(name="test-threat-feeds")
def test_threat_feeds(
        config: str = typer.Option(
            None, help="Configuration file path (auto-detected if not provided)"
        ),
) -> None:
    """Test automated threat intelligence feeds functionality"""
    console.print("🛡️ [bold blue]Testing Threat Intelligence Feeds[/bold blue]")

    try:
        # Use standardized config resolution
        config_path = config if config else get_default_config_path()
        config_data = load_config(config_path)

        console.print("🔧 Initializing threat intelligence components...")

        asyncio.run(_test_threat_feeds_async(config_data))

        console.print("\n🎉 [bold green]Threat feeds test completed successfully![/bold green]")

    except ConfigurationError as e:
        console.print(f"❌ [bold red]Configuration Error:[/bold red] {e}")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"❌ [bold red]Threat feeds test failed:[/bold red] {e}")
        raise typer.Exit(1)


async def _test_threat_feeds_async(config_data: dict) -> None:
    """Test threat feed functionality asynchronously"""
    try:
        from .core.models import IOCType
        from .enrichment.threat_feed_manager import ThreatFeedManager
        from .enrichment.threat_intel_db import ThreatIntelDB

        # Initialize components
        threat_intel_db = ThreatIntelDB(config_data)
        feed_manager = ThreatFeedManager(
            config_path=config_data,
            threat_intel_db=threat_intel_db
        )

        console.print("=== Testing Threat Feed Manager ===")

        # Check initial feed status
        console.print("\n📋 Initial feed status:")
        status = feed_manager.get_feed_status()
        for feed_name, feed_info in status.items():
            enabled_status = "✅ Enabled" if feed_info['enabled'] else "❌ Disabled"
            console.print(f"  • {feed_name}: {enabled_status}, last_update={feed_info['last_update']}")

        # Get initial database statistics
        console.print("\n📊 Initial database statistics:")
        initial_stats = threat_intel_db.get_statistics()
        console.print(f"  • Total IOCs: {initial_stats['total_iocs']}")
        console.print(f"  • IOCs by type: {initial_stats['iocs_by_type']}")
        console.print(f"  • IOCs by source: {initial_stats['iocs_by_source']}")

        # Test manual feed update
        console.print("\n🔄 Testing manual feed update...")
        with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
        ) as progress:
            task = progress.add_task("Updating threat feeds...", total=None)
            await feed_manager.update_all_feeds()
            progress.update(task, completed=100)

        # Check database statistics after update
        console.print("\n📊 Database statistics after update:")
        final_stats = threat_intel_db.get_statistics()
        console.print(f"  • Total IOCs: {final_stats['total_iocs']}")
        console.print(f"  • IOCs by type: {final_stats['iocs_by_type']}")
        console.print(f"  • IOCs by source: {final_stats['iocs_by_source']}")

        # Calculate and show improvement
        iocs_added = final_stats['total_iocs'] - initial_stats['total_iocs']
        if iocs_added > 0:
            console.print(f"\n✅ Successfully added {iocs_added} new IOCs from threat feeds!")
        else:
            console.print("\nℹ️ No new IOCs added (feeds may be up to date)")

        # Check feed status after update
        console.print("\n📋 Feed status after update:")
        status = feed_manager.get_feed_status()
        for feed_name, feed_info in status.items():
            if feed_info['enabled']:
                console.print(f"  • {feed_name}: last_update={feed_info['last_update']}")

        # Test a few IOC lookups
        console.print("\n🔍 Testing IOC lookups:")

        # Test with some common test values
        sample_searches = [
            ("1.2.3.4", IOCType.IP),
            ("malicious.exe", IOCType.FILE_PATH),
            ("test.malware.com", IOCType.DOMAIN),
        ]

        for ioc_value, ioc_type in sample_searches:
            result = threat_intel_db.is_malicious(ioc_value, ioc_type)
            status_emoji = "🔴" if result['is_malicious'] else "🟢"
            console.print(f"  {status_emoji} {ioc_value} ({ioc_type.value}): malicious={result['is_malicious']}")
            if result['is_malicious']:
                console.print(
                    f"    └─ Confidence: {result.get('confidence', 'N/A')}, Source: {result.get('source', 'N/A')}")

    except ImportError as e:
        console.print(f"❌ Failed to import threat intelligence components: {e}")
        console.print("💡 Make sure all threat intelligence modules are properly installed")
    except Exception as e:
        console.print(f"❌ Threat feeds test error: {e}")


@app.command(name="threat-feed-status")
def show_threat_feed_status(
        config: str = typer.Option(
            None, help="Configuration file path (auto-detected if not provided)"
        ),
) -> None:
    """Show current threat feed status"""
    console.print("📋 [bold blue]Threat Intelligence Feed Status[/bold blue]")

    try:
        config_path = config if config else get_default_config_path()
        config_data = load_config(config_path)

        # Initialize components quickly just to get status
        from .enrichment.threat_feed_manager import ThreatFeedManager
        from .enrichment.threat_intel_db import ThreatIntelDB

        threat_intel_db = ThreatIntelDB(config_data)
        feed_manager = ThreatFeedManager(
            config_path=config_data,
            threat_intel_db=threat_intel_db
        )

        # Get feed status
        status = feed_manager.get_feed_status()

        # Create status table
        table = Table(title="Threat Intelligence Feeds")
        table.add_column("Feed Name", style="cyan")
        table.add_column("Status", style="magenta")
        table.add_column("Last Update", style="green")
        table.add_column("Update Interval", style="yellow")
        table.add_column("Confidence", style="blue")

        for feed_name, feed_info in status.items():
            status_text = "✅ Enabled" if feed_info['enabled'] else "❌ Disabled"
            last_update = feed_info['last_update'] if feed_info['last_update'] != 'Never' else '❌ Never'
            interval = f"{feed_info['update_interval_hours']}h"
            confidence = f"{feed_info['confidence']:.2f}"

            table.add_row(
                feed_name,
                status_text,
                last_update,
                interval,
                confidence
            )

        console.print(table)

        # Show database stats
        stats = threat_intel_db.get_statistics()
        console.print("\n📊 [bold cyan]Database Statistics:[/bold cyan]")
        console.print(f"  • Total IOCs: {stats['total_iocs']:,}")
        console.print(f"  • IOCs by type: {dict(stats['iocs_by_type'])}")
        console.print(f"  • IOCs by source: {dict(stats['iocs_by_source'])}")

    except Exception as e:
        console.print(f"❌ [bold red]Failed to get threat feed status:[/bold red] {e}")
        raise typer.Exit(1)


@app.command(name="update-threat-feeds")
def update_threat_feeds_manual(
        config: str = typer.Option(
            None, help="Configuration file path (auto-detected if not provided)"
        ),
) -> None:
    """Manually update threat intelligence feeds"""
    console.print("🔄 [bold blue]Manually Updating Threat Intelligence Feeds[/bold blue]")

    try:
        config_path = config if config else get_default_config_path()
        config_data = load_config(config_path)

        asyncio.run(_update_feeds_manual_async(config_data))

    except Exception as e:
        console.print(f"❌ [bold red]Failed to update threat feeds:[/bold red] {e}")
        raise typer.Exit(1)


async def _update_feeds_manual_async(config_data: dict) -> None:
    """Manually update feeds asynchronously"""
    try:
        from .enrichment.threat_feed_manager import ThreatFeedManager
        from .enrichment.threat_intel_db import ThreatIntelDB

        # Initialize components
        threat_intel_db = ThreatIntelDB(config_data)
        feed_manager = ThreatFeedManager(
            config_path=config_data,
            threat_intel_db=threat_intel_db
        )

        # Get initial stats
        initial_stats = threat_intel_db.get_statistics()
        console.print(f"📊 Initial IOCs: {initial_stats['total_iocs']:,}")

        # Update feeds
        console.print("🔄 Updating all enabled feeds...")
        with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
        ) as progress:
            task = progress.add_task("Downloading and processing feeds...", total=None)
            await feed_manager.update_all_feeds()
            progress.update(task, completed=100)

        # Get final stats
        final_stats = threat_intel_db.get_statistics()
        iocs_added = final_stats['total_iocs'] - initial_stats['total_iocs']

        console.print("✅ [bold green]Update completed![/bold green]")
        console.print(f"📊 Final IOCs: {final_stats['total_iocs']:,}")
        console.print(f"📈 IOCs added: {iocs_added:,}")

        if iocs_added > 0:
            console.print("\n🎯 [bold cyan]New IOCs by type:[/bold cyan]")
            for ioc_type, count in final_stats['iocs_by_type'].items():
                initial_count = initial_stats['iocs_by_type'].get(ioc_type, 0)
                added = count - initial_count
                if added > 0:
                    console.print(f"  • {ioc_type}: +{added}")

    except Exception as e:
        console.print(f"❌ Manual feed update error: {e}")


@app.command()
def status(
        config: str = typer.Option(
            None, help="Configuration file path (auto-detected if not provided)"
        ),
) -> None:
    """Show pipeline configuration status"""
    console.print("📊 [bold blue]AFRETIP Pipeline Status[/bold blue]")

    try:
        # Use standardized config resolution
        config_path = config if config else get_default_config_path()
        console.print(f"📄 Configuration: {config_path}")

        config_data = load_config(config_path)

        table = Table(title="Pipeline Configuration Status")
        table.add_column("Component", style="cyan")
        table.add_column("Status", style="magenta")
        table.add_column("Details", style="green")

        table.add_row("Configuration", "✅ Loaded", f"From: {config_path}")

        # Wazuh configuration
        wazuh_config = config_data.get("wazuh", {})
        use_socket = wazuh_config.get("connection", {}).get("use_socket", True)
        if use_socket:
            socket_path = wazuh_config.get("sockets", {}).get("archives", "Unknown")
            table.add_row("Wazuh Connection", "🔌 Socket", f"Path: {socket_path}")
        else:
            file_path = wazuh_config.get("files", {}).get("archives", "Unknown")
            table.add_row("Wazuh Connection", "📁 File", f"Path: {file_path}")

        # Processing configuration
        processing_config = config_data.get("processing", {})
        confidence_threshold = processing_config.get("confidence_threshold", 0.6)
        novelty_threshold = processing_config.get("novelty_threshold", 0.7)
        table.add_row(
            "IOC Extraction",
            "⚡ Ready",
            f"Confidence: {confidence_threshold}, Novelty: {novelty_threshold}",
        )

        pattern_detection = processing_config.get("enable_pattern_detection", True)
        novelty_detection = processing_config.get("enable_novelty_detection", True)
        status_text = f"Pattern: {'✅' if pattern_detection else '❌'}, Novelty: {'✅' if novelty_detection else '❌'}"
        table.add_row("Threat Detection", "🛡️ Ready", status_text)

        # Threat Intelligence configuration
        threat_intel_config = config_data.get("threat_intelligence", {})
        auto_update = threat_intel_config.get("auto_update_feeds", False)
        feeds_count = len(threat_intel_config.get("feeds", {}))
        enabled_feeds = sum(1 for feed in threat_intel_config.get("feeds", {}).values()
                            if feed.get("enabled", False))
        status_text = f"Feeds: {enabled_feeds}/{feeds_count}, Auto-update: {'✅' if auto_update else '❌'}"
        table.add_row("Threat Intelligence", "🛡️ Ready", status_text)

        # Analytics configuration
        analytics_config = config_data.get("analytics", {})
        analytics_enabled = analytics_config.get("enabled", False)
        if analytics_enabled:
            session_name = analytics_config.get("session_name", "default")
            table.add_row("Analytics", "📊 Enabled", f"Session: {session_name}")
        else:
            table.add_row(
                "Analytics", "⏸️ Disabled", "Enable in config for data collection"
            )

        # Deployment configuration
        deployment_config = config_data.get("deployment", {})
        deployment_enabled = deployment_config.get("enabled", False)
        if deployment_enabled:
            rules_dir = deployment_config.get("filesystem", {}).get(
                "rules_dir", "/var/ossec/etc/rules"
            )
            table.add_row("Rule Deployment", "🚀 Enabled", f"Target: {rules_dir}")
        else:
            table.add_row(
                "Rule Deployment", "⏸️ Disabled", "Enable in config for auto-deployment"
            )

        console.print(table)

    except ConfigurationError as e:
        console.print(f"❌ [bold red]Configuration Error:[/bold red] {e}")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"❌ [bold red]Status check failed:[/bold red] {e}")
        raise typer.Exit(1)


@app.command()
def version() -> None:
    console.print("🔧 [bold blue]AFRETIP Version Information[/bold blue]")
    console.print("Version: 1.0.0")
    console.print("Description: Automated First Response Threat Intelligence Pipeline")
    console.print("Repository: https://git.mif.vu.lt/micac/2025/afretip.git")
    console.print("Author: C Nyandoro")


@app.command(name="show-stats")
def show_analytics_stats(
        hours: int = typer.Option(24, help="Number of hours of data to show"),
        config: str = typer.Option(
            None, help="Configuration file path (auto-detected if not provided)"
        ),
) -> None:
    """Show analytics statistics from the pipeline"""
    try:
        # Use standardized config resolution
        config_path = config if config else get_default_config_path()
        config_data = load_config(config_path)

        analytics_config = config_data.get("analytics", {})
        if analytics_config.get("enabled", False):
            if not get_analytics():
                initialize_analytics(config_data)

        analytics = get_analytics()
        if not analytics:
            console.print("❌ [bold red]No analytics data available[/bold red]")
            console.print("💡 [blue]Suggestions:[/blue]")
            console.print("   • Start the pipeline first to generate analytics data")
            console.print("   • Ensure analytics.enabled=true in configuration")
            console.print("   • Check if the pipeline has processed any logs")
            raise typer.Exit(1)

        console.print(
            f"📊 [bold blue]Analytics Statistics (last {hours} hours)[/bold blue]\n"
        )

        with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
        ) as progress:
            task = progress.add_task("Gathering statistics...", total=None)
            stats = analytics.get_realtime_stats()
            progress.update(task, completed=100)

        _display_basic_stats(stats)

    except ConfigurationError as e:
        console.print(f"❌ [bold red]Configuration Error:[/bold red] {e}")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"❌ [bold red]Failed to show stats:[/bold red] {e}")
        raise typer.Exit(1)


@app.command(name="generate-report")
def generate_analytics_report(
        hours: int = typer.Option(24, help="Number of hours to analyze"),
        save_report: bool = typer.Option(True, help="Save report to file"),
        config: str = typer.Option(
            None, help="Configuration file path (auto-detected if not provided)"
        ),
) -> None:
    """Generate a comprehensive analytics report"""
    try:
        # Use standardized config resolution
        config_path = config if config else get_default_config_path()
        config_data = load_config(config_path)

        analytics_config = config_data.get("analytics", {})
        if analytics_config.get("enabled", False):
            if not get_analytics():
                initialize_analytics(config_data)

        analytics = get_analytics()
        if not analytics:
            console.print("❌ [bold red]No analytics data available[/bold red]")
            console.print("💡 [blue]Suggestions:[/blue]")
            console.print("   • Start the pipeline first to generate analytics data")
            console.print("   • Ensure analytics.enabled=true in configuration")
            raise typer.Exit(1)

        console.print(
            f"📄 [bold blue]Generating Analytics Report ({hours} hours)[/bold blue]\n"
        )

        with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
        ) as progress:
            task = progress.add_task("Generating report...", total=None)
            report = analytics.generate_analytics_report()
            progress.update(task, completed=100)

        _display_report_summary(report)

        if save_report:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"afretip_report_{timestamp}.json"

            with open(filename, "w") as f:
                json.dump(report, f, indent=2, default=str)

            console.print(f"\n📄 [bold green]Report saved:[/bold green] {filename}")

    except ConfigurationError as e:
        console.print(f"❌ [bold red]Configuration Error:[/bold red] {e}")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"❌ [bold red]Report generation failed:[/bold red] {e}")
        raise typer.Exit(1)


def _display_basic_stats(stats: dict) -> None:
    """Display basic analytics statistics"""
    processing_stats = stats.get("processing_stats", {})
    console.print("📍 [bold cyan]Processing Statistics:[/bold cyan]")
    console.print(f"  • Logs processed: {processing_stats.get('logs_processed', 0):,}")
    console.print(f"  • IOCs extracted: {processing_stats.get('iocs_extracted', 0):,}")
    console.print(
        f"  • Rules generated: {processing_stats.get('rules_generated', 0):,}"
    )
    console.print(
        f"  • Processing errors: {processing_stats.get('processing_errors', 0):,}"
    )
    console.print()

    deployment_stats = stats.get("deployment_stats", {})
    if deployment_stats:
        console.print("🚀 [bold purple]Deployment Statistics:[/bold purple]")
        console.print(
            f"  • Total deployments: {deployment_stats.get('total_deployments', 0)}"
        )
        console.print(
            f"  • Success rate: {deployment_stats.get('success_rate', 0):.1f}%"
        )
        console.print(
            f"  • Average deployment time: {deployment_stats.get('avg_time_ms', 0):.1f}ms"
        )
        console.print()

    ioc_analysis = stats.get("ioc_analysis", {})
    console.print("🛡️ [bold red]IOC Analysis:[/bold red]")
    console.print(f"  • Novel IOCs found: {ioc_analysis.get('novel_iocs_found', 0)}")
    console.print(f"  • Threat intel hits: {ioc_analysis.get('threat_intel_hits', 0)}")
    console.print(
        f"  • Reputation confirmations: {ioc_analysis.get('reputation_confirmations', 0)}"
    )
    console.print()

    performance = stats.get("performance", {})
    console.print("⚡ [bold green]Performance:[/bold green]")
    console.print(f"  • Logs/sec: {performance.get('logs_per_second', 0):.2f}")
    console.print(f"  • IOCs/sec: {performance.get('iocs_per_second', 0):.2f}")
    console.print(
        f"  • Avg processing time: {performance.get('avg_processing_time_ms', 0):.2f}ms"
    )
    console.print()


def _display_report_summary(report: dict) -> None:
    """Display analytics report summary"""
    console.print("📊 [bold blue]Analytics Report Summary[/bold blue]\n")

    processing_stats = report.get("processing_stats", {})
    console.print("📍 [bold cyan]Processing Summary:[/bold cyan]")
    console.print(f"  • Logs processed: {processing_stats.get('logs_processed', 0):,}")
    console.print(f"  • IOCs extracted: {processing_stats.get('iocs_extracted', 0):,}")
    console.print(
        f"  • Rules generated: {processing_stats.get('rules_generated', 0):,}"
    )
    console.print(
        f"  • Processing errors: {processing_stats.get('processing_errors', 0):,}"
    )
    console.print()

    analytics_insights = report.get("analytics_insights", {})
    if analytics_insights:
        hybrid_effectiveness = analytics_insights.get(
            "hybrid_detection_effectiveness", {}
        )
        console.print("🧠 [bold magenta]Hybrid Detection Effectiveness:[/bold magenta]")
        console.print(
            f"  • Total IOCs analyzed: {hybrid_effectiveness.get('total_iocs_analyzed', 0):,}"
        )
        console.print(
            f"  • Novel detection rate: {hybrid_effectiveness.get('novel_detection_rate_percent', 0):.2f}%"
        )
        console.print(
            f"  • Threat intel hit rate: {hybrid_effectiveness.get('threat_intel_hit_rate_percent', 0):.2f}%"
        )
        console.print()

    session_info = report.get("session_info", {})
    console.print("⏱️ [bold yellow]Session Information:[/bold yellow]")
    console.print(f"  • Session ID: {session_info.get('session_id', 'N/A')}")
    console.print(f"  • Runtime: {session_info.get('runtime_hours', 0):.2f} hours")
    console.print()


@app.command(name="test-rules")
def test_rule_generation(
        config: str = typer.Option(
            None, help="Configuration file path (auto-detected if not provided)"
        ),
        sample_logs: str = typer.Option(
            "experiments/malicious", help="Directory containing sample logs to test"
        ),
        output_rules: str = typer.Option(
            "test_generated_rules.xml", help="Output file for generated rules"
        ),
        max_tests: int = typer.Option(5, help="Maximum number of test files to process")
) -> None:
    """Test rule generation capabilities with sample logs"""
    console.print("🧪 [bold blue]Testing Rule Generation Capabilities[/bold blue]")

    try:
        config_path = config if config else get_default_config_path()
        config_data = load_config(config_path)

        sample_dir = Path(sample_logs)
        if not sample_dir.exists():
            console.print(f"❌ Sample logs directory not found: {sample_dir}")
            raise typer.Exit(1)

        # Find test logs
        test_files = list(sample_dir.rglob("*.json"))
        console.print(f"📄 Found {len(test_files)} test files")

        total_rules = 0
        successful_tests = 0
        all_generated_rules = []

        console.print("🔧 Testing rule generation for each log...")

        for test_file in test_files[:max_tests]:  # Test first N files
            console.print(f"  Testing: {test_file.name}")

            result = subprocess.run([
                "threat-intel", "dry-run",
                "--config", config_path,
                "--log-sample", str(test_file)
            ], capture_output=True, text=True)

            if result.returncode == 0:
                # Parse rules generated
                rules_count = 0
                for line in result.stdout.split('\n'):
                    if "Rules generated:" in line:
                        try:
                            rules_count = int(line.split(":")[-1].strip())
                            total_rules += rules_count
                            break
                        except ValueError:
                            pass

                if rules_count > 0:
                    successful_tests += 1
                    console.print(f"    ✅ Generated {rules_count} rules")
                    # Store output for rule extraction
                    all_generated_rules.append({
                        "test_file": test_file.name,
                        "rules_count": rules_count,
                        "output": result.stdout
                    })
                else:
                    console.print("    ⚠️ No rules generated")
            else:
                console.print(f"    ❌ Failed: {result.stderr[:100]}...")

        # Save generated rules to output file
        if all_generated_rules and output_rules:
            _save_generated_rules_summary(all_generated_rules, output_rules)

        console.print("\n📊 [bold green]Rule Generation Test Results:[/bold green]")
        console.print(f"  • Total tests: {min(len(test_files), max_tests)}")
        console.print(f"  • Successful: {successful_tests}")
        console.print(f"  • Total rules generated: {total_rules}")
        console.print(
            f"  • Average rules per test: {total_rules / successful_tests if successful_tests > 0 else 0:.1f}")

        if output_rules and all_generated_rules:
            console.print(f"  • Rules summary saved to: {output_rules}")

    except Exception as e:
        console.print(f"❌ [bold red]Rule generation test failed:[/bold red] {e}")
        raise typer.Exit(1)


def _save_generated_rules_summary(rules_data: list, output_file: str) -> None:
    """Save summary of generated rules to file"""
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with open(output_file, 'w') as f:
            f.write("# AFRETIP Rule Generation Test Summary\n")
            f.write(f"# Generated: {timestamp}\n")
            f.write(f"# Total test files: {len(rules_data)}\n\n")

            for rule_info in rules_data:
                f.write(f"## Test File: {rule_info['test_file']}\n")
                f.write(f"Rules Generated: {rule_info['rules_count']}\n")
                f.write("### Sample Output:\n")
                # Extract just the rules section from output
                output_lines = rule_info['output'].split('\n')
                in_rules_section = False
                for line in output_lines:
                    if "Extracted IOCs" in line:
                        in_rules_section = True
                    if in_rules_section and line.strip():
                        f.write(f"  {line}\n")
                    if "Processing time:" in line:
                        break
                f.write("\n" + "=" * 50 + "\n\n")

    except Exception as e:
        console.print(f"⚠️ Warning: Could not save rules summary: {e}")


@app.command(name="run-experiments")
def run_comprehensive_experiments(
        config: str = typer.Option(
            None, help="Configuration file path (auto-detected if not provided)"
        ),
        generate_data: bool = typer.Option(
            True, help="Generate test data first"
        ),
        run_performance: bool = typer.Option(
            True, help="Run performance tests"
        )
) -> None:
    """Run comprehensive experimental evaluation"""
    console.print("🧪 [bold blue]Running Comprehensive AFRETIP Experiments[/bold blue]")

    try:
        config_path = config if config else get_default_config_path()
        console.print(f"📄 Using configuration: {config_path}")

        # Validate config exists
        if not Path(config_path).exists():
            console.print(f"❌ Configuration file not found: {config_path}")
            console.print("💡 Try: threat-intel dev-mode")
            raise typer.Exit(1)

        # Generate test data if requested
        if generate_data:
            console.print("🗂️ Generating test data...")

            # Check if generator exists
            generator_path = Path("experiments/generate_test_logs.py")
            if not generator_path.exists():
                console.print(f"⚠️ Test data generator not found: {generator_path}")
                console.print("💡 Make sure you have the complete experimental framework")
            else:
                result = subprocess.run([
                    "python", str(generator_path)
                ], capture_output=True, text=True)

                if result.returncode == 0:
                    console.print("✅ Test data generated successfully")
                else:
                    console.print(f"⚠️ Test data generation warning: {result.stderr}")

        # Run comprehensive tests
        console.print("🚀 Starting comprehensive experiments...")

        # Check if test runner exists
        runner_path = Path("experiments/test_runner.py")
        if not runner_path.exists():
            console.print(f"❌ Test runner not found: {runner_path}")
            console.print("💡 Make sure you have the complete experimental framework")
            raise typer.Exit(1)

        result = subprocess.run([
            "python", str(runner_path)
        ], capture_output=True, text=True)

        if result.returncode == 0:
            console.print("✅ Experiments completed successfully")
            # Show relevant output (not the full verbose log)
            lines = result.stdout.split('\n')
            for line in lines[-20:]:  # Show last 20 lines
                if line.strip():
                    console.print(f"  {line}")
        else:
            console.print(f"❌ Experiments failed: {result.stderr}")
            raise typer.Exit(1)

        # Show results location
        console.print("\n📊 [bold green]Results Available:[/bold green]")
        results_dir = Path("experiments/results")
        if results_dir.exists():
            console.print(f"  • Raw results: {results_dir}/raw/")
            console.print(f"  • CSV summary: {results_dir}/test_summary.csv")
            console.print(f"  • Comprehensive report: {results_dir}/comprehensive_report_*.json")

            # Count files
            raw_files = list((results_dir / "raw").glob("*.json")) if (results_dir / "raw").exists() else []
            console.print(f"  • Generated {len(raw_files)} individual test results")
        else:
            console.print("  ⚠️ Results directory not found - check experiment execution")

    except Exception as e:
        console.print(f"❌ [bold red]Experiments failed:[/bold red] {e}")
        raise typer.Exit(1)


@app.command(name="dev-mode")
def enable_dev_mode() -> None:
    """Switch to development mode configuration"""
    console.print("🔧 [bold blue]Enabling Development Mode[/bold blue]")

    dev_config_path = Path("config/config-dev.yaml")

    # Set environment variable for development config
    os.environ["AFRETIP_CONFIG"] = str(dev_config_path)

    if not dev_config_path.exists():
        console.print("⚠️ Development config not found, creating from template...")

        # Create dev config from production config
        prod_config_path = Path("config/config.yaml")
        if prod_config_path.exists():
            shutil.copy(prod_config_path, dev_config_path)
            console.print(f"✅ Created {dev_config_path} from {prod_config_path}")

            # Modify paths for development
            _modify_config_for_dev(dev_config_path)
        else:
            console.print("❌ No base config found to copy from")
            console.print("💡 Try: threat-intel create-config config/config.yaml")
            raise typer.Exit(1)

    console.print("✅ Development mode enabled")
    console.print(f"📄 Using config: {dev_config_path}")
    console.print("🔧 All subsequent commands will use development configuration")

    # Test the development config
    try:
        config_data = load_config(str(dev_config_path))
        console.print("✅ Development configuration loaded successfully")

        # Show key differences
        storage_config = config_data.get("storage", {})
        rules_dir = config_data.get("deployment", {}).get("filesystem", {}).get("rules_dir", "Not set")

        console.print("\n📋 [bold cyan]Development Configuration:[/bold cyan]")
        console.print(f"  • Rules directory: {rules_dir}")
        console.print(f"  • Data directory: {storage_config.get('files', {}).get('raw_logs', 'Not set')}")

    except Exception as e:
        console.print(f"❌ Error loading development config: {e}")


def _modify_config_for_dev(config_path: Path) -> None:
    """Modify configuration file for development environment"""
    try:
        import yaml

        with open(config_path) as f:
            config = yaml.safe_load(f)

        # Modify paths for development
        if 'storage' in config and 'files' in config['storage']:
            for key, path in config['storage']['files'].items():
                # Change /var/lib/afretip/ to ./data/
                if path.startswith('/var/lib/afretip/'):
                    config['storage']['files'][key] = path.replace('/var/lib/afretip/', './data/')

        if 'deployment' in config and 'filesystem' in config['deployment']:
            # Change rules directory to local
            config['deployment']['filesystem']['rules_dir'] = './data/rules'
            # Disable deployment by default in dev
            config['deployment']['enabled'] = False

        if 'analytics' in config:
            # Change analytics output to local
            config['analytics']['output_dir'] = './data/analytics'

        if 'logging' in config:
            # Change log path to local
            config['logging']['file'] = './logs/threat_detection.log'

        # Save modified config
        with open(config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)

        console.print("🔧 Modified configuration for development environment")

    except Exception as e:
        console.print(f"⚠️ Warning: Could not modify config for development: {e}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
