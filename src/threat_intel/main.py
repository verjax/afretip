import asyncio
import signal
import sys
from typing import Any

from .core.engine import ProcessingEngine
from .utils.config import load_config
from .utils.logging import setup_logging


# Main application entry point
async def main() -> int:
    config = load_config()
    setup_logging(config)

    import structlog

    logger = structlog.get_logger(__name__)
    logger.info("Starting Pipeline")

    engine = ProcessingEngine(config)

    def signal_handler(signum: int, frame: Any) -> None:
        logger.info("Received shutdown signal", signal=signum)
        asyncio.create_task(engine.stop())

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        await engine.start()
    except KeyboardInterrupt:
        logger.info("Shutdown requested")
    except Exception as e:
        logger.error("Fatal error", error=str(e))
        return 1

    logger.info("Pipeline stopped")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
