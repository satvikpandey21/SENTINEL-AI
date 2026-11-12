import asyncio
import signal

from sentinel_security.config import Settings
from sentinel_security.logging import configure_logging
from sentinel_worker.runtime import run_worker


async def main() -> None:
    settings = Settings()
    configure_logging(settings.log_level)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, stop.set)
    await run_worker(settings, stop)


if __name__ == "__main__":
    asyncio.run(main())
