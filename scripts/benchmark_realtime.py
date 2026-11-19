"""Sample local Docker resources during the owned three-client streaming verification."""

import json
import shutil
import subprocess
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCKER = shutil.which("docker")
if DOCKER is None:
    raise RuntimeError("Docker CLI is required")


def main():
    stop = threading.Event()
    samples = []

    def sample():
        while not stop.is_set():
            result = subprocess.run(
                [DOCKER, "stats", "--no-stream", "--format", "{{json .}}"],
                capture_output=True,
                text=True,
                check=True,
            )
            for line in result.stdout.splitlines():
                row = json.loads(line)
                if row["Name"].startswith("sentinel-ai-") and row["Name"].endswith("-1"):
                    samples.append(
                        {
                            "name": row["Name"],
                            "cpu_percent": float(row["CPUPerc"].rstrip("%")),
                            "memory": row["MemUsage"],
                        }
                    )
            stop.wait(0.5)

    thread = threading.Thread(target=sample, daemon=True)
    thread.start()
    try:
        verification = subprocess.run(
            [
                DOCKER,
                "compose",
                "--profile",
                "test",
                "run",
                "--rm",
                "--no-deps",
                "tests",
                "python",
                "scripts/verify_realtime.py",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
    finally:
        stop.set()
        thread.join(timeout=10)
    print(
        json.dumps(
            {"streaming": json.loads(verification.stdout), "docker_samples": samples}, indent=2
        )
    )


if __name__ == "__main__":
    main()
