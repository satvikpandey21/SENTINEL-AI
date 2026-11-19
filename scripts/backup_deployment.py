"""Write a PostgreSQL custom-format backup as bytes, safely on Windows and Linux."""

import argparse
import subprocess
from pathlib import Path

from deploy import ROOT, command

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, default=ROOT / ".env.production")
    parser.add_argument("--project", default="sentinel-production")
    parser.add_argument(
        "--mode", choices=["production", "local-test", "tunnel"], default="production"
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    base = command(args.env_file, args.project, args.mode)
    # Database owner/name are resolved inside the container; passwords never enter arguments.
    with args.output.open("xb") as output:
        subprocess.run(
            [
                *base,
                "exec",
                "-T",
                "postgres",
                "sh",
                "-c",
                'exec pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc',
            ],
            cwd=ROOT,
            stdout=output,
            check=True,
        )
    print("Database backup created; store it encrypted outside the deployment host.")
