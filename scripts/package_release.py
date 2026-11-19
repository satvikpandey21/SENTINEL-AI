"""Package all current Git-visible source, including uncommitted files, without local secrets."""

import argparse
import hashlib
import json
import shutil
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def package(output):
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("Git is required to enumerate the current source")
    names = (
        subprocess.check_output(
            [git, "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT
        )
        .decode()
        .split("\0")
    )
    manifest = {}
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation avoids overwriting a previously reviewed release.
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(set(names)):
            path = ROOT / name
            if not name or not path.is_file() or path.resolve() == output:
                continue
            if path.is_symlink() or not path.resolve().is_relative_to(ROOT):
                raise ValueError("Release source must stay inside the repository")
            if ".secrets" in path.parts or (
                path.name.startswith(".env") and path.name != ".env.example"
            ):
                raise ValueError("Private environment/secret file unexpectedly visible to Git")
            data = path.read_bytes()
            archive.writestr(name, data)
            manifest[name] = hashlib.sha256(data).hexdigest()
        archive.writestr("release-manifest.json", json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"files": len(manifest), "archive": str(output), "committed": False}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    package(parser.parse_args().output)
