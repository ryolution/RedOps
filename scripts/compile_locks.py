"""Regenerate hash locks in each supported Linux Python environment using pip-tools."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    current = f"{sys.version_info.major}.{sys.version_info.minor}"
    if sys.platform != "linux" or current not in {"3.11", "3.13", "3.14"}:
        raise SystemExit("Compile in a supported Linux Python environment.")
    for kind, extras in (("runtime", ["postgres"]), ("dev", ["postgres", "dev", "browser"])):
        command = [
            sys.executable,
            "-m",
            "piptools",
            "compile",
            "pyproject.toml",
            "--generate-hashes",
            "--allow-unsafe",
            "--strip-extras",
            "--all-build-deps",
            "--no-emit-index-url",
            "--no-emit-trusted-host",
            "--quiet",
            "--constraint",
            "requirements/compat.in",
            "--output-file",
            f"requirements/linux-py{current}-{kind}.txt",
        ]
        for extra in extras:
            command.extend(["--extra", extra])
        subprocess.run(command, cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
