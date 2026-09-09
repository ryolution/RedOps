"""Check packaged assets and execute the installed wheel away from the checkout."""

import os
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS = (
    "redops/web/templates/base.html",
    "redops/web/templates/login.html",
    "redops/web/templates/assessment.html",
    "redops/web/templates/finding.html",
    "redops/web/static/app.css",
    "redops/web/static/app.js",
    "redops/reporting/fonts/DejaVuSans.ttf",
    "redops/reporting/fonts/DejaVuSans-Bold.ttf",
    "redops/reporting/fonts/LICENSE.txt",
)


def main() -> None:
    wheel = max((ROOT / "dist").glob("*.whl"), key=lambda path: path.stat().st_mtime)
    archive = max((ROOT / "dist").glob("*.tar.gz"), key=lambda path: path.stat().st_mtime)
    with zipfile.ZipFile(wheel) as bundle:
        assert set(ASSETS) <= set(bundle.namelist()), "Wheel is missing required assets"
    with tarfile.open(archive) as bundle:
        names = {name.split("/", 1)[1] for name in bundle.getnames() if "/" in name}
        assert set(ASSETS) <= names, "Source distribution is missing assets"
        assert "requirements/linux-py3.13-runtime.txt" in names
        assert "scripts/check_distribution.py" in names
    with tempfile.TemporaryDirectory(prefix="redops-wheel-") as temporary:
        site = Path(temporary) / "site"
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--no-index",
                "--no-deps",
                "--target",
                str(site),
                str(wheel),
            ],
            cwd=temporary,
            check=True,
        )
        subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                (ROOT / "scripts/installed_smoke.py").read_text(),
                str(site),
                str(ROOT / "labs"),
            ],
            cwd=temporary,
            check=True,
        )
        # Exercise the installed console entry point as well as imported interfaces.
        subprocess.run(
            [
                sys.executable,
                str(site / "bin/redops"),
                "--about",
            ],
            cwd=temporary,
            env={**os.environ, "PYTHONPATH": str(site)},
            check=True,
        )
    print("Wheel and source assets, offline workflow, dashboard, reports and restore passed.")


if __name__ == "__main__":
    main()
