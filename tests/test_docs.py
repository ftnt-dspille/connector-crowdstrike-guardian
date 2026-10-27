"""The generated README sections must be current."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_readme_is_current():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "gen_docs.py"), "--check"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_readme_names_every_visible_operation():
    import json

    info = json.load(open(ROOT / "crowdstrike_guardian" / "info.json"))
    readme = (ROOT / "README.md").read_text()
    missing = [
        op["operation"]
        for op in info["operations"]
        if op.get("visible", True) and ("`{}`".format(op["operation"])) not in readme
    ]
    assert not missing, f"operations missing from README: {missing}"
