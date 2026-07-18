from __future__ import annotations

import sys
import tomllib
from pathlib import Path


root = Path(__file__).resolve().parents[1]
pyproject_path = root / "backend" / "pyproject.toml"
requirements_path = root / "backend" / "requirements.txt"

project = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))["project"]
declared = {str(item).strip() for item in project["dependencies"]}
mirrored = {
    line.strip()
    for line in requirements_path.read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.lstrip().startswith("#")
}

if declared != mirrored:
    print("backend/requirements.txt is not aligned with backend/pyproject.toml.", file=sys.stderr)
    for dependency in sorted(declared - mirrored):
        print(f"Missing from requirements.txt: {dependency}", file=sys.stderr)
    for dependency in sorted(mirrored - declared):
        print(f"Only in requirements.txt: {dependency}", file=sys.stderr)
    raise SystemExit(1)

print(f"Dependency mirror is aligned ({len(declared)} runtime dependencies).")
