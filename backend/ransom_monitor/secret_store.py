from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path


class SecretStore:
    """Small local credential store whose contents are never exposed by the API."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        if self.path.exists():
            self.path.chmod(0o600)

    def _read(self) -> dict[str, str]:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
        return {
            str(key): str(value)
            for key, value in data.items()
            if isinstance(key, str) and isinstance(value, str) and value
        } if isinstance(data, dict) else {}

    def _write(self, values: dict[str, str]) -> None:
        descriptor, temp_name = tempfile.mkstemp(prefix=".secrets-", dir=self.path.parent)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(values, output, separators=(",", ":"))
                output.flush()
                os.fsync(output.fileno())
            os.replace(temp_name, self.path)
            self.path.chmod(0o600)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    def get(self, name: str) -> str:
        with self._lock:
            return self._read().get(name, "")

    def set(self, name: str, value: str) -> None:
        with self._lock:
            values = self._read()
            values[name] = value
            self._write(values)

    def delete(self, name: str) -> None:
        with self._lock:
            values = self._read()
            if name in values:
                del values[name]
                self._write(values)

    def configured_names(self) -> set[str]:
        with self._lock:
            return set(self._read())
