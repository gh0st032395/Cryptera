"""
Persistent audit logging for CryptoV2.

Writes structured JSONL (one JSON object per line) to a rotating log file.
Default location: ~/.cryptov2_logs/
Rotation: new file when current exceeds max_file_mb; keeps at most max_files files.
"""

import os
import json
import glob
import threading
from datetime import datetime, timezone


_DEFAULT_LOG_DIR = os.path.expanduser("~/.cryptov2_logs")
_FILE_PREFIX = "cryptov2_audit_"
_FILE_EXT = ".jsonl"


class AuditLogger:
    """Thread-safe JSONL audit logger with automatic file rotation."""

    def __init__(
        self,
        log_dir: str = _DEFAULT_LOG_DIR,
        max_file_mb: float = 5.0,
        max_files: int = 5,
    ):
        self._log_dir = log_dir
        self._max_bytes = int(max_file_mb * 1024 * 1024)
        self._max_files = max(1, max_files)
        self._lock = threading.Lock()
        self._current_path: str | None = None

        os.makedirs(log_dir, exist_ok=True)
        self._current_path = self._latest_or_new()

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def log(
        self,
        op: str,
        input_file: str,
        *,
        output_file: str | None = None,
        file_size_bytes: int | None = None,
        profile_sec: str | None = None,
        profile_int: str | None = None,
        duration_s: float | None = None,
        status: str = "OK",
        error: str | None = None,
    ) -> None:
        """Append one audit entry. Thread-safe."""
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "op": op,
            "file": os.path.basename(input_file),
            "size_mb": round(file_size_bytes / (1024 * 1024), 3) if file_size_bytes else None,
            "profile_sec": profile_sec,
            "profile_int": profile_int,
            "duration_s": round(duration_s, 2) if duration_s is not None else None,
            "status": status,
            "error": error,
        }
        line = json.dumps(entry, ensure_ascii=False) + "\n"
        with self._lock:
            self._rotate_if_needed()
            with open(self._current_path, "a", encoding="utf-8") as f:
                f.write(line)

    def read_recent(self, max_entries: int = 500) -> list[dict]:
        """
        Return up to max_entries recent log entries, newest first.
        Reads across rotated files if necessary.
        """
        files = sorted(self._all_log_files(), reverse=True)
        entries: list[dict] = []
        for path in files:
            if len(entries) >= max_entries:
                break
            try:
                with open(path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                for line in reversed(lines):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
                    if len(entries) >= max_entries:
                        break
            except OSError:
                pass
        return entries

    def get_log_dir(self) -> str:
        return self._log_dir

    def get_current_log_path(self) -> str | None:
        return self._current_path

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _all_log_files(self) -> list[str]:
        pattern = os.path.join(self._log_dir, f"{_FILE_PREFIX}*{_FILE_EXT}")
        return sorted(glob.glob(pattern))

    def _latest_or_new(self) -> str:
        files = self._all_log_files()
        if files:
            latest = files[-1]
            if os.path.getsize(latest) < self._max_bytes:
                return latest
        return self._new_file_path()

    def _new_file_path(self) -> str:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        return os.path.join(self._log_dir, f"{_FILE_PREFIX}{ts}{_FILE_EXT}")

    def _rotate_if_needed(self) -> None:
        """Must be called while holding self._lock."""
        if self._current_path and os.path.exists(self._current_path):
            if os.path.getsize(self._current_path) >= self._max_bytes:
                self._current_path = self._new_file_path()
                self._prune_old_files()

    def _prune_old_files(self) -> None:
        """Delete oldest files when over the limit."""
        files = self._all_log_files()
        while len(files) > self._max_files:
            try:
                os.remove(files.pop(0))
            except OSError:
                pass
