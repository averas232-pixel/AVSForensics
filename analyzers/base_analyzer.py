"""
FileAutopsy — Base Analyzer
System-level metadata: timestamps, hashes, file type detection.
"""

import os
from datetime import datetime
from pathlib import Path
from typing import Optional
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.file_utils import detect_real_type, compute_hashes, get_file_size_human


class BaseAnalyzer:
    """
    Base class for all file analyzers.
    Collects filesystem metadata, hashes, and real type detection.
    Subclasses extend with format-specific metadata.
    """

    def __init__(self, filepath: Path):
        self.filepath = filepath
        self.flags: list[dict] = []  # Accumulated risk flags
        self.results: dict = {}

    def analyze(self) -> dict:
        """Run base analysis. Call super().analyze() from subclasses."""
        stat = self.filepath.stat()

        created = self._get_creation_time(stat)
        modified = datetime.fromtimestamp(stat.st_mtime)
        accessed = datetime.fromtimestamp(stat.st_atime)

        real_type = detect_real_type(self.filepath)
        hashes = compute_hashes(self.filepath)

        base = {
            "file": {
                "name": self.filepath.name,
                "path": str(self.filepath.resolve()),
                "size": get_file_size_human(self.filepath),
                "size_bytes": stat.st_size,
                "extension": self.filepath.suffix.lower(),
            },
            "system_dates": {
                "created": self._fmt(created),
                "modified": self._fmt(modified),
                "accessed": self._fmt(accessed),
                "created_raw": created,
                "modified_raw": modified,
            },
            "real_type": real_type,
            "hashes": hashes,
            "flags": self.flags,
        }

        # Flag magic byte mismatch
        if real_type.get("mismatch"):
            self._add_flag("MAGIC_MISMATCH", "critical",
                f"Extension '{real_type['declared_extension']}' but real type is '{real_type['detected']}'")

        self.results = base
        return base

    def _get_creation_time(self, stat) -> datetime:
        """Cross-platform creation time."""
        if hasattr(stat, "st_birthtime"):
            return datetime.fromtimestamp(stat.st_birthtime)
        # Linux: use st_ctime as fallback (inode change time)
        return datetime.fromtimestamp(stat.st_ctime)

    def _add_flag(self, name: str, level: str, message: str):
        self.flags.append({"name": name, "level": level, "message": message})

    def _fmt(self, dt: Optional[datetime]) -> str:
        if dt is None:
            return "N/A"
        return dt.strftime("%Y-%m-%d %H:%M:%S")

    def _check_future_date(self, dt: Optional[datetime], label: str):
        if dt and dt > datetime.now():
            self._add_flag("FUTURE_DATE", "critical",
                f"{label} is set in the future: {self._fmt(dt)}")

    def _check_date_mismatch(self, meta_dt: Optional[datetime], sys_dt: Optional[datetime],
                               label: str, tolerance_days: int = 2):
        if meta_dt and sys_dt:
            diff = abs((meta_dt - sys_dt).total_seconds()) / 86400
            if diff > tolerance_days:
                self._add_flag("DATE_MISMATCH", "warning",
                    f"{label}: metadata={self._fmt(meta_dt)} vs filesystem={self._fmt(sys_dt)} "
                    f"(Δ {diff:.1f} days)")
