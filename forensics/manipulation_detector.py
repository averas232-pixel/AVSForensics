"""
FileAutopsy — Manipulation Detector
Cross-checks metadata fields to detect tampering and inconsistencies.
"""

from datetime import datetime
from typing import Optional


def detect_manipulation(results: dict) -> list[dict]:
    """
    Analyze a results dict (from any analyzer) and return additional
    manipulation-specific flags beyond what individual analyzers add.
    """
    flags = []

    # ── Check 1: Created after Modified ──────────────────────────────────────
    doc = results.get("document") or {}
    img_dates = results.get("dates") or {}
    sys_dates = results.get("system_dates") or {}

    created_raw = doc.get("created_raw") or _parse_any_date(img_dates.get("captured"))
    modified_raw = doc.get("modified_raw") or results.get("system_dates", {}).get("modified_raw")

    if created_raw and modified_raw:
        c = _strip_tz(created_raw)
        m = _strip_tz(modified_raw)
        if isinstance(c, datetime) and isinstance(m, datetime):
            if c > m:
                flags.append({
                    "name": "CREATION_AFTER_MODIFICATION",
                    "level": "critical",
                    "message": f"File creation date ({c.date()}) is after modification date ({m.date()}) — likely tampered",
                })

    # ── Check 2: Filesystem vs Metadata date gap > 30 days ───────────────────
    sys_mod_raw = sys_dates.get("modified_raw")
    if created_raw and sys_mod_raw:
        c = _strip_tz(created_raw)
        s = _strip_tz(sys_mod_raw)
        if isinstance(c, datetime) and isinstance(s, datetime):
            diff_days = abs((c - s).days)
            if diff_days > 30:
                flags.append({
                    "name": "LARGE_DATE_GAP",
                    "level": "warning",
                    "message": f"Metadata date vs filesystem date differ by {diff_days} days — possible re-dating",
                })

    # ── Check 3: Both author fields empty ────────────────────────────────────
    author = doc.get("author")
    last_mod_by = doc.get("last_modified_by")
    if author is None and last_mod_by is None and doc:
        # Already flagged at analyzer level usually; skip duplicate
        pass

    # ── Check 4: GPS in non-camera context ───────────────────────────────────
    gps = results.get("gps") or {}
    camera = results.get("camera") or {}
    if gps.get("latitude") and not camera.get("make") and not camera.get("model"):
        flags.append({
            "name": "GPS_WITHOUT_CAMERA",
            "level": "info",
            "message": "GPS coordinates present but no camera device info — unusual for a photo",
        })

    # ── Check 5: Future system dates ─────────────────────────────────────────
    sys_created_str = sys_dates.get("created")
    if sys_created_str and sys_created_str != "N/A":
        try:
            sys_created = datetime.strptime(sys_created_str, "%Y-%m-%d %H:%M:%S")
            if sys_created > datetime.now():
                flags.append({
                    "name": "FUTURE_FILESYSTEM_DATE",
                    "level": "critical",
                    "message": f"Filesystem creation date is in the future: {sys_created_str}",
                })
        except Exception:
            pass

    return flags


def _strip_tz(dt):
    if isinstance(dt, datetime) and dt.tzinfo is not None:
        return dt.replace(tzinfo=None)
    return dt


def _parse_any_date(date_str: Optional[str]) -> Optional[datetime]:
    if not date_str or date_str == "N/A":
        return None
    for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y:%m:%d %H:%M:%S"]:
        try:
            return datetime.strptime(date_str[:len(fmt)], fmt)
        except Exception:
            continue
    return None
