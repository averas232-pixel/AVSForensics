"""
FileAutopsy — Configuration
"""

# Supported extensions by category
SUPPORTED_EXTENSIONS = {
    "image": [".jpg", ".jpeg", ".png", ".heic", ".heif", ".gif", ".bmp", ".tiff", ".tif", ".webp"],
    "document": [".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt"],
    "media": [".mp4", ".mp3", ".avi", ".mov", ".mkv", ".wav", ".flac", ".ogg", ".m4a", ".m4v", ".wmv"],
}

ALL_SUPPORTED = [ext for exts in SUPPORTED_EXTENSIONS.values() for ext in exts]

# Risk flag definitions
RISK_FLAGS = {
    "GPS_PRESENT": {
        "level": "info",
        "message": "GPS coordinates found — location data exposed",
    },
    "DATE_MISMATCH": {
        "level": "warning",
        "message": "Mismatch between system date and metadata date — possible manipulation",
    },
    "EDITOR_TRACE": {
        "level": "warning",
        "message": "Evidence of post-processing software (Photoshop, GIMP, etc.)",
    },
    "METADATA_STRIPPED": {
        "level": "info",
        "message": "Metadata appears stripped or minimal — possible sanitization",
    },
    "AUTHOR_MISMATCH": {
        "level": "warning",
        "message": "Original author differs from last editor",
    },
    "REVISION_HIGH": {
        "level": "info",
        "message": "High number of document revisions",
    },
    "MAGIC_MISMATCH": {
        "level": "critical",
        "message": "File extension does not match real file type (magic bytes) — possible disguise",
    },
    "FUTURE_DATE": {
        "level": "critical",
        "message": "Metadata contains a future date — likely tampered",
    },
    "SUSPICIOUS_SOFTWARE": {
        "level": "warning",
        "message": "Created/modified by potentially suspicious or uncommon software",
    },
    "EMPTY_AUTHOR": {
        "level": "info",
        "message": "Author field is empty or anonymous",
    },
    "TIMEZONE_ANOMALY": {
        "level": "warning",
        "message": "Timezone offset is unusual or inconsistent",
    },
}

# Software known to manipulate or edit media
EDITOR_SOFTWARE_KEYWORDS = [
    "photoshop", "lightroom", "gimp", "affinity", "capture one",
    "darktable", "rawtherapee", "snapseed", "vsco", "pixelmator",
    "paint.net", "canva", "adobe", "corel",
]

SUSPICIOUS_SOFTWARE_KEYWORDS = [
    "metadata editor", "exif tool", "metashred", "exif eraser",
    "photo investigator", "metastripper", "metadata cleaner",
]

# Thresholds
HIGH_REVISION_THRESHOLD = 20
DATE_TOLERANCE_DAYS = 2  # Tolerance for date comparison (filesystem vs metadata)
