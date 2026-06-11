"""
FileAutopsy — File Utilities
Real file type detection via magic bytes.
"""

import hashlib
import os
import struct
from pathlib import Path
from typing import Optional

# Magic byte signatures: (offset, bytes, description, mime)
MAGIC_SIGNATURES = [
    (0, b'\xff\xd8\xff',              "JPEG image",              "image/jpeg"),
    (0, b'\x89PNG\r\n\x1a\n',        "PNG image",               "image/png"),
    (0, b'GIF87a',                    "GIF image (87a)",         "image/gif"),
    (0, b'GIF89a',                    "GIF image (89a)",         "image/gif"),
    (0, b'BM',                        "BMP image",               "image/bmp"),
    (0, b'II\x2a\x00',               "TIFF image (little-end)", "image/tiff"),
    (0, b'MM\x00\x2a',               "TIFF image (big-end)",    "image/tiff"),
    (0, b'RIFF',                      "RIFF container",          "audio/wav"),   # also AVI
    (0, b'%PDF',                      "PDF document",            "application/pdf"),
    (0, b'PK\x03\x04',               "ZIP / Office Open XML",   "application/zip"),
    (0, b'\xd0\xcf\x11\xe0',         "OLE2 / Legacy Office",    "application/msoffice"),
    (0, b'ID3',                       "MP3 audio (ID3)",         "audio/mpeg"),
    (0, b'\xff\xfb',                  "MP3 audio",               "audio/mpeg"),
    (0, b'fLaC',                      "FLAC audio",              "audio/flac"),
    (0, b'OggS',                      "OGG container",           "audio/ogg"),
    (4, b'ftyp',                      "MP4 / MOV video",         "video/mp4"),
    (0, b'\x1aE\xdf\xa3',            "MKV / WebM video",        "video/mkv"),
    (0, b'FORM',                      "AIFF audio",              "audio/aiff"),
    (0, b'\x00\x00\x00\x1cftyp',     "MP4 video",               "video/mp4"),
    (0, b'FLV',                       "Flash Video",             "video/x-flv"),
    (0, b'\x30\x26\xb2\x75',         "WMV/WMA (ASF)",           "video/x-ms-wmv"),
]

EXTENSION_MIME_MAP = {
    ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".png": "image/png", ".gif": "image/gif", ".bmp": "image/bmp",
    ".tiff": "image/tiff", ".tif": "image/tiff", ".webp": "image/webp",
    ".heic": "image/heic", ".heif": "image/heif",
    ".pdf": "application/pdf",
    ".docx": "application/zip", ".xlsx": "application/zip", ".pptx": "application/zip",
    ".doc": "application/msoffice", ".xls": "application/msoffice",
    ".mp3": "audio/mpeg", ".flac": "audio/flac", ".ogg": "audio/ogg",
    ".wav": "audio/wav", ".m4a": "video/mp4", ".aiff": "audio/aiff",
    ".mp4": "video/mp4", ".m4v": "video/mp4", ".mov": "video/mp4",
    ".avi": "audio/wav",  # RIFF-based
    ".mkv": "video/mkv", ".wmv": "video/x-ms-wmv",
}


def detect_real_type(filepath: Path) -> dict:
    """
    Detect the real file type using magic bytes.
    Returns dict with detected type info and whether extension matches.
    """
    try:
        with open(filepath, "rb") as f:
            header = f.read(32)
    except (OSError, PermissionError):
        return {"detected": "Unknown", "mime": "unknown", "mismatch": False}

    detected_desc = "Unknown"
    detected_mime = "unknown"

    for offset, signature, description, mime in MAGIC_SIGNATURES:
        chunk = header[offset:offset + len(signature)]
        if chunk == signature:
            detected_desc = description
            detected_mime = mime
            break

    # Normalize: RIFF can be WAV or AVI — peek further
    if detected_mime == "audio/wav" and len(header) >= 12:
        subtype = header[8:12]
        if subtype == b'AVI ':
            detected_desc = "AVI video"
            detected_mime = "video/avi"

    # Check extension vs real type
    ext = filepath.suffix.lower()
    expected_mime = EXTENSION_MIME_MAP.get(ext, "")

    # Mismatch: compare top-level type
    mismatch = False
    if expected_mime and detected_mime != "unknown":
        exp_top = expected_mime.split("/")[0]
        det_top = detected_mime.split("/")[0]
        if exp_top != det_top:
            mismatch = True
        # More specific check for ZIP-based Office formats
        if detected_mime == "application/zip" and expected_mime == "application/zip":
            mismatch = False  # Both are ZIP-based, fine

    return {
        "detected": detected_desc,
        "mime": detected_mime,
        "declared_extension": ext,
        "mismatch": mismatch,
    }


def compute_hashes(filepath: Path) -> dict:
    """Compute MD5 and SHA256 hashes of a file."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk)
                sha256.update(chunk)
        return {
            "md5": md5.hexdigest(),
            "sha256": sha256.hexdigest(),
        }
    except (OSError, PermissionError):
        return {"md5": "Error", "sha256": "Error"}


def get_file_size_human(filepath: Path) -> str:
    """Human-readable file size."""
    size = filepath.stat().st_size
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def collect_targets(target: Path, recursive: bool = False, extensions: list = None) -> list[Path]:
    """
    Collect all files to analyze from a path (file or directory).
    Returns list of Path objects.
    """
    from config import ALL_SUPPORTED
    allowed = extensions or ALL_SUPPORTED

    if target.is_file():
        return [target]

    if target.is_dir():
        if recursive:
            files = [p for p in target.rglob("*") if p.is_file() and p.suffix.lower() in allowed]
        else:
            files = [p for p in target.iterdir() if p.is_file() and p.suffix.lower() in allowed]
        return sorted(files)

    return []
