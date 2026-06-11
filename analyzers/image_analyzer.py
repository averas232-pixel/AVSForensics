"""
FileAutopsy — Image Analyzer
Handles JPG, PNG, HEIC, GIF, BMP, TIFF, WEBP.
Extracts EXIF, GPS coordinates, camera info, editor traces.
"""

import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))
from analyzers.base_analyzer import BaseAnalyzer
from config import EDITOR_SOFTWARE_KEYWORDS, SUSPICIOUS_SOFTWARE_KEYWORDS


class ImageAnalyzer(BaseAnalyzer):

    def analyze(self) -> dict:
        base = super().analyze()
        exif_data = self._extract_exif()
        image_info = self._extract_pillow_info()

        base["image"] = {
            "dimensions": image_info.get("dimensions"),
            "color_mode": image_info.get("mode"),
            "format": image_info.get("format"),
            "dpi": image_info.get("dpi"),
        }

        base["camera"] = {
            "make": exif_data.get("Image Make"),
            "model": exif_data.get("Image Model"),
            "lens": exif_data.get("EXIF LensModel"),
            "software": exif_data.get("Image Software"),
            "flash": self._decode_flash(exif_data.get("EXIF Flash")),
            "iso": exif_data.get("EXIF ISOSpeedRatings"),
            "focal_length": exif_data.get("EXIF FocalLength"),
            "exposure": exif_data.get("EXIF ExposureTime"),
            "aperture": exif_data.get("EXIF FNumber"),
        }

        # Dates from EXIF
        exif_dt = self._parse_exif_date(exif_data.get("EXIF DateTimeOriginal") or
                                         exif_data.get("Image DateTime"))
        digitized_dt = self._parse_exif_date(exif_data.get("EXIF DateTimeDigitized"))

        base["dates"] = {
            "captured": self._fmt(exif_dt),
            "digitized": self._fmt(digitized_dt),
            "modified_meta": exif_data.get("Image DateTime"),
        }

        # GPS
        gps = self._extract_gps(exif_data)
        base["gps"] = gps

        # Forensic checks
        self._check_editor_software(exif_data.get("Image Software", ""))
        self._check_future_date(exif_dt, "EXIF capture date")
        if exif_dt and base["system_dates"]["modified_raw"]:
            self._check_date_mismatch(exif_dt, base["system_dates"]["modified_raw"],
                                       "Capture date vs filesystem modified", tolerance_days=1)

        # Flag GPS presence
        if gps.get("latitude") is not None:
            self._add_flag("GPS_PRESENT", "info",
                f"GPS: {gps['latitude']:.6f}, {gps['longitude']:.6f}")

        # Flag if no EXIF at all
        if not exif_data:
            self._add_flag("METADATA_STRIPPED", "info", "No EXIF data found — may have been stripped")

        base["flags"] = self.flags
        self.results = base
        return base

    def _extract_exif(self) -> dict:
        try:
            import exifread
            with open(self.filepath, "rb") as f:
                tags = exifread.process_file(f, details=True, stop_tag="UNDEF")
            return {k: str(v) for k, v in tags.items()}
        except Exception:
            return {}

    def _extract_pillow_info(self) -> dict:
        try:
            from PIL import Image
            with Image.open(self.filepath) as img:
                dpi = img.info.get("dpi")
                return {
                    "dimensions": f"{img.width} × {img.height} px",
                    "mode": img.mode,
                    "format": img.format,
                    "dpi": f"{dpi[0]:.0f} × {dpi[1]:.0f} DPI" if dpi else None,
                }
        except Exception:
            return {}

    def _extract_gps(self, exif: dict) -> dict:
        try:
            import exifread

            def to_decimal(values_str: str, ref: str) -> Optional[float]:
                # Parse "[d, m, s]" format from exifread
                import re
                nums = re.findall(r'[\d/\.]+', values_str)
                if len(nums) < 3:
                    return None

                def frac(s):
                    if '/' in s:
                        a, b = s.split('/')
                        return float(a) / float(b) if float(b) != 0 else 0
                    return float(s)

                d, m, s = frac(nums[0]), frac(nums[1]), frac(nums[2])
                decimal = d + m / 60 + s / 3600
                if ref in ('S', 'W'):
                    decimal = -decimal
                return decimal

            lat_str = exif.get("GPS GPSLatitude")
            lat_ref = exif.get("GPS GPSLatitudeRef", "N")
            lon_str = exif.get("GPS GPSLongitude")
            lon_ref = exif.get("GPS GPSLongitudeRef", "E")
            alt_str = exif.get("GPS GPSAltitude")

            if not (lat_str and lon_str):
                return {"latitude": None, "longitude": None}

            lat = to_decimal(lat_str, lat_ref)
            lon = to_decimal(lon_str, lon_ref)

            result = {
                "latitude": lat,
                "longitude": lon,
                "maps_link": f"https://maps.google.com/?q={lat},{lon}" if lat and lon else None,
            }

            if alt_str:
                try:
                    import re
                    nums = re.findall(r'[\d/\.]+', alt_str)
                    if nums:
                        n = nums[0]
                        if '/' in n:
                            a, b = n.split('/')
                            alt = float(a) / float(b)
                        else:
                            alt = float(n)
                        result["altitude_m"] = f"{alt:.1f} m"
                except Exception:
                    pass

            return result
        except Exception:
            return {"latitude": None, "longitude": None}

    def _parse_exif_date(self, date_str: Optional[str]) -> Optional[datetime]:
        if not date_str:
            return None
        for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y:%m:%d"):
            try:
                return datetime.strptime(date_str.strip(), fmt)
            except ValueError:
                continue
        return None

    def _decode_flash(self, flash_val: Optional[str]) -> Optional[str]:
        if flash_val is None:
            return None
        try:
            v = int(str(flash_val))
            fired = bool(v & 0x1)
            return "Fired" if fired else "Did not fire"
        except Exception:
            return str(flash_val)

    def _check_editor_software(self, software: str):
        s = software.lower()
        for kw in SUSPICIOUS_SOFTWARE_KEYWORDS:
            if kw in s:
                self._add_flag("SUSPICIOUS_SOFTWARE", "warning",
                    f"Software '{software}' is a known metadata editor")
                return
        for kw in EDITOR_SOFTWARE_KEYWORDS:
            if kw in s:
                self._add_flag("EDITOR_TRACE", "warning",
                    f"Image processed by editing software: '{software}'")
                return
