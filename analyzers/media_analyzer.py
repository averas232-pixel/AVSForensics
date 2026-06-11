"""
FileAutopsy — Media Analyzer
Handles MP3, MP4, AVI, MOV, MKV, WAV, FLAC, OGG, M4A.
Extracts codec, bitrate, duration, device, GPS, recording date.
"""

import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))
from analyzers.base_analyzer import BaseAnalyzer


class MediaAnalyzer(BaseAnalyzer):

    def analyze(self) -> dict:
        base = super().analyze()
        ext = self.filepath.suffix.lower()

        meta = self._analyze_mutagen()
        base["media"] = meta

        base["flags"] = self.flags
        self.results = base
        return base

    def _analyze_mutagen(self) -> dict:
        try:
            import mutagen
            from mutagen import File as MutagenFile
            from mutagen.mp4 import MP4
            from mutagen.id3 import ID3
            from mutagen.flac import FLAC
            from mutagen.oggvorbis import OggVorbis

            audio = MutagenFile(str(self.filepath), easy=False)

            if audio is None:
                return {"error": "Could not parse media file with mutagen"}

            result = {
                "format": type(audio).__name__,
                "duration": self._fmt_duration(audio.info.length if hasattr(audio, 'info') and audio.info else None),
                "duration_seconds": round(audio.info.length, 2) if hasattr(audio, 'info') and audio.info else None,
                "bitrate_kbps": None,
                "sample_rate_hz": None,
                "channels": None,
                "codec": None,
                "title": None,
                "artist": None,
                "album": None,
                "date_recorded": None,
                "encoder": None,
                "comment": None,
                "gps": {"latitude": None, "longitude": None},
            }

            info = audio.info if hasattr(audio, 'info') else None
            if info:
                if hasattr(info, 'bitrate'):
                    result["bitrate_kbps"] = f"{info.bitrate // 1000} kbps" if info.bitrate else None
                if hasattr(info, 'sample_rate'):
                    result["sample_rate_hz"] = f"{info.sample_rate} Hz"
                if hasattr(info, 'channels'):
                    result["channels"] = info.channels
                if hasattr(info, 'codec'):
                    result["codec"] = info.codec
                # MP4-specific
                if hasattr(info, 'codec_description'):
                    result["codec"] = info.codec_description

            # Extract tags per format
            type_name = type(audio).__name__

            if "MP4" in type_name:
                result.update(self._parse_mp4_tags(audio))
            elif "ID3" in type_name or "MP3" in type_name:
                result.update(self._parse_id3_tags(audio))
            elif "FLAC" in type_name:
                result.update(self._parse_vorbis_tags(audio))
            elif "Ogg" in type_name:
                result.update(self._parse_vorbis_tags(audio))
            elif "AIFF" in type_name:
                result.update(self._parse_id3_tags(audio))
            else:
                # Generic fallback
                result.update(self._parse_generic_tags(audio))

            # GPS flag
            gps = result.get("gps", {})
            if gps.get("latitude") is not None:
                lat, lon = gps["latitude"], gps["longitude"]
                result["gps"]["maps_link"] = f"https://maps.google.com/?q={lat},{lon}"
                self._add_flag("GPS_PRESENT", "info",
                    f"GPS in media file: {lat:.6f}, {lon:.6f}")

            # Date checks
            date_str = result.get("date_recorded")
            if date_str:
                dt = self._parse_date(date_str)
                self._check_future_date(dt, "Media recording date")

            return result

        except Exception as e:
            return {"error": str(e)}

    def _parse_mp4_tags(self, audio) -> dict:
        tags = audio.tags or {}
        result = {}

        def get(key, default=None):
            v = tags.get(key)
            if v is None:
                return default
            if isinstance(v, list):
                return str(v[0]) if v else default
            return str(v)

        result["title"] = get("\xa9nam")
        result["artist"] = get("\xa9ART")
        result["album"] = get("\xa9alb")
        result["date_recorded"] = get("\xa9day")
        result["encoder"] = get("\xa9too") or get("©enc")
        result["comment"] = get("\xa9cmt")

        # GPS in MP4 — stored in ©xyz or udta
        xyz = tags.get("©xyz") or tags.get("\xa9xyz")
        if xyz:
            gps = self._parse_mp4_gps(str(xyz[0]) if isinstance(xyz, list) else str(xyz))
            if gps:
                result["gps"] = gps

        # Device / make
        device = get("©mak") or get("©mod")
        if device:
            result["device"] = device

        return result

    def _parse_mp4_gps(self, xyz_str: str) -> Optional[dict]:
        """Parse ©xyz tag: '+lat+lon/' or similar."""
        import re
        m = re.match(r'([+-]?\d+\.?\d*)([+-]\d+\.?\d*)', xyz_str.replace('\x00', ''))
        if m:
            lat, lon = float(m.group(1)), float(m.group(2))
            return {"latitude": lat, "longitude": lon}
        return None

    def _parse_id3_tags(self, audio) -> dict:
        from mutagen.id3 import TIT2, TPE1, TALB, TDRC, TENC, COMM, TSSE
        tags = audio.tags if audio.tags else {}
        result = {}

        def get_text(key):
            v = tags.get(key)
            return str(v.text[0]) if v and hasattr(v, 'text') and v.text else None

        result["title"] = get_text("TIT2")
        result["artist"] = get_text("TPE1")
        result["album"] = get_text("TALB")
        result["date_recorded"] = get_text("TDRC")
        result["encoder"] = get_text("TENC") or get_text("TSSE")

        # COMM (comment)
        for key in tags:
            if key.startswith("COMM"):
                v = tags[key]
                if hasattr(v, 'text') and v.text:
                    result["comment"] = str(v.text[0])
                break

        # GEOB or TXXX for GPS? Some cameras embed GPS in custom frames
        for key in tags:
            if key.startswith("TXXX") and "gps" in key.lower():
                result["comment"] = (result.get("comment") or "") + f" [GPS tag: {key}]"

        return result

    def _parse_vorbis_tags(self, audio) -> dict:
        tags = audio.tags or {}
        result = {
            "title": self._first(tags.get("title")),
            "artist": self._first(tags.get("artist")),
            "album": self._first(tags.get("album")),
            "date_recorded": self._first(tags.get("date")),
            "encoder": self._first(tags.get("encoder")),
            "comment": self._first(tags.get("comment")),
        }
        return result

    def _parse_generic_tags(self, audio) -> dict:
        tags = audio.tags or {}
        result = {}
        for key in ["title", "artist", "album", "date", "encoder", "comment"]:
            v = tags.get(key) or tags.get(key.upper())
            if v:
                result[key if key != "date" else "date_recorded"] = self._first(v) if isinstance(v, list) else str(v)
        return result

    def _first(self, val):
        if val is None:
            return None
        if isinstance(val, list):
            return str(val[0]) if val else None
        return str(val)

    def _fmt_duration(self, seconds: Optional[float]) -> Optional[str]:
        if seconds is None:
            return None
        h = int(seconds // 3600)
        m = int((seconds % 3600) // 60)
        s = int(seconds % 60)
        if h > 0:
            return f"{h:02d}:{m:02d}:{s:02d}"
        return f"{m:02d}:{s:02d}"

    def _parse_date(self, date_str: str) -> Optional[datetime]:
        if not date_str:
            return None
        clean = str(date_str).strip()
        for fmt in ["%Y-%m-%d", "%Y", "%Y-%m-%dT%H:%M:%S", "%Y%m%d"]:
            try:
                return datetime.strptime(clean[:len(fmt)], fmt)
            except Exception:
                continue
        return None
