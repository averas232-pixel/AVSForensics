#!/usr/bin/env python3
"""
AVSForensics — Digital Forensics Metadata Analyzer
CLI entrypoint. Supports individual files and folders.
"""

import argparse
import sys
import os
from pathlib import Path

# Make sure project root is in path
sys.path.insert(0, str(Path(__file__).parent))

from utils.logger import console, banner, section, field, flag as log_flag, success, info, warning, critical
from utils.file_utils import collect_targets, get_file_size_human
from config import SUPPORTED_EXTENSIONS


def get_analyzer(filepath: Path):
    """Return the appropriate analyzer for a file."""
    ext = filepath.suffix.lower()
    from analyzers.image_analyzer import ImageAnalyzer
    from analyzers.document_analyzer import DocumentAnalyzer
    from analyzers.media_analyzer import MediaAnalyzer
    from analyzers.base_analyzer import BaseAnalyzer

    if ext in SUPPORTED_EXTENSIONS["image"]:
        return ImageAnalyzer(filepath)
    elif ext in SUPPORTED_EXTENSIONS["document"]:
        return DocumentAnalyzer(filepath)
    elif ext in SUPPORTED_EXTENSIONS["media"]:
        return MediaAnalyzer(filepath)
    else:
        return BaseAnalyzer(filepath)


def print_results(results: dict, modules: str = "all"):
    """Pretty-print analysis results to terminal."""
    file_info = results.get("file", {})
    real_type = results.get("real_type", {})
    sys_dates = results.get("system_dates", {})
    hashes = results.get("hashes", {})
    flags = results.get("flags", [])

    # ── File Overview ─────────────────────────────────────────────────────────
    section(f"FILE OVERVIEW", file_info.get("path", ""))
    field("Name", file_info.get("name"))
    field("Size", file_info.get("size"))
    field("Extension", file_info.get("extension"))
    field("Detected Type", real_type.get("detected"))

    if real_type.get("mismatch"):
        critical(f"MAGIC MISMATCH — Extension '{real_type['declared_extension']}' but real type: '{real_type['detected']}'")

    # ── System Dates ──────────────────────────────────────────────────────────
    section("SYSTEM DATES")
    field("Created (FS)", sys_dates.get("created"))
    field("Modified (FS)", sys_dates.get("modified"))
    field("Accessed (FS)", sys_dates.get("accessed"))

    # ── Format-specific ───────────────────────────────────────────────────────
    if "camera" in results and (modules in ("all", "meta")):
        cam = results["camera"]
        section("CAMERA / DEVICE")
        field("Make", cam.get("make"))
        field("Model", cam.get("model"))
        field("Lens", cam.get("lens"))
        field("Software", cam.get("software"))
        field("Flash", cam.get("flash"))
        field("ISO", cam.get("iso"))
        field("Focal Length", cam.get("focal_length"))
        field("Exposure", cam.get("exposure"))
        field("Aperture", cam.get("aperture"))

        img = results.get("image", {})
        section("IMAGE PROPERTIES")
        field("Dimensions", img.get("dimensions"))
        field("Color Mode", img.get("color_mode"))
        field("Format", img.get("format"))
        field("DPI", img.get("dpi"))

        dates = results.get("dates", {})
        section("CAPTURE DATES")
        field("Captured (EXIF)", dates.get("captured"))
        field("Digitized", dates.get("digitized"))
        field("Modified (Meta)", dates.get("modified_meta"))

        gps = results.get("gps", {})
        if gps.get("latitude") is not None:
            section("GPS LOCATION", "Location data found in image metadata")
            field("Latitude", f"{gps['latitude']:.6f}")
            field("Longitude", f"{gps['longitude']:.6f}")
            if gps.get("altitude_m"):
                field("Altitude", gps["altitude_m"])
            if gps.get("maps_link"):
                field("Maps Link", gps["maps_link"], style="gps")

    if "document" in results and (modules in ("all", "meta")):
        doc = results["document"]
        section("DOCUMENT METADATA")
        field("Format", doc.get("format"))
        field("Author", doc.get("author"))
        field("Last Modified By", doc.get("last_modified_by"))
        field("Title", doc.get("title"))
        field("Subject", doc.get("subject"))
        field("Keywords", doc.get("keywords"))
        field("Created App", doc.get("creator_app") or doc.get("producer"))
        field("Created", doc.get("created"))
        field("Modified", doc.get("modified"))
        if doc.get("revision") is not None:
            field("Revisions", str(doc.get("revision")))
        if doc.get("pages"):
            field("Pages", str(doc.get("pages")))
        if doc.get("sheets"):
            field("Sheets", ", ".join(doc.get("sheets", [])))
        if doc.get("encrypted") is not None:
            field("Encrypted", "Yes" if doc.get("encrypted") else "No")

    if "media" in results and (modules in ("all", "meta")):
        media = results["media"]
        section("MEDIA METADATA")
        field("Format", media.get("format"))
        field("Duration", media.get("duration"))
        field("Bitrate", media.get("bitrate_kbps"))
        field("Sample Rate", media.get("sample_rate_hz"))
        field("Channels", media.get("channels"))
        field("Codec", media.get("codec"))
        field("Title", media.get("title"))
        field("Artist", media.get("artist"))
        field("Album", media.get("album"))
        field("Date Recorded", media.get("date_recorded"))
        field("Encoder", media.get("encoder"))
        field("Device", media.get("device"))
        gps = media.get("gps", {})
        if gps and gps.get("latitude"):
            field("GPS Latitude", f"{gps['latitude']:.6f}", style="gps")
            field("GPS Longitude", f"{gps['longitude']:.6f}", style="gps")
            if gps.get("maps_link"):
                field("Maps Link", gps["maps_link"], style="gps")

    # ── Hashes ────────────────────────────────────────────────────────────────
    if modules in ("all", "hash"):
        section("INTEGRITY HASHES")
        field("MD5", hashes.get("md5"), style="hash")
        field("SHA256", hashes.get("sha256"), style="hash")

    # ── Flags ─────────────────────────────────────────────────────────────────
    if modules in ("all", "flags") and flags:
        section("FORENSIC FLAGS", f"{len(flags)} anomalies detected")
        for f in flags:
            log_flag(f["name"], f["message"], f["level"])
    elif modules in ("all", "flags") and not flags:
        section("FORENSIC FLAGS")
        success("No anomalies detected")

    console.print()


def main():
    banner()

    parser = argparse.ArgumentParser(
        prog="avsforensics",
        description="AVSForensics — Digital Forensics Metadata Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --target foto.jpg
  python main.py --target documento.pdf --out markdown
  python main.py --target video.mp4 --modules all
  python main.py --target C:/fotos/ --recursive --out pdf
  python main.py --target folder/ --modules meta
        """,
    )

    parser.add_argument(
        "--target", "-t",
        required=True,
        help="File or folder to analyze",
    )
    parser.add_argument(
        "--modules", "-m",
        choices=["all", "meta", "hash", "flags"],
        default="all",
        help="Which analysis modules to show (default: all)",
    )
    parser.add_argument(
        "--out", "-o",
        choices=["markdown", "pdf"],
        default=None,
        help="Export report format",
    )
    parser.add_argument(
        "--recursive", "-r",
        action="store_true",
        help="Recursively analyze subdirectories",
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory to save reports (default: current dir)",
    )

    args = parser.parse_args()

    target = Path(args.target)
    if not target.exists():
        critical(f"Target not found: {target}")
        sys.exit(1)

    # Collect files
    files = collect_targets(target, recursive=args.recursive)

    if not files:
        warning(f"No supported files found in: {target}")
        info("Supported: images (jpg/png/heic...), documents (pdf/docx/xlsx...), media (mp4/mp3/avi...)")
        sys.exit(0)

    info(f"Found {len(files)} file(s) to analyze")
    console.print()

    all_results = []

    for filepath in files:
        try:
            analyzer = get_analyzer(filepath)
            results = analyzer.analyze()

            # Run extra manipulation detection
            from forensics.manipulation_detector import detect_manipulation
            extra_flags = detect_manipulation(results)
            results["flags"].extend(extra_flags)

            all_results.append(results)
            print_results(results, modules=args.modules)

        except KeyboardInterrupt:
            warning("Interrupted by user.")
            break
        except Exception as e:
            critical(f"Error analyzing {filepath.name}: {e}")
            import traceback
            traceback.print_exc()
            continue

    # ── Summary ───────────────────────────────────────────────────────────────
    if len(all_results) > 1:
        section("SUMMARY", f"{len(all_results)} files analyzed")
        total_flags = sum(len(r.get("flags", [])) for r in all_results)
        critical_flags = sum(
            1 for r in all_results for f in r.get("flags", []) if f["level"] == "critical"
        )
        field("Total Files Analyzed", str(len(all_results)))
        field("Total Flags Raised", str(total_flags))
        if critical_flags:
            field("Critical Anomalies", str(critical_flags), style="critical")
        else:
            field("Critical Anomalies", "None", style="success")

    # ── Export report ─────────────────────────────────────────────────────────
    if args.out and all_results:
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        stem = target.stem if target.is_file() else target.name
        timestamp = __import__("datetime").datetime.now().strftime("%Y%m%d_%H%M%S")

        if args.out == "markdown":
            from reports.report_generator import generate_markdown
            out_path = output_dir / f"avsforensics_{stem}_{timestamp}.md"
            generate_markdown(all_results, out_path)
            success(f"Markdown report saved: {out_path}")

        elif args.out == "pdf":
            from reports.report_generator import generate_pdf
            out_path = output_dir / f"avsforensics_{stem}_{timestamp}.pdf"
            ok = generate_pdf(all_results, out_path)
            if ok:
                success(f"PDF report saved: {out_path}")
            else:
                warning("PDF generation failed — try Markdown instead")

    console.print()


if __name__ == "__main__":
    main()
