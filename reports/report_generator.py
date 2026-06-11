"""
AVSForensics — Report Generator
Exports analysis results as Markdown or PDF.
"""

import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))


def generate_markdown(all_results: list[dict], output_path: Optional[Path] = None) -> str:
    """Generate a Markdown forensics report from a list of file result dicts."""
    lines = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines.append("# AVSForensics — Forensic Metadata Report")
    lines.append(f"\n**Generated:** {now}  ")
    lines.append(f"**Files analyzed:** {len(all_results)}\n")
    lines.append("---\n")

    for i, res in enumerate(all_results, 1):
        file_info = res.get("file", {})
        filename = file_info.get("name", "Unknown")
        lines.append(f"## {i}. {filename}\n")

        # File info
        lines.append("### File Info")
        lines.append(f"- **Path:** `{file_info.get('path', 'N/A')}`")
        lines.append(f"- **Size:** {file_info.get('size', 'N/A')}")
        lines.append(f"- **Extension:** `{file_info.get('extension', 'N/A')}`")

        # Real type
        real = res.get("real_type", {})
        lines.append(f"- **Detected Type:** {real.get('detected', 'Unknown')}")
        if real.get("mismatch"):
            lines.append(f"- **⚠ Type Mismatch:** Extension vs real type do not match!")

        # System dates
        sys_dates = res.get("system_dates", {})
        lines.append("\n### System Dates")
        lines.append(f"- **Created:** {sys_dates.get('created', 'N/A')}")
        lines.append(f"- **Modified:** {sys_dates.get('modified', 'N/A')}")
        lines.append(f"- **Accessed:** {sys_dates.get('accessed', 'N/A')}")

        # Hashes
        hashes = res.get("hashes", {})
        lines.append("\n### Integrity Hashes")
        lines.append(f"- **MD5:** `{hashes.get('md5', 'N/A')}`")
        lines.append(f"- **SHA256:** `{hashes.get('sha256', 'N/A')}`")

        # Format-specific
        if "camera" in res:
            cam = res["camera"]
            lines.append("\n### Camera / Device")
            for k, v in cam.items():
                if v:
                    lines.append(f"- **{k.title()}:** {v}")

            img_dates = res.get("dates", {})
            if any(img_dates.values()):
                lines.append("\n### Capture Dates")
                for k, v in img_dates.items():
                    if v and not k.endswith("_raw"):
                        lines.append(f"- **{k.replace('_', ' ').title()}:** {v}")

            gps = res.get("gps", {})
            if gps.get("latitude"):
                lines.append("\n### GPS Location")
                lines.append(f"- **Coordinates:** {gps['latitude']:.6f}, {gps['longitude']:.6f}")
                if gps.get("maps_link"):
                    lines.append(f"- **Maps Link:** {gps['maps_link']}")
                if gps.get("altitude_m"):
                    lines.append(f"- **Altitude:** {gps['altitude_m']}")

        if "document" in res:
            doc = res["document"]
            lines.append("\n### Document Metadata")
            skip_keys = {"created_raw", "modified_raw", "error", "sheets"}
            for k, v in doc.items():
                if k not in skip_keys and v is not None:
                    lines.append(f"- **{k.replace('_', ' ').title()}:** {v}")

        if "media" in res:
            media = res["media"]
            lines.append("\n### Media Metadata")
            skip_keys = {"gps", "error"}
            for k, v in media.items():
                if k not in skip_keys and v is not None:
                    lines.append(f"- **{k.replace('_', ' ').title()}:** {v}")
            gps = media.get("gps", {})
            if gps.get("latitude"):
                lines.append(f"\n**GPS:** {gps['latitude']:.6f}, {gps['longitude']:.6f}")
                if gps.get("maps_link"):
                    lines.append(f"  — [Open in Maps]({gps['maps_link']})")

        # Flags
        flags = res.get("flags", [])
        if flags:
            lines.append("\n### 🚩 Forensic Flags")
            for f in flags:
                icon = {"info": "ℹ️", "warning": "⚠️", "critical": "🔴"}.get(f["level"], "•")
                lines.append(f"- {icon} **[{f['name']}]** {f['message']}")
        else:
            lines.append("\n### ✅ Forensic Flags")
            lines.append("- No anomalies detected.")

        lines.append("\n---\n")

    content = "\n".join(lines)

    if output_path:
        output_path.write_text(content, encoding="utf-8")

    return content


def generate_pdf(all_results: list[dict], output_path: Path):
    """Generate a PDF forensics report."""
    try:
        from fpdf import FPDF

        class ForensicPDF(FPDF):
            def header(self):
                self.set_font("Helvetica", "B", 10)
                self.set_text_color(50, 50, 200)
                self.cell(0, 8, "AVSForensics — Forensic Metadata Report", align="C")
                self.ln(4)
                self.set_draw_color(50, 50, 200)
                self.line(10, self.get_y(), 200, self.get_y())
                self.ln(4)

            def footer(self):
                self.set_y(-12)
                self.set_font("Helvetica", "I", 8)
                self.set_text_color(150)
                self.cell(0, 5, f"Page {self.page_no()} — AVSForensics", align="C")

        pdf = ForensicPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        # Title
        pdf.set_font("Helvetica", "B", 16)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 10, "Forensic Metadata Analysis", ln=True)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(100)
        pdf.cell(0, 6, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}   Files: {len(all_results)}", ln=True)
        pdf.ln(4)

        for i, res in enumerate(all_results, 1):
            file_info = res.get("file", {})
            filename = file_info.get("name", "Unknown")

            # File header
            pdf.set_fill_color(40, 40, 120)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(0, 8, f"  {i}. {filename}", fill=True, ln=True)
            pdf.set_text_color(30, 30, 30)
            pdf.ln(2)

            def row(label, value, color=(30, 30, 30)):
                if value is None or value == "" or value == "N/A":
                    return
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_text_color(60, 60, 150)
                pdf.cell(50, 5, str(label)[:35])
                pdf.set_font("Helvetica", "", 8)
                pdf.set_text_color(*color)
                safe_val = str(value).encode('latin-1', errors='replace').decode('latin-1')
                pdf.multi_cell(0, 5, safe_val[:200])

            def section_title(title):
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(50, 50, 200)
                pdf.cell(0, 6, title, ln=True)
                pdf.set_draw_color(200, 200, 220)
                pdf.line(10, pdf.get_y(), 200, pdf.get_y())
                pdf.ln(1)

            section_title("File Information")
            row("Path:", file_info.get("path"))
            row("Size:", file_info.get("size"))
            real = res.get("real_type", {})
            row("Detected Type:", real.get("detected"))
            if real.get("mismatch"):
                row("⚠ TYPE MISMATCH:", "Extension does not match real file type!", (200, 50, 50))

            section_title("System Dates")
            sys_dates = res.get("system_dates", {})
            row("Created:", sys_dates.get("created"))
            row("Modified:", sys_dates.get("modified"))

            section_title("Integrity Hashes")
            hashes = res.get("hashes", {})
            row("MD5:", hashes.get("md5"))
            row("SHA256:", hashes.get("sha256"))

            if "camera" in res:
                section_title("Camera / Device")
                cam = res["camera"]
                for k, v in cam.items():
                    if v:
                        row(f"{k.title()}:", v)
                gps = res.get("gps", {})
                if gps.get("latitude"):
                    section_title("GPS Location")
                    row("Coordinates:", f"{gps['latitude']:.6f}, {gps['longitude']:.6f}")
                    row("Maps:", gps.get("maps_link", ""))

            if "document" in res:
                section_title("Document Metadata")
                doc = res["document"]
                skip = {"created_raw", "modified_raw", "error", "sheets"}
                for k, v in doc.items():
                    if k not in skip and v is not None:
                        row(f"{k.replace('_', ' ').title()}:", v)

            if "media" in res:
                section_title("Media Metadata")
                media = res["media"]
                skip = {"gps", "error"}
                for k, v in media.items():
                    if k not in skip and v is not None:
                        row(f"{k.replace('_', ' ').title()}:", v)

            flags = res.get("flags", [])
            if flags:
                section_title("Forensic Flags")
                for f in flags:
                    colors = {"info": (0, 100, 200), "warning": (180, 100, 0), "critical": (200, 30, 30)}
                    color = colors.get(f["level"], (30, 30, 30))
                    row(f"[{f['name']}]", f["message"], color)
            else:
                section_title("Forensic Flags")
                pdf.set_font("Helvetica", "", 8)
                pdf.set_text_color(0, 150, 0)
                pdf.cell(0, 5, "  No anomalies detected.", ln=True)

            pdf.set_text_color(30, 30, 30)
            pdf.ln(5)

        pdf.output(str(output_path))
        return True

    except Exception as e:
        print(f"PDF generation error: {e}")
        return False
