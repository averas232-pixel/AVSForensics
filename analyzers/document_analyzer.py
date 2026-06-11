"""
FileAutopsy — Document Analyzer
Handles PDF, DOCX, DOC, XLSX, XLS, PPTX.
Extracts author, dates, software, revision history, hidden metadata.
"""

import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))
from analyzers.base_analyzer import BaseAnalyzer
from config import EDITOR_SOFTWARE_KEYWORDS, SUSPICIOUS_SOFTWARE_KEYWORDS, HIGH_REVISION_THRESHOLD


class DocumentAnalyzer(BaseAnalyzer):

    def analyze(self) -> dict:
        base = super().analyze()
        ext = self.filepath.suffix.lower()

        if ext == ".pdf":
            doc_meta = self._analyze_pdf()
        elif ext in (".docx", ".doc"):
            doc_meta = self._analyze_docx()
        elif ext in (".xlsx", ".xls"):
            doc_meta = self._analyze_xlsx()
        elif ext in (".pptx", ".ppt"):
            doc_meta = self._analyze_pptx()
        else:
            doc_meta = {"error": "Unsupported document format"}

        base["document"] = doc_meta
        self._run_forensic_checks(doc_meta, base)
        base["flags"] = self.flags
        self.results = base
        return base

    # ─── PDF ──────────────────────────────────────────────────────────────────

    def _analyze_pdf(self) -> dict:
        try:
            import fitz  # pymupdf
            doc = fitz.open(str(self.filepath))
            meta = doc.metadata or {}

            created = self._parse_pdf_date(meta.get("creationDate"))
            modified = self._parse_pdf_date(meta.get("modDate"))

            result = {
                "format": "PDF",
                "author": meta.get("author") or None,
                "creator_app": meta.get("creator") or None,
                "producer": meta.get("producer") or None,
                "title": meta.get("title") or None,
                "subject": meta.get("subject") or None,
                "keywords": meta.get("keywords") or None,
                "pages": doc.page_count,
                "created": self._fmt(created),
                "modified": self._fmt(modified),
                "created_raw": created,
                "modified_raw": modified,
                "encrypted": doc.is_encrypted,
                "pdf_version": doc.pdf_version() if hasattr(doc, "pdf_version") else None,
            }

            # Try to get trapped / linearized flags
            try:
                xmp = doc.get_xml_metadata()
                result["has_xmp"] = bool(xmp and len(xmp) > 10)
            except Exception:
                result["has_xmp"] = None

            doc.close()

            self._check_future_date(created, "PDF creation date")
            self._check_future_date(modified, "PDF modification date")
            if created and modified and modified < created:
                self._add_flag("DATE_MISMATCH", "critical",
                    "Modification date is BEFORE creation date — strong indicator of tampering")

            return result
        except Exception as e:
            return {"format": "PDF", "error": str(e)}

    def _parse_pdf_date(self, date_str: Optional[str]) -> Optional[datetime]:
        if not date_str:
            return None
        # PDF date format: D:YYYYMMDDHHmmSSOHH'mm'
        date_str = date_str.strip().lstrip("D:").replace("'", "")
        for fmt in ["%Y%m%d%H%M%S%z", "%Y%m%d%H%M%S", "%Y%m%d%H%M", "%Y%m%d"]:
            try:
                dt = datetime.strptime(date_str[:len(fmt.replace('%z','').replace('%Y','0000').replace('%m','00').replace('%d','00').replace('%H','00').replace('%M','00').replace('%S','00'))], fmt)
                return dt.replace(tzinfo=None) if dt.tzinfo else dt
            except Exception:
                continue
        # Try manual strip
        try:
            clean = date_str[:14]
            return datetime.strptime(clean, "%Y%m%d%H%M%S")
        except Exception:
            return None

    # ─── DOCX ─────────────────────────────────────────────────────────────────

    def _analyze_docx(self) -> dict:
        try:
            from docx import Document
            from docx.opc.constants import RELATIONSHIP_TYPE as RT
            doc = Document(str(self.filepath))
            cp = doc.core_properties

            created = cp.created
            modified = cp.modified
            last_modified_by = cp.last_modified_by

            result = {
                "format": "DOCX",
                "author": cp.author or None,
                "last_modified_by": last_modified_by or None,
                "title": cp.title or None,
                "subject": cp.subject or None,
                "description": cp.description or None,
                "keywords": cp.keywords or None,
                "category": cp.category or None,
                "created": self._fmt(created),
                "modified": self._fmt(modified),
                "created_raw": created,
                "modified_raw": modified,
                "revision": cp.revision,
                "version": cp.version or None,
                "language": cp.language or None,
                "content_status": cp.content_status or None,
            }

            # Author vs last_modified_by mismatch
            if (cp.author and last_modified_by and
                    cp.author.strip().lower() != last_modified_by.strip().lower()):
                self._add_flag("AUTHOR_MISMATCH", "warning",
                    f"Original author '{cp.author}' ≠ last editor '{last_modified_by}'")

            if not cp.author:
                self._add_flag("EMPTY_AUTHOR", "info", "Author field is empty")

            if cp.revision and cp.revision > HIGH_REVISION_THRESHOLD:
                self._add_flag("REVISION_HIGH", "info",
                    f"Document has {cp.revision} revisions")

            if created and modified and modified < created:
                self._add_flag("DATE_MISMATCH", "critical",
                    "Modification date is BEFORE creation date — strong indicator of tampering")

            return result
        except Exception as e:
            return {"format": "DOCX", "error": str(e)}

    # ─── XLSX ─────────────────────────────────────────────────────────────────

    def _analyze_xlsx(self) -> dict:
        try:
            import openpyxl
            wb = openpyxl.load_workbook(str(self.filepath), read_only=True, data_only=True)
            cp = wb.properties

            created = cp.created
            modified = cp.modified

            result = {
                "format": "XLSX",
                "author": cp.creator or None,
                "last_modified_by": cp.lastModifiedBy or None,
                "title": cp.title or None,
                "subject": cp.subject or None,
                "description": cp.description or None,
                "keywords": cp.keywords or None,
                "category": cp.category or None,
                "created": self._fmt(created),
                "modified": self._fmt(modified),
                "created_raw": created,
                "modified_raw": modified,
                "sheets": wb.sheetnames,
                "sheet_count": len(wb.sheetnames),
            }

            wb.close()

            if (cp.creator and cp.lastModifiedBy and
                    cp.creator.strip().lower() != cp.lastModifiedBy.strip().lower()):
                self._add_flag("AUTHOR_MISMATCH", "warning",
                    f"Original author '{cp.creator}' ≠ last editor '{cp.lastModifiedBy}'")

            if not cp.creator:
                self._add_flag("EMPTY_AUTHOR", "info", "Creator field is empty")

            return result
        except Exception as e:
            return {"format": "XLSX", "error": str(e)}

    # ─── PPTX ─────────────────────────────────────────────────────────────────

    def _analyze_pptx(self) -> dict:
        try:
            from pptx import Presentation
            prs = Presentation(str(self.filepath))
            cp = prs.core_properties

            created = cp.created
            modified = cp.modified

            result = {
                "format": "PPTX",
                "author": cp.author or None,
                "last_modified_by": cp.last_modified_by or None,
                "title": cp.title or None,
                "subject": cp.subject or None,
                "created": self._fmt(created),
                "modified": self._fmt(modified),
                "created_raw": created,
                "modified_raw": modified,
                "revision": cp.revision,
                "slides": len(prs.slides),
            }

            if (cp.author and cp.last_modified_by and
                    cp.author.strip().lower() != cp.last_modified_by.strip().lower()):
                self._add_flag("AUTHOR_MISMATCH", "warning",
                    f"Original author '{cp.author}' ≠ last editor '{cp.last_modified_by}'")

            return result
        except Exception as e:
            return {"format": "PPTX", "error": str(e)}

    # ─── Common forensic checks ───────────────────────────────────────────────

    def _run_forensic_checks(self, doc_meta: dict, base: dict):
        creator = doc_meta.get("creator_app") or doc_meta.get("producer") or ""
        software = (creator or "").lower()

        for kw in SUSPICIOUS_SOFTWARE_KEYWORDS:
            if kw in software:
                self._add_flag("SUSPICIOUS_SOFTWARE", "warning",
                    f"Created/modified by known metadata tool: '{creator}'")

        for kw in EDITOR_SOFTWARE_KEYWORDS:
            if kw in software:
                self._add_flag("EDITOR_TRACE", "info",
                    f"Document produced by: '{creator}'")
                break

        created_raw = doc_meta.get("created_raw")
        self._check_future_date(created_raw, "Document creation date")

        modified_raw = doc_meta.get("modified_raw")
        sys_modified = base["system_dates"].get("modified_raw")
        if modified_raw and sys_modified:
            # Normalize timezone
            if hasattr(modified_raw, "tzinfo") and modified_raw.tzinfo:
                modified_raw = modified_raw.replace(tzinfo=None)
            self._check_date_mismatch(modified_raw, sys_modified,
                "Doc modified date vs filesystem modified", tolerance_days=2)
