#!/usr/bin/env python3
"""
EntrAudit PDF Report Generator
===============================
Converts a YAML results file (written by Write-EntrAuditPdfReport.ps1) into a
branded M365 / Entra ID security review PDF.

Forked from RootSec's Folio pentest-report engine
(Documents\\Github\\Folio\\pentest-report\\generate.py) — the Playwright
two-pass PDF generation (clean header-free cover merged with running-header/
footer body pages) is proven there and kept as-is; everything report-
structure-specific (sections/exec-summary/roadmap/appendices/syntax
highlighting) is trimmed since EntrAudit's flatter per-check finding model
doesn't need it. Cover and footer are redesigned to match the Swiss InfoSec
M365 Security Checklist reference (logo top-left on every page, solid red
footer band with page number) instead of Folio's centered-logo/blue-line style.

Usage:
    python generate_pdf.py data.yaml --output report.pdf
    python generate_pdf.py data.yaml --html          # HTML only, no Playwright needed
"""

import argparse
import base64
import os
import re
import sys
import tempfile
from datetime import datetime
from pathlib import Path

import jinja2
import markdown as md_lib
import yaml
from pypdf import PdfReader, PdfWriter

BASE_DIR = Path(__file__).parent
TEMPLATES_DIR = BASE_DIR
ASSETS_DIR = BASE_DIR / "templates" / "assets"
ICONS_DIR = BASE_DIR.parent / "Assets" / "ServiceIcons"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

# ─── SERVICE ICONS ───────────────────────────────────────────────────────────
# Real per-service brand SVGs (EntrAudit\Assets\ServiceIcons), one per CheckId
# prefix, so a reader can tell at a glance which M365 surface a finding belongs
# to — mirrors the Swiss InfoSec reference's per-finding service icon in the
# header row of the card.
SERVICE_ICON_FILES = {
    "ENTRA": "entra-id.svg",
    "OFFICE": "office-365.svg",
    "EXO": "microsoft-exchange.svg",
    "SHAREPOINT": "microsoft-sharepoint.svg",
    "TEAMS": "microsoft-teams.svg",
    "DEFENDER": "microsoft-defender.svg",
    "INTUNE": "microsoft-intune.svg",
    "FORMS": "microsoft-forms.svg",
    "POWERBI": "powerbi.svg",
    "COMPLIANCE": "compliance-center.svg",
}
DEFAULT_ICON = (
    '<svg viewBox="0 0 28 28" xmlns="http://www.w3.org/2000/svg">'
    '<rect width="28" height="28" rx="6" fill="#6b7280"/>'
    '<circle cx="14" cy="14" r="5.5" fill="none" stroke="#fff" stroke-width="1.8"/></svg>'
)

_icon_cache: dict = {}


def _namespace_svg_ids(svg: str, prefix: str) -> str:
    """Several of the vendored icons reuse tiny generic ids (id="a", id="b"...)
    for gradients/clip-paths. Multiple DIFFERENT service icons land inlined in
    the same HTML document, so colliding ids would make one icon's gradient
    bleed into another's. Prefix every id (and its url(#..)/href="#.." refs)
    with the service name to make them unique per icon type."""
    ids = sorted(set(re.findall(r'\bid="([^"]+)"', svg)), key=len, reverse=True)
    for old in ids:
        esc = re.escape(old)
        new = f"{prefix}-{old}"
        svg = re.sub(rf'id="{esc}"', f'id="{new}"', svg)
        svg = re.sub(rf'url\(#{esc}\)', f'url(#{new})', svg)
        svg = re.sub(rf'(xlink:href|href)="#{esc}"', rf'\1="#{new}"', svg)
    return svg


def _ensure_viewbox(svg: str) -> str:
    """Some vendored icons (e.g. powerbi.svg) carry only width/height, no
    viewBox. Stripping width/height from those would leave the SVG with no
    coordinate system to scale by, collapsing it to a blank/clipped corner
    inside our fixed-size icon box — so synthesize one from width/height
    first, before width/height get stripped below."""
    m = re.search(r'<svg\b([^>]*)>', svg)
    if not m or 'viewBox' in m.group(1):
        return svg
    w = re.search(r'\bwidth="([\d.]+)"', m.group(1))
    h = re.search(r'\bheight="([\d.]+)"', m.group(1))
    if w and h:
        svg = svg.replace('<svg', f'<svg viewBox="0 0 {w.group(1)} {h.group(1)}"', 1)
    return svg


def _load_service_icon(prefix: str) -> str:
    if prefix in _icon_cache:
        return _icon_cache[prefix]
    filename = SERVICE_ICON_FILES.get(prefix)
    svg = DEFAULT_ICON
    if filename:
        path = ICONS_DIR / filename
        if path.exists():
            raw = path.read_text(encoding="utf-8")
            raw = re.sub(r'<\?xml[^>]*\?>\s*', '', raw)
            raw = _ensure_viewbox(raw)
            raw = re.sub(r'(<svg\b[^>]*?)\swidth="[^"]*"', r'\1', raw, count=1)
            raw = re.sub(r'(<svg\b[^>]*?)\sheight="[^"]*"', r'\1', raw, count=1)
            svg = _namespace_svg_ids(raw, prefix.lower())
    _icon_cache[prefix] = svg
    return svg


def service_icon_for(check_id: str) -> str:
    prefix = str(check_id).split("-")[0].upper()
    return _load_service_icon(prefix)


# ─── UTILITIES ───────────────────────────────────────────────────────────────

def load_yaml(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def md_to_html(text) -> str:
    if not text:
        return ""
    return md_lib.markdown(str(text).strip(), extensions=["fenced_code", "sane_lists"])


def img_to_b64(path) -> str:
    p = Path(path)
    if not p.exists():
        return ""
    suffix = p.suffix.lower().lstrip(".")
    mime = {"jpg": "jpeg", "jpeg": "jpeg", "png": "png", "svg": "svg+xml"}.get(suffix, "png")
    encoded = base64.b64encode(p.read_bytes()).decode()
    return f"data:image/{mime};base64,{encoded}"


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-")


def format_date(d) -> str:
    if not d:
        return ""
    try:
        return datetime.strptime(str(d), "%Y-%m-%d").strftime("%B %d, %Y")
    except ValueError:
        return str(d)


# ─── REPORT PROCESSING ───────────────────────────────────────────────────────

def process_finding(finding: dict) -> dict:
    f = dict(finding)
    sev_key = str(f.get("severity", "Informational")).lower()

    f["severity_key"] = sev_key
    f["sort_key"] = SEVERITY_ORDER.get(sev_key, 5)
    f["rationale_html"] = md_to_html(f.get("rationale", ""))
    f["recommendation_html"] = md_to_html(f.get("recommendation", ""))
    f["icon_svg"] = service_icon_for(f.get("id", ""))
    return f


def process_report(data: dict, logo_path: Path) -> dict:
    report = dict(data)
    meta = report.setdefault("meta", {})
    meta["report_date_fmt"] = format_date(meta.get("report_date"))
    report["_company_logo"] = img_to_b64(logo_path)

    sections_in = report.get("sections", [])
    sections_out = []
    category_names = []
    by_category = []
    total = 0

    for sec in sections_in:
        findings = [process_finding(f) for f in sec.get("findings", [])]
        findings.sort(key=lambda f: f["sort_key"])
        counts = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        for f in findings:
            sk = f["severity_key"]
            if sk in counts:
                counts[sk] += 1
        sections_out.append({
            "title": sec.get("title", "Untitled"),
            "slug": slug(sec.get("title", "section")),
            "findings": findings,
        })
        category_names.append(sec.get("title", "Untitled"))
        by_category.append({"category": sec.get("title", "Untitled"), **counts})
        total += counts["total"]

    report["sections"] = sections_out
    report["category_names"] = category_names
    report["not_connected"] = report.get("not_connected") or []
    report["summary"] = {"total_checks": total, "by_category": by_category}
    return report


# ─── JINJA2 RENDERING ────────────────────────────────────────────────────────

def build_jinja_env() -> jinja2.Environment:
    return jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(BASE_DIR)),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_html(report: dict) -> str:
    env = build_jinja_env()
    css = (ASSETS_DIR / "style.css").read_text(encoding="utf-8")
    template = env.get_template("templates/report.html.j2")
    return template.render(report=report, css_content=css)


def render_cover_html(report: dict) -> str:
    env = build_jinja_env()
    css = (ASSETS_DIR / "style.css").read_text(encoding="utf-8")
    tmpl = env.from_string(
        '<!DOCTYPE html><html><head><meta charset="UTF-8">'
        '<style>{{ css_content }}</style></head><body>'
        '{% include "templates/_cover.html.j2" %}'
        '</body></html>'
    )
    return tmpl.render(report=report, css_content=css)


# ─── PDF GENERATION ──────────────────────────────────────────────────────────

def html_to_pdf_playwright(html_path, output_path, header_html="<span></span>",
                            footer_html="<span></span>", show_header_footer=True,
                            top_margin="45px", bottom_margin="38px", page_map=None) -> None:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("Error: playwright not installed. Run: pip install playwright && playwright install chromium",
              file=sys.stderr)
        sys.exit(1)

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 794, "height": 1123})
        page.goto(Path(html_path).resolve().as_uri(), wait_until="networkidle")

        if page_map is not None:
            # Second pass: stamp TOC rows with the real, pypdf-verified page
            # numbers computed from the first pass's rendered PDF (see
            # _compute_page_map). Exact, unlike the breaker-counting guess
            # below — that guess is wrong as soon as any section spans more
            # than one physical page, which happens the moment a category has
            # enough findings to overflow a page.
            page.evaluate(
                """(pageMap) => {
                    document.querySelectorAll('.toc-row').forEach(row => {
                        const href = row.getAttribute('href') || '';
                        if (!href.startsWith('#')) return;
                        const pn = pageMap[href.slice(1)];
                        if (!pn) return;
                        let numEl = row.querySelector('.toc-page-num');
                        if (!numEl) {
                            numEl = document.createElement('span');
                            numEl.className = 'toc-page-num';
                            row.appendChild(numEl);
                        }
                        numEl.textContent = pn;
                    });
                }""",
                page_map,
            )
        else:
            # First pass (and the headerless cover pass, which has no TOC at
            # all): approximate breaker-counting, just to produce a real PDF
            # whose page geometry generate_pdf() can then read back accurately
            # via pypdf. Any numbers it stamps here are discarded by the caller.
            page.evaluate("""
            () => {
                const breakers = Array.from(document.querySelectorAll(
                    '.cover-page, .toc-page, .report-section'
                ));
                const pageMap = {};
                breakers.forEach((el, idx) => { if (el.id) pageMap[el.id] = idx + 1; });
                document.querySelectorAll('.toc-row').forEach(row => {
                    const href = row.getAttribute('href') || '';
                    if (!href.startsWith('#')) return;
                    const pn = pageMap[href.slice(1)];
                    if (!pn) return;
                    let numEl = row.querySelector('.toc-page-num');
                    if (!numEl) {
                        numEl = document.createElement('span');
                        numEl.className = 'toc-page-num';
                        row.appendChild(numEl);
                    }
                    numEl.textContent = pn;
                });
            }
            """)

        page.pdf(
            path=output_path,
            format="A4",
            print_background=True,
            display_header_footer=show_header_footer,
            header_template=header_html,
            footer_template=footer_html,
            margin={
                "top": top_margin if show_header_footer else "0px",
                "bottom": bottom_margin if show_header_footer else "0px",
                "left": "0px", "right": "0px",
            },
        )
        browser.close()


def build_header_html(logo_data_uri: str) -> str:
    """Running header — logo pinned top-LEFT on every body page (Swiss InfoSec
    layout), unlike Folio's top-right placement. The cover page (@page cover,
    margin:0) never renders this."""
    if not logo_data_uri:
        return "<span></span>"
    return (
        '<div style="width:100%;box-sizing:border-box;padding:8px 0 0 32px;'
        'display:flex;justify-content:flex-start;align-items:center;'
        '-webkit-print-color-adjust:exact;print-color-adjust:exact;">'
        f'<img src="{logo_data_uri}" style="height:42px;object-fit:contain;">'
        '</div>'
    )


def build_footer_html(client_name: str, report_date: str) -> str:
    """Solid red footer band with white page number — matches the Swiss
    InfoSec reference, replacing Folio's thin blue separator-line footer."""
    return (
        '<div style="width:100%;background:#e63946;'
        '-webkit-print-color-adjust:exact;print-color-adjust:exact;'
        'box-sizing:border-box;padding:16px 32px;'
        'display:flex;justify-content:space-between;align-items:center;'
        'font-family:Inter,\'Segoe UI\',sans-serif;font-size:11px;color:#ffffff;">'
        f'<span>{client_name}</span>'
        f'<span style="font-weight:700">Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>'
        '</div>'
    )


def _merge_cover_with_body(cover_pdf_path, body_pdf_path, output_path) -> None:
    body_reader = PdfReader(body_pdf_path)
    body_page_count = len(body_reader.pages)
    writer = PdfWriter()
    writer.append(cover_pdf_path, pages=(0, 1))
    if body_page_count > 1:
        writer.append(body_pdf_path, pages=(1, body_page_count))
    with open(output_path, "wb") as f:
        writer.write(f)


def _compute_page_map(pdf_path: str) -> dict:
    """Map each HTML element id to the 0-based page index it actually landed
    on in pdf_path, by reading the named destinations Chromium's print-to-PDF
    preserves for every same-document anchor link (`<a href="#id">`). Exact,
    unlike guessing page numbers from page-break CSS rules - that guess is
    wrong as soon as a section spans more than one physical page, which
    happens the moment a category has enough findings to overflow a page."""
    reader = PdfReader(pdf_path)
    page_key_to_index = {}
    for i, pg in enumerate(reader.pages):
        ref = getattr(pg, "indirect_reference", None)
        if ref is not None:
            page_key_to_index[(ref.idnum, ref.generation)] = i

    result = {}
    for name, dest in (reader.named_destinations or {}).items():
        page_ref = dest.get("/Page")
        if page_ref is None:
            continue
        key = (page_ref.idnum, page_ref.generation)
        idx = page_key_to_index.get(key)
        if idx is not None:
            result[str(name).lstrip("/")] = idx
    return result


def generate_pdf(html_content: str, output_path: str, report: dict) -> None:
    """Two-pass generation: cover rendered with zero header/footer so it's
    always clean, body pages get the running top-left logo + red footer,
    merged with pypdf (preserves cross-page link annotations).

    The body itself is rendered twice: once to learn its real page geometry
    (via _compute_page_map), then again with the TOC stamped with those
    verified page numbers instead of an approximation."""
    meta = report.get("meta", {})
    client_name = meta.get("client", "")
    report_date = meta.get("report_date_fmt") or meta.get("report_date", "")

    header_html = build_header_html(report.get("_company_logo", ""))
    footer_html = build_footer_html(client_name, report_date)

    body_html_path = str(BASE_DIR / "_tmp_report.html")
    cover_html_path = str(BASE_DIR / "_tmp_cover.html")
    body_pdf_path = output_path + ".body.tmp.pdf"
    cover_pdf_path = output_path + ".cover.tmp.pdf"

    Path(body_html_path).write_text(html_content, encoding="utf-8")
    Path(cover_html_path).write_text(render_cover_html(report), encoding="utf-8")

    try:
        html_to_pdf_playwright(body_html_path, body_pdf_path, header_html, footer_html,
                                show_header_footer=True, top_margin="104px", bottom_margin="72px")

        # Body page 0 is the body document's own embedded (header/footer-
        # cluttered) cover, discarded below in favor of the clean cover-only
        # render - so body page i lands on final page i+1.
        body_page_map = _compute_page_map(body_pdf_path)
        final_page_map = {k: v + 1 for k, v in body_page_map.items()}

        html_to_pdf_playwright(body_html_path, body_pdf_path, header_html, footer_html,
                                show_header_footer=True, top_margin="104px", bottom_margin="72px",
                                page_map=final_page_map)
        html_to_pdf_playwright(cover_html_path, cover_pdf_path, show_header_footer=False)
        _merge_cover_with_body(cover_pdf_path, body_pdf_path, output_path)
    finally:
        for p in [body_html_path, cover_html_path, body_pdf_path, cover_pdf_path]:
            Path(p).unlink(missing_ok=True)


# ─── MAIN ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="EntrAudit PDF Report Generator")
    parser.add_argument("yaml_file", help="Path to the results YAML file")
    parser.add_argument("--output", "-o", default=None, help="Output PDF/HTML path")
    parser.add_argument("--logo", default=None, help="Path to the logo image (default: rootsec-logo.png next to the YAML)")
    parser.add_argument("--html", action="store_true", help="Output HTML only (no Playwright needed)")
    args = parser.parse_args()

    yaml_path = Path(args.yaml_file)
    if not yaml_path.exists():
        print(f"Error: YAML file not found: {yaml_path}", file=sys.stderr)
        sys.exit(1)

    logo_path = Path(args.logo) if args.logo else (yaml_path.parent / "rootsec-logo.png")

    raw = load_yaml(yaml_path)
    report = process_report(raw, logo_path)
    html = render_html(report)

    if args.html:
        out = args.output or str(yaml_path.with_suffix(".html"))
        Path(out).write_text(html, encoding="utf-8")
        print(f"HTML written to: {out}")
        return

    out = args.output or str(yaml_path.with_suffix(".pdf"))
    generate_pdf(html, out, report)
    print(f"PDF written to: {out}")


if __name__ == "__main__":
    main()
