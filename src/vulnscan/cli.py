"""Command-line interface for the vulnerability scanner."""

from __future__ import annotations

import argparse
import logging
import sys

from vulnscan import __version__
from vulnscan.models import ScanResult


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description="Web Application Vulnerability Scanner",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan a target URL for vulnerabilities")
    scan.add_argument("url", help="Target URL (e.g. http://localhost:8086)")
    scan.add_argument("-u", "--user", default="admin", help="Login username")
    scan.add_argument("-p", "--password", default="password", help="Login password")
    scan.add_argument("-o", "--output", default=".", help="Output directory for reports")
    scan.add_argument("--depth", type=int, default=1, help="Crawl depth (default: 1)")

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    # Configure logging
    log_level = logging.DEBUG if getattr(args, "verbose", False) else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(message)s",
    )

    if args.command == "scan":
        _run_scan(args)


def _run_scan(args: argparse.Namespace) -> None:
    from vulnscan.crawler import crawl_site
    from vulnscan.scanner import scan_site
    from vulnscan.reporter import generate_json, generate_html

    target = args.url.rstrip("/")
    print(f"[*] Target: {target}")
    print(f"[*] Crawl depth: {args.depth}")

    # Phase 1: Crawl
    print("\n[+] Crawling...")
    pages = crawl_site(target, args.user, args.password, args.depth)
    total_forms = sum(len(p.forms) for p in pages)
    print(f"[+] Crawled {len(pages)} pages, found {total_forms} forms")

    # Phase 2: Scan for SQL injection
    print("\n[+] Scanning for SQL injection...")
    vulns = scan_site(pages, target, args.user, args.password)

    # Phase 3: Scan for sensitive paths
    print("\n[+] Scanning for sensitive information leakage...")
    from vulnscan.sensitive import scan_sensitive_paths
    import httpx
    with httpx.Client(timeout=30, follow_redirects=True) as client:
        from vulnscan.crawler import login
        login(client, target, args.user, args.password)
        vulns.extend(scan_sensitive_paths(client, target))

    # Phase 4: Scan for reflected XSS
    print("\n[+] Scanning for reflected XSS...")
    from vulnscan.xss import scan_xss
    vulns.extend(scan_xss(pages, target, args.user, args.password))

    # Print results
    print(f"\n{'='*60}")
    print(f"  VULNERABILITIES FOUND: {len(vulns)}")
    print(f"{'='*60}")

    if vulns:
        by_type: dict[str, int] = {}
        for v in vulns:
            by_type[v.vuln_type.value] = by_type.get(v.vuln_type.value, 0) + 1
        for vtype, count in sorted(by_type.items()):
            print(f"  {vtype}: {count}")
        print()
        for v in vulns:
            print(f"  [{v.vuln_type.value}] {v.url}")
            print(f"    param={v.parameter}  payload={v.payload}")
            print(f"    {v.evidence[:120]}")
            print()
    else:
        print("  No vulnerabilities detected.")

    # Phase 3: Generate reports
    result = ScanResult(
        target=target,
        vulnerabilities=vulns,
        pages_crawled=len(pages),
        forms_found=total_forms,
    )

    json_path = generate_json(result, args.output)
    html_path = generate_html(result, args.output, __version__)
    print(f"\n[*] Reports saved:")
    print(f"    JSON: {json_path}")
    print(f"    HTML: {html_path}")

    if vulns:
        sys.exit(1)


if __name__ == "__main__":
    main()
