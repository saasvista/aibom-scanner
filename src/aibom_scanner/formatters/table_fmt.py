"""Terminal table output with ANSI colors."""

from aibom_scanner.models import ScanResult

# ANSI color codes
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

SEVERITY_COLORS = {
    "critical": RED + BOLD,
    "high": RED,
    "medium": YELLOW,
    "low": GREEN,
}


INFERRED_PREAMBLE = (
    "These items reflect absence of evidence, not evidence of absence. "
    "They were not observed in the scanned source."
)


def _coverage_line(result: ScanResult, files_scanned: int) -> str:
    """One line describing what fraction of the repo's source was read."""
    cov = result.coverage
    if cov is None or cov.source_files_seen == 0:
        return f"  Scanned {BOLD}{files_scanned}{RESET} files"

    line = (
        f"  Scanned {BOLD}{cov.files_scanned}{RESET} of {BOLD}{cov.source_files_seen}{RESET} "
        f"source files ({cov.coverage_pct}%)"
    )
    if cov.skipped_by_path:
        line += f" — {cov.skipped_by_path} test/fixture files excluded"
        line += f", {cov.readable_coverage_pct}% of source attempted"
    return line


def _render_risks(lines: list[str], risks: list[dict]) -> None:
    """Append the per-risk detail block for a group of risks."""
    for risk in risks:
        sev = risk.get("severity", "medium")
        color = SEVERITY_COLORS.get(sev, "")
        title = risk.get("title", "")
        refs = ", ".join(risk.get("framework_refs", [])[:3])
        providers_list = risk.get("affected_providers", [])
        prov_str = ", ".join(providers_list[:5]) if providers_list else ""

        lines.append(f"  {color}[{sev.upper():8s}]{RESET} {title}")
        if prov_str:
            lines.append(f"             {DIM}Providers: {prov_str}{RESET}")
        if refs:
            lines.append(f"             {DIM}Frameworks: {refs}{RESET}")
        lines.append("")


def format_table(result: ScanResult) -> str:
    """Format scan result as a colored terminal table."""
    lines = []
    summary = result.summary

    # Header
    lines.append(f"\n{BOLD}AIBOM Scanner Results{RESET}")
    lines.append(f"{DIM}{'─' * 70}{RESET}")

    # Summary
    providers = summary.get("providers", {})
    total_det = summary.get("total_detections", 0)
    total_deps = summary.get("total_dependencies", 0)
    files_scanned = summary.get("files_scanned", 0)
    risk_counts = summary.get("risk_counts", {})

    lines.append(_coverage_line(result, files_scanned))
    lines.append(f"  Found {BOLD}{total_det}{RESET} AI SDK detections + {BOLD}{total_deps}{RESET} dependency detections")
    if providers:
        prov_str = ", ".join(f"{CYAN}{p}{RESET} ({c})" for p, c in sorted(providers.items(), key=lambda x: -x[1]))
        lines.append(f"  Providers: {prov_str}")

    # Unreadable languages and unread files — a partial scan must not read as a clean one
    cov = result.coverage
    if cov and (cov.unsupported_languages or cov.unread_source_files):
        lines.append("")
        lines.append(f"  {RED}{BOLD}INCOMPLETE COVERAGE{RESET}")
        if cov.unsupported_languages:
            detail = ", ".join(
                f"{cov.unscanned_by_extension.get(ext, 0)} {ext} files"
                for ext in cov.unsupported_languages
            )
            lines.append(f"  {RED}{detail} could not be read by this scanner version.{RESET}")
        if cov.unread_source_files:
            detail = ", ".join(f"{n} {ext} files" for ext, n in sorted(cov.unread_source_files.items()))
            lines.append(f"  {RED}{detail} were not read (too large or unreadable).{RESET}")
        lines.append(f"  {DIM}Findings below do not account for these files.{RESET}")

    # Risk summary
    crit = risk_counts.get("critical", 0)
    high = risk_counts.get("high", 0)
    med = risk_counts.get("medium", 0)
    low = risk_counts.get("low", 0)
    total_risks = crit + high + med + low

    if total_risks:
        lines.append(f"\n{BOLD}Risk Findings ({total_risks}){RESET}")
        lines.append(f"{DIM}{'─' * 70}{RESET}")

        if crit:
            lines.append(f"  {RED}{BOLD}CRITICAL: {crit}{RESET}")
        if high:
            lines.append(f"  {RED}HIGH: {high}{RESET}")
        if med:
            lines.append(f"  {YELLOW}MEDIUM: {med}{RESET}")
        if low:
            lines.append(f"  {GREEN}LOW: {low}{RESET}")

        observed = [r for r in result.risks if r.get("evidence_basis", "observed") != "inferred"]
        inferred = [r for r in result.risks if r.get("evidence_basis", "observed") == "inferred"]

        if observed:
            lines.append(f"\n{BOLD}Observed in code ({len(observed)}){RESET}")
            lines.append("")
            _render_risks(lines, observed)

        if inferred:
            lines.append(f"\n{BOLD}Governance checklist — not observed in code ({len(inferred)}){RESET}")
            lines.append(f"  {DIM}{INFERRED_PREAMBLE}{RESET}")
            lines.append("")
            _render_risks(lines, inferred)
    else:
        lines.append(f"\n  {GREEN}No risk findings.{RESET}\n")

    # Detection table
    if result.detections:
        lines.append(f"{BOLD}AI SDK Detections ({len(result.detections)}){RESET}")
        lines.append(f"{DIM}{'─' * 70}{RESET}")
        lines.append(f"  {DIM}{'Provider':<16} {'SDK':<16} {'Type':<12} {'File':>26}{RESET}")
        lines.append(f"  {DIM}{'─'*16} {'─'*16} {'─'*12} {'─'*26}{RESET}")
        for d in result.detections[:30]:
            provider = d.get("provider", "")
            sdk = d.get("sdk_name", "")
            dtype = d.get("detection_type", "")
            fpath = d.get("file_path", "")
            line = d.get("line_number", 0)
            loc = f"{fpath}:{line}" if line else fpath
            if len(loc) > 26:
                loc = "..." + loc[-23:]
            lines.append(f"  {CYAN}{provider:<16}{RESET} {sdk:<16} {dtype:<12} {loc:>26}")
        if len(result.detections) > 30:
            lines.append(f"  {DIM}... and {len(result.detections) - 30} more{RESET}")
        lines.append("")

    # MCP servers (names, hosts and key names only; values are never collected)
    if result.mcp_servers:
        lines.append(f"{BOLD}MCP Servers ({len(result.mcp_servers)}){RESET}")
        lines.append(f"{DIM}{'─' * 70}{RESET}")
        for s in result.mcp_servers[:15]:
            target = s.get("url_host") or s.get("command") or ""
            pin = {True: "pinned", False: "unpinned"}.get(s.get("pinned"), "")
            loc = f"{s.get('file', '')}:{s.get('line', 0)}"
            lines.append(f"  {CYAN}{(s.get('name') or '(unnamed)')[:20]:<20}{RESET} {s.get('transport', ''):<8} "
                         f"{target[:28]:<28} {pin:<8} {DIM}{loc}{RESET}")
        if len(result.mcp_servers) > 15:
            lines.append(f"  {DIM}... and {len(result.mcp_servers) - 15} more{RESET}")
        lines.append(f"  {DIM}{result.summary.get('mcp_servers_note', '')}{RESET}")
        lines.append("")

    # Tool capability classes (tools matched by import or MCP package; unclassified tools are not listed)
    if result.tool_capabilities:
        lines.append(f"{BOLD}Tool Capabilities ({len(result.tool_capabilities)} classified tools){RESET}")
        lines.append(f"{DIM}{'─' * 70}{RESET}")
        for cls in result.summary.get("capability_classes", []):
            tools = [t for t in result.tool_capabilities if cls in t["classes"]]
            names = ", ".join(t["tool"].rsplit(".", 1)[-1] for t in tools[:3])
            more = f" +{len(tools) - 3} more" if len(tools) > 3 else ""
            lines.append(f"  {CYAN}{cls:<22}{RESET} {len(tools):>3}  {DIM}{names}{more}{RESET}")
        lines.append("")

    # CTA
    lines.append(f"{DIM}{'─' * 70}{RESET}")
    lines.append(f"  {BOLD}Get remediation evidence and compliance reports:{RESET}")
    lines.append(f"  {CYAN}https://saasvista.io/scan{RESET}")
    lines.append("")

    return "\n".join(lines)
