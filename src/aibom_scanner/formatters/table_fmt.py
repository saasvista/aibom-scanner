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

    lines.append(f"  Scanned {BOLD}{files_scanned}{RESET} files")
    lines.append(f"  Found {BOLD}{total_det}{RESET} AI SDK detections + {BOLD}{total_deps}{RESET} dependency detections")
    if providers:
        prov_str = ", ".join(f"{CYAN}{p}{RESET} ({c})" for p, c in sorted(providers.items(), key=lambda x: -x[1]))
        lines.append(f"  Providers: {prov_str}")

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

        lines.append("")
        for risk in result.risks:
            sev = risk.get("severity", "medium")
            color = SEVERITY_COLORS.get(sev, "")
            title = risk.get("title", "")
            cat = risk.get("category", "")
            refs = ", ".join(risk.get("framework_refs", [])[:3])
            providers_list = risk.get("affected_providers", [])
            prov_str = ", ".join(providers_list[:5]) if providers_list else ""

            lines.append(f"  {color}[{sev.upper():8s}]{RESET} {title}")
            if prov_str:
                lines.append(f"             {DIM}Providers: {prov_str}{RESET}")
            if refs:
                lines.append(f"             {DIM}Frameworks: {refs}{RESET}")
            lines.append("")
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

    # CTA
    lines.append(f"{DIM}{'─' * 70}{RESET}")
    lines.append(f"  {BOLD}Get remediation evidence and compliance reports:{RESET}")
    lines.append(f"  {CYAN}https://saasvista.io/scan{RESET}")
    lines.append("")

    return "\n".join(lines)
