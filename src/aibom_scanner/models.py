"""Data models for aibom-scanner output — stdlib only, zero dependencies."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CoverageStatus(str, Enum):
    MAPPED = "mapped"
    PARTIAL = "partial"
    GAP = "gap"


@dataclass
class ControlMapping:
    framework: str
    control_id: str
    control_name: str
    status: CoverageStatus
    notes: str = ""


@dataclass
class RiskFinding:
    category: str
    title: str
    severity: Severity
    description: str = ""
    remediation: str = ""
    evidence: list[str] = field(default_factory=list)
    framework_refs: list[str] = field(default_factory=list)
    affected_providers: list[str] = field(default_factory=list)
    evidence_qualifier: Optional[str] = None
    mitigation_status: Optional[str] = None
    evidence_basis: str = "observed"  # "observed" | "inferred" — inferred = no evidence, no providers


@dataclass
class CoverageReport:
    """How much of a repo's source the scanner could actually read.

    Two ratios, because either one alone misleads:
      - coverage_pct: files_scanned / source_files_seen. The honest headline.
      - readable_coverage_pct: files_scanned / (source we intended to read).
        Isolates scanner capability from deliberate test exclusion.
    """

    files_in_tree: int = 0
    source_files_seen: int = 0
    files_scanned: int = 0
    skipped_by_path: int = 0
    unscanned_by_extension: dict[str, int] = field(default_factory=dict)
    coverage_pct: float = 0.0
    readable_coverage_pct: float = 0.0
    unsupported_languages: list[str] = field(default_factory=list)
    # extension -> count of supported-language source files that were not read
    # (too large, unreadable, rejected). Also counted in unscanned_by_extension.
    unread_source_files: dict[str, int] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Top-level output from a scan."""

    detections: list[dict] = field(default_factory=list)
    dependencies: list[dict] = field(default_factory=list)
    dev_tools: list[dict] = field(default_factory=list)
    secrets: list[dict] = field(default_factory=list)
    mcp_servers: list[dict] = field(default_factory=list)
    tool_capabilities: list[dict] = field(default_factory=list)
    guardrails: list[dict] = field(default_factory=list)
    transparency: list[dict] = field(default_factory=list)
    hitl: list[dict] = field(default_factory=list)
    risks: list[dict] = field(default_factory=list)
    control_mappings: list[dict] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)
    coverage: Optional[CoverageReport] = None
