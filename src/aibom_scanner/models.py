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


@dataclass
class ScanResult:
    """Top-level output from a scan."""

    detections: list[dict] = field(default_factory=list)
    dependencies: list[dict] = field(default_factory=list)
    dev_tools: list[dict] = field(default_factory=list)
    secrets: list[dict] = field(default_factory=list)
    guardrails: list[dict] = field(default_factory=list)
    transparency: list[dict] = field(default_factory=list)
    hitl: list[dict] = field(default_factory=list)
    risks: list[dict] = field(default_factory=list)
    control_mappings: list[dict] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)
