"""Map findings to compliance framework controls (NIST AI RMF, ISO 42001, EU AI Act)."""

from aibom_scanner.models import ControlMapping, CoverageStatus


# --- Framework Definitions ---

NIST_AI_RMF = {
    "NIST-GOVERN-1.1": ("GOVERN 1.1", "AI governance policies and procedures are established"),
    "NIST-GOVERN-1.2": ("GOVERN 1.2", "AI system inventory and documentation maintained"),
    "NIST-GOVERN-1.3": ("GOVERN 1.3", "Risk management integrated into organizational governance"),
    "NIST-GOVERN-1.4": ("GOVERN 1.4", "Third-party AI provider compliance assessed"),
    "NIST-GOVERN-1.5": ("GOVERN 1.5", "Data governance policies for AI systems established"),
    "NIST-GOVERN-1.6": ("GOVERN 1.6", "Cross-border data transfer requirements addressed"),
    "NIST-GOVERN-2.1": ("GOVERN 2.1", "Roles and responsibilities for AI oversight defined"),
    "NIST-GOVERN-2.2": ("GOVERN 2.2", "Human oversight mechanisms established"),
    "NIST-MAP-1.1": ("MAP 1.1", "AI system purposes and intended uses documented"),
    "NIST-MAP-1.6": ("MAP 1.6", "Stakeholder engagement and transparency practices defined"),
    "NIST-MAP-2.3": ("MAP 2.3", "AI supply chain risks identified and managed"),
    "NIST-MAP-3.1": ("MAP 3.1", "Data processing agreements and privacy controls in place"),
    "NIST-MAP-3.2": ("MAP 3.2", "Data retention and provider training policies reviewed"),
    "NIST-MEASURE-2.1": ("MEASURE 2.1", "Model performance monitoring and metrics established"),
    "NIST-MEASURE-2.5": ("MEASURE 2.5", "AI system logging and audit trails implemented"),
    "NIST-MEASURE-2.6": ("MEASURE 2.6", "Output validation and safety measures active"),
    "NIST-MEASURE-2.7": ("MEASURE 2.7", "Bias testing and fairness evaluation procedures established"),
    "NIST-MANAGE-1.1": ("MANAGE 1.1", "AI risk assessment and prioritization framework established"),
    "NIST-MANAGE-2.1": ("MANAGE 2.1", "Model versioning and change management processes defined"),
    "NIST-MANAGE-3.1": ("MANAGE 3.1", "Continuous risk monitoring and model drift detection implemented"),
    "NIST-MANAGE-4.1": ("MANAGE 4.1", "Security controls for AI systems implemented"),
    "NIST-MANAGE-4.2": ("MANAGE 4.2", "Developer tool security and data transmission reviewed"),
    "NIST-MANAGE-4.3": ("MANAGE 4.3", "AI incident response plan established"),
}

ISO_42001 = {
    "ISO-42001-5.1": ("5.1 Leadership and commitment", "Top management demonstrates commitment to AI management system"),
    "ISO-42001-5.3": ("5.3 Organizational roles", "AI-related roles and responsibilities assigned"),
    "ISO-42001-A.6.1": ("A.6.1 AI system documentation", "AI system purposes, capabilities, and limitations documented"),
    "ISO-42001-A.6.2": ("A.6.2 AI system inventory", "Comprehensive inventory of AI systems maintained"),
    "ISO-42001-A.7.3": ("A.7.3 Compliance requirements", "Applicable compliance requirements identified and tracked"),
    "ISO-42001-A.7.4": ("A.7.4 Data management", "Data classification and management for AI systems established"),
    "ISO-42001-A.7.5": ("A.7.5 Privacy and data protection", "Privacy controls for AI data processing implemented"),
    "ISO-42001-A.8.2": ("A.8.2 Supply chain management", "AI supply chain risks assessed and managed"),
    "ISO-42001-A.8.3": ("A.8.3 Logging and monitoring", "AI system activities logged and monitored"),
    "ISO-42001-A.8.4": ("A.8.4 Change management", "Change management procedures for AI systems established"),
    "ISO-42001-A.8.5": ("A.8.5 Output controls", "AI output validation and safety controls implemented"),
    "ISO-42001-A.8.6": ("A.8.6 Security controls", "Security measures for AI systems implemented"),
    "ISO-42001-A.9.1": ("A.9.1 Human oversight", "Human oversight mechanisms for AI decisions established"),
    "ISO-42001-A.9.3": ("A.9.3 Incident management", "AI incident response procedures defined"),
    "ISO-42001-A.9.4": ("A.9.4 Bias and fairness", "Bias testing and fairness evaluation conducted"),
}

EU_AI_ACT = {
    "EU-AI-ACT-ART-5": ("Article 5", "Prohibited AI practices"),
    "EU-AI-ACT-ART-6": ("Article 6", "High-risk AI system classification assessment"),
    "EU-AI-ACT-ART-9": ("Article 9", "Risk management system for AI established"),
    "EU-AI-ACT-ART-10": ("Article 10", "Data governance measures for training and input data"),
    "EU-AI-ACT-ART-11": ("Article 11", "Technical documentation maintained"),
    "EU-AI-ACT-ART-12": ("Article 12", "Record-keeping and logging requirements"),
    "EU-AI-ACT-ART-13": ("Article 13", "Transparency and information provision to users"),
    "EU-AI-ACT-ART-14": ("Article 14", "Human oversight measures implemented"),
    "EU-AI-ACT-ART-15": ("Article 15", "Accuracy, robustness, and cybersecurity measures"),
    "EU-AI-ACT-ART-43": ("Article 43", "Conformity assessment procedures"),
    "EU-AI-ACT-ART-52": ("Article 52", "Transparency obligations for AI-generated content"),
}

ALL_FRAMEWORKS = {
    "NIST AI RMF": NIST_AI_RMF,
    "ISO 42001": ISO_42001,
    "EU AI Act": EU_AI_ACT,
}


def map_controls(risks: list[dict]) -> list[ControlMapping]:
    """Map risk findings to framework controls and determine coverage status."""
    control_finding_map: dict[str, list[dict]] = {}
    for risk in risks:
        for ref in risk.get("framework_refs", []):
            control_finding_map.setdefault(ref, []).append(risk)

    HEDGING_PHRASES = ["may apply", "potentially", "could apply", "needs assessment"]

    mappings: list[ControlMapping] = []
    for framework_name, controls in ALL_FRAMEWORKS.items():
        for control_id, (control_name, description) in controls.items():
            if control_id in control_finding_map:
                related_risks = control_finding_map[control_id]
                has_advisory = any(r.get("evidence_qualifier") for r in related_risks)
                has_hedging = any(
                    any(phrase in r.get("title", "").lower() for phrase in HEDGING_PHRASES)
                    for r in related_risks
                )
                has_mitigation = any(r.get("mitigation_status") for r in related_risks)

                if has_mitigation and not has_advisory and not has_hedging:
                    status = CoverageStatus.MAPPED
                else:
                    status = CoverageStatus.PARTIAL

                note_parts = []
                for r in related_risks:
                    sev = r.get("severity", "medium")
                    if hasattr(sev, "value"):
                        sev = sev.value
                    title = r.get("title", "")
                    if title:
                        note_parts.append(f"[{sev.upper()}] {title}")
                notes = "; ".join(note_parts)
            else:
                status = CoverageStatus.GAP
                notes = "No scan findings reference this control"

            mappings.append(ControlMapping(
                framework=framework_name,
                control_id=control_id,
                control_name=f"{control_name}: {description}",
                status=status,
                notes=notes,
            ))
    return mappings
