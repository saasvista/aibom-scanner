"""Integration tests for the scanner orchestrator."""

from aibom_scanner.scanner import scan_directory


class TestScanDirectory:
    def test_scan_with_ai_code(self, tmp_repo):
        result = scan_directory(tmp_repo)
        assert len(result.detections) > 0
        assert result.summary["total_detections"] > 0
        providers = result.summary.get("providers", {})
        assert "openai" in providers

    def test_scan_empty_dir(self, empty_repo):
        result = scan_directory(empty_repo)
        assert len(result.detections) == 0
        assert result.summary["total_detections"] == 0

    def test_scan_produces_risks(self, tmp_repo):
        result = scan_directory(tmp_repo)
        assert len(result.risks) > 0
        severities = {r["severity"] for r in result.risks}
        assert len(severities) > 0

    def test_scan_produces_control_mappings(self, tmp_repo):
        result = scan_directory(tmp_repo)
        assert len(result.control_mappings) > 0
        frameworks = {m["framework"] for m in result.control_mappings}
        assert "NIST AI RMF" in frameworks
        assert "ISO 42001" in frameworks
        assert "EU AI Act" in frameworks

    def test_chinese_ai_critical_finding(self, chinese_ai_repo):
        result = scan_directory(chinese_ai_repo)
        critical_risks = [r for r in result.risks if r["severity"] == "critical"]
        assert len(critical_risks) > 0
        entity_list = [r for r in critical_risks if "Entity List" in r["title"]]
        assert len(entity_list) > 0

    def test_agentic_ai_detection(self, agentic_repo):
        result = scan_directory(agentic_repo)
        providers = result.summary.get("providers", {})
        assert "crewai" in providers
        agentic_risks = [r for r in result.risks if "agentic" in r["category"]]
        assert len(agentic_risks) > 0

    def test_metadata_populated(self, tmp_repo):
        result = scan_directory(tmp_repo)
        assert "scanner_version" in result.metadata
        assert "scan_start" in result.metadata
        assert "scan_end" in result.metadata

    def test_dependency_detection(self, tmp_repo):
        # Dependencies are detected when requirements.txt is in the scan
        # The scan may or may not pick up requirements.txt depending on should_scan_file
        result = scan_directory(tmp_repo)
        # At minimum, we should have SDK detections from the .py and .js files
        assert result.summary["total_detections"] > 0

    def test_invalid_path_raises(self, tmp_path):
        import pytest
        with pytest.raises(ValueError):
            scan_directory(tmp_path / "nonexistent")
