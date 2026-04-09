"""Tests for risk classification and consolidation."""

from aibom_scanner.models import Severity
from aibom_scanner.risk_engine import classify_risks, consolidate_risks, RISK_RULES


class TestClassifyRisks:
    def test_single_provider(self):
        risks = classify_risks(["openai"])
        assert len(risks) > 0
        categories = {r["category"] for r in risks}
        assert "data_privacy" in categories
        assert "model_governance" in categories

    def test_entity_listed_provider(self):
        risks = classify_risks(["zhipu"])
        critical = [r for r in risks if r["severity"] == Severity.CRITICAL]
        assert len(critical) > 0
        assert any("Entity List" in r["title"] for r in critical)

    def test_chinese_data_sovereignty(self):
        risks = classify_risks(["deepseek"])
        high = [r for r in risks if r["severity"] in (Severity.HIGH, Severity.CRITICAL)]
        assert any("data sovereignty" in r["title"].lower() for r in high)

    def test_multiple_providers_trigger_complexity(self):
        risks_one = classify_risks(["openai"])
        risks_two = classify_risks(["openai", "anthropic"])
        # Should have the "multiple providers" rule
        multi = [r for r in risks_two if "Multiple" in r["title"]]
        assert len(multi) > 0

    def test_agentic_provider_risks(self):
        risks = classify_risks(["crewai"])
        agentic = [r for r in risks if "agentic" in r["category"]]
        assert len(agentic) > 0

    def test_no_providers_fewer_risks(self):
        # With no providers, wildcard rules still fire but provider-specific ones don't
        risks_none = classify_risks([])
        risks_openai = classify_risks(["openai"])
        assert len(risks_none) < len(risks_openai)


class TestConsolidateRisks:
    def test_consolidation_reduces_count(self):
        raw = classify_risks(["openai", "anthropic"])
        consolidated = consolidate_risks(raw)
        assert len(consolidated) < len(raw)

    def test_anchor_absorbs_subordinates(self):
        raw = classify_risks(["openai"])
        consolidated = consolidate_risks(raw)
        titles = {r["title"] for r in consolidated}
        # "No model inventory" should be absorbed by "AI model usage without governance"
        assert "No model inventory or registry maintained" not in titles
        assert "AI model usage without governance framework" in titles

    def test_entity_list_not_absorbed(self):
        raw = classify_risks(["zhipu"])
        consolidated = consolidate_risks(raw)
        entity = [r for r in consolidated if "Entity List" in r["title"]]
        assert len(entity) > 0

    def test_framework_refs_merged(self):
        raw = classify_risks(["openai"])
        consolidated = consolidate_risks(raw)
        governance = [r for r in consolidated if r["title"] == "AI model usage without governance framework"]
        assert len(governance) == 1
        # Should have refs from absorbed rules too
        assert len(governance[0]["framework_refs"]) > 3
