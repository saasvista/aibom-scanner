"""code_snippet must never carry a credential value into the serialized report."""

import json

from aibom_scanner.detectors.ai_sdk import scan_file
from aibom_scanner.detectors.secrets import mask_secrets
from aibom_scanner.formatters.json_fmt import format_json
from aibom_scanner.formatters.sarif_fmt import format_sarif
from aibom_scanner.formatters.table_fmt import format_table
from aibom_scanner.scanner import scan_directory

# Assembled at runtime so no key-shaped literal sits in this file.
KEY_SHAPED = "sk-" + "ant-" + "A" * 48
NO_SHAPE = "plainvalue" + "-xyz-" + "98765"


def _repo(tmp_path):
    (tmp_path / "app.py").write_text(
        "import anthropic\n"
        f'c2 = anthropic.messages.Client(api_key="{KEY_SHAPED}")\n'
        f'c3 = anthropic.messages.Client(api_key="{NO_SHAPE}")\n'
    )
    return tmp_path


class TestSnippets:
    def test_detection_kept_and_values_masked(self):
        src = f'import os\nc2 = anthropic.messages.Client(api_key="{KEY_SHAPED}", access_token="{NO_SHAPE}")\n'
        dets = [d for d in scan_file("app.py", src) if d.line_number == 2]
        assert dets and all(KEY_SHAPED not in d.code_snippet and NO_SHAPE not in d.code_snippet for d in dets)
        assert (dets[0].provider, dets[0].file_path, dets[0].line_number) == ("anthropic", "app.py", 2)
        assert 'api_key="<redacted>"' in dets[0].code_snippet

    def test_no_value_in_any_detection_or_other_format(self, tmp_path):
        result = scan_directory(_repo(tmp_path))
        assert any(d["provider"] == "anthropic" and d["line_number"] == 2 for d in result.detections)
        assert KEY_SHAPED not in json.dumps(result.detections) and NO_SHAPE not in json.dumps(result.detections)
        for output in (format_json(result), format_sarif(result), format_table(result)):
            assert KEY_SHAPED not in output and NO_SHAPE not in output

    def test_secrets_drop_raw_value_but_keep_redacted_value(self, tmp_path):
        result = scan_directory(_repo(tmp_path))
        hardcoded = [s for s in result.secrets if s["evidence_type"] == "hardcoded_key"]
        assert hardcoded and all("raw_value" not in s for s in result.secrets)
        assert all(s["redacted_value"] and s["redacted_value"] != KEY_SHAPED for s in hardcoded)
        assert all(len(s["redacted_value"]) == 9 for s in hardcoded)  # 4 + "..." + 2
        assert '"raw_value"' not in format_json(result)

    def test_env_lookups_are_left_intact(self):
        for line in ('c = anthropic.messages.Client(api_key=os.environ["ANTHROPIC_API_KEY"])',
                     "c = anthropic.messages.Client(api_key=os.getenv('ANTHROPIC_API_KEY'))",
                     "const k = process.env.ANTHROPIC_API_KEY"):
            assert mask_secrets(line) == line

    def test_masks_quoted_credential_names(self):
        assert mask_secrets('headers = {"Authorization": "Bearer abcdefgh1234"}') == \
            'headers = {"Authorization": "<redacted>"}'
        assert mask_secrets("password = 'short'") == "password = 'short'"
        assert mask_secrets('db_password="hunter2hunter2"') == 'db_password="<redacted>"'

    def test_evidence_qualifier_keywords_survive(self):
        line = 'resp = anthropic.messages.create(user_input, api_key="' + NO_SHAPE + '")'
        assert "user_input" in mask_secrets(line)


class TestMaskingGaps:
    # Assembled at runtime so no key-shaped literal sits in this file.
    UNDERSCORE_KEY = "sk-" + "ant-" + "A" * 20 + "_" + "B" * 20
    PROJ_KEY = "sk-" + "proj-" + "C" * 24 + "-" + "D" * 12
    FSTRING_VALUE = "plainvalue" + "-xyz-" + "55555"

    def test_underscore_key_is_masked_whole(self):
        out = mask_secrets(f'client = Client(credentials_blob("{self.UNDERSCORE_KEY}"))')
        assert out == 'client = Client(credentials_blob("<redacted>"))'

    def test_underscore_key_in_json_detection_snippet(self, tmp_path):
        (tmp_path / "app.py").write_text(f'import anthropic\nc = anthropic.messages.Client("{self.UNDERSCORE_KEY}")\n')
        result = scan_directory(tmp_path)
        text = json.dumps(result.detections)
        assert "B" * 20 not in text and "_" + "B" * 5 not in text
        assert any("<redacted>" in d["code_snippet"] for d in result.detections)

    def test_sk_proj_key_masked_including_backtick_string(self):
        assert self.PROJ_KEY not in mask_secrets(f"see {self.PROJ_KEY} here")
        out = mask_secrets(f"const c = new Client({{ apiKey: `{self.PROJ_KEY}` }})")
        assert "CCCC" not in out and "DDDD" not in out and "apiKey: `<redacted>`" in out

    def test_backtick_assignment_to_credential_name(self):
        out = mask_secrets(f"const apiKey = `{self.FSTRING_VALUE}`;")
        assert self.FSTRING_VALUE not in out and out == "const apiKey = `<redacted>`;"

    def test_f_string_prefix(self):
        for prefix in ("f", "rf", "b"):
            out = mask_secrets(f'client = C(api_key={prefix}"{self.FSTRING_VALUE}")')
            assert self.FSTRING_VALUE not in out and f'api_key={prefix}"<redacted>"' in out


class TestPositionalUrlHeaderMasking:
    # Assembled at runtime so no key-shaped literal sits in this file.
    TOKEN = "Zq" + "8" * 10 + "Wx" + "4" * 10
    HEX = "a1" * 20
    PASS = "pw" + "-" + "77" * 5

    def test_positional_token_is_masked(self):
        assert mask_secrets(f'c = anthropic.Anthropic("{self.TOKEN}")') == 'c = anthropic.Anthropic("<redacted>")'
        assert mask_secrets(f"c = Client('x', '{self.HEX}', timeout=3)") == "c = Client('x', '<redacted>', timeout=3)"

    def test_positional_non_tokens_are_kept(self):
        for line in ('m = ChatAnthropic("claude-3-5-sonnet-20241022")',
                     'k = os.getenv("ANTHROPIC_API_KEY_2024_PROD")',
                     'c = OpenAI(base_url="https://api.example.com/v1")',
                     'r = client.messages.create(user_input, "short")'):
            assert mask_secrets(line) == line

    def test_url_userinfo_and_query_are_masked(self):
        out = mask_secrets(f'c = Client(base_url="https://bot:{self.PASS}@api.example.com/v1?api_key={self.TOKEN}&x=1")')
        assert self.PASS not in out and self.TOKEN not in out
        assert "https://<redacted>@api.example.com/v1?api_key=<redacted>&x=1" in out

    def test_header_dict_values_are_masked(self):
        out = mask_secrets(f'c = OpenAI(default_headers={{"X-Custom": "{self.PASS}", "X-Org": "acme"}})')
        assert out == 'c = OpenAI(default_headers={"X-Custom": "<redacted>", "X-Org": "<redacted>"})'
        out = mask_secrets(f'"headers": {{"X-Relay": "{self.PASS}"}}')
        assert out == '"headers": {"X-Relay": "<redacted>"}'

    def test_no_value_in_json_detection(self, tmp_path):
        (tmp_path / "app.py").write_text(
            "import anthropic\n"
            f'c = anthropic.messages.Client("{self.TOKEN}", base_url="https://u:{self.PASS}@h.example")\n'
        )
        result = scan_directory(tmp_path)
        assert any(d["line_number"] == 2 and "<redacted>" in d["code_snippet"] for d in result.detections)
        output = format_json(result)
        assert self.TOKEN not in output and self.PASS not in output


class TestSkProjDetection:
    PROJ_KEY = "sk-" + "proj-" + "Ab3" * 10 + "_" + "Cd4" * 8

    def test_sk_proj_key_is_detected_once(self):
        from aibom_scanner.detectors.secrets import detect_hardcoded_keys
        dets = detect_hardcoded_keys("app.py", f'client = OpenAI(api_key="{self.PROJ_KEY}")\n')
        assert [d.method for d in dets] == ["hardcoded_openai_key"]
        assert dets[0].raw_value == self.PROJ_KEY and dets[0].redacted_value == "sk-p...d4"

    def test_sk_proj_key_kept_out_of_report(self, tmp_path):
        (tmp_path / "app.py").write_text(f'import openai\nclient = openai.OpenAI(api_key="{self.PROJ_KEY}")\n')
        result = scan_directory(tmp_path)
        assert any(s["method"] == "hardcoded_openai_key" for s in result.secrets)
        assert self.PROJ_KEY not in format_json(result)
