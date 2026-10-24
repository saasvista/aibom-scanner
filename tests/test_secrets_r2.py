"""Run-2 audit: S1 unquoted/suffix credential names, S2 validation context, S3 secrets-management decoys, S4 cost."""

import time

from aibom_scanner.detectors.secrets import (
    detect_hardcoded_keys,
    detect_secrets_management,
    mask_secrets,
)

VAL = "Zq" + "7" * 6 + "Lm" + "4" * 6
OAI = "sk-" + "Ab1" * 10


class TestSuffixCredentialNames:
    def test_masked(self):
        for line in (
            f"export AZURE_OPENAI_KEY={VAL}",
            f"AZURE_OPENAI_KEY: {VAL}",
            f'AZURE_OPENAI_KEY="{VAL}"',
            f"QIANFAN_SK={VAL}",
            f'os.environ["AZURE_OPENAI_KEY"] = "{VAL}"',
            f'os.environ["X_API_KEY"] = "{VAL}"',
            f"os.environ['X_API_KEY'] = '{VAL}'",
        ):
            assert VAL not in mask_secrets(line), line

    def test_name_kept(self):
        assert "QIANFAN_SK" in mask_secrets(f"QIANFAN_SK={VAL}")

    def test_benign_unchanged(self):
        for line in (
            "file_path = some_long_path_value",
            "task_skip = 1234567890123",
            "task_skip: abcdefghijkl",
            "AZURE_OPENAI_KEY=$SOME_VARIABLE_NAME",
            'key = os.getenv("AZURE_OPENAI_KEY")',
            "AZURE_OPENAI_KEY: ${{ secrets.AZURE_KEY_X }}",
            "monkey = abcdefghijkl",
        ):
            assert mask_secrets(line) == line, line

    def test_long_name_run_is_fast(self):
        t = time.time()
        mask_secrets("a" * 200000)
        mask_secrets("a-" * 100000)
        assert time.time() - t < 2


class TestValidationContext:
    def test_key_in_search_call_detected(self):
        found = detect_hardcoded_keys("a.py", f'search(q, api_key="{OAI}")\n')
        assert len(found) == 1

    def test_prefix_named_variable_detected(self):
        found = detect_hardcoded_keys("a.py", f'key_prefix_cfg = "{OAI}"\n')
        assert len(found) == 1

    def test_startswith_still_suppressed(self):
        assert detect_hardcoded_keys("a.py", f'if key.startswith("{OAI}"):\n') == []
        assert detect_hardcoded_keys("a.py", f"re.match('{OAI}', k)\n") == []

    def test_other_line_context_does_not_suppress(self):
        text = f'x.startswith("a")\nk = "{OAI}"\n'
        assert len(detect_hardcoded_keys("a.py", text)) == 1

    def test_doc_and_placeholder_filters_kept(self):
        assert detect_hardcoded_keys("README.md", f'k = "{OAI}"\n') == []
        assert detect_hardcoded_keys("a.py", 'k = "sk-' + "YOUR" * 6 + '"\n') == []


class TestPerMatchCost:
    def test_one_megabyte_line(self):
        n = 1_000_000 // 40
        content = " ".join("sk-" + ("Ab1" * 10) + str(i % 10) for i in range(n))
        t = time.time()
        found = detect_hardcoded_keys("a.py", content)
        assert time.time() - t < 2
        assert len(found) >= n // 2


class TestSecretsManagementDecoys:
    def _methods(self, paths=(), contents=None):
        return {(d.method, d.evidence_type) for d in detect_secrets_management(list(paths), contents)}

    def test_path_decoys_ignored(self):
        assert ("sops", "file_path") not in self._methods(["docs/not.sops.yaml.md"])
        assert ("vault", "file_path") not in self._methods(["x/vault.hcl.bak", "my-vault.hcl"])
        assert ("1password", "file_path") not in self._methods(["foo.op/x.txt"])

    def test_real_paths_counted(self):
        assert ("sops", "file_path") in self._methods(["cfg/.sops.yaml"])
        assert ("1password", "file_path") in self._methods(["a/.op/config"])
        assert ("dotenv_config", "file_path") in self._methods([".env.example"])

    def test_comment_decoys_ignored(self):
        m = self._methods(contents={"a.py": "# move to secretsmanager\n// get_secret_value later\n"})
        assert ("aws_secrets_manager", "code_pattern") not in m

    def test_bare_word_ignored_call_counted(self):
        assert ("aws_secrets_manager", "code_pattern") not in self._methods(contents={"a.py": 'x = "secretsmanager"\n'})
        for src in ('c = boto3.client("secretsmanager")\n', "c = boto3.client( 'secretsmanager' )\n"):
            assert ("aws_secrets_manager", "code_pattern") in self._methods(contents={"a.py": src})
        assert ("aws_secrets_manager", "code_pattern") in self._methods(contents={"a.py": "c.get_secret_value(Id=1)\n"})

    def test_other_patterns_unaffected(self):
        assert ("env_vars", "code_pattern") in self._methods(contents={"a.py": 'os.getenv("K")\n'})
