"""Audit F2: unquoted credential values must be masked in code snippets."""

import json

from aibom_scanner.detectors.secrets import mask_secrets
from aibom_scanner.scanner import scan_directory

HEX = "d0" * 16
ID_SECRET = "a1b2c3d4" + "." + "Zz9y8x7w6v5u"
JWT = ".".join(["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "dBjftJeZ4CVPmB92K27uhbUJU1p1r"])


def _snippets(tmp_path, files):
    for name, text in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    result = scan_directory(tmp_path)
    return json.dumps(json.loads(json.dumps(result.detections)))


class TestUnquotedCredentials:
    def test_unquoted_values_masked_in_scan_directory(self, tmp_path):
        out = _snippets(tmp_path, {
            "run.sh": f"export AZURE_OPENAI_API_KEY={HEX}\n"
                      f"export ZHIPU_API_KEY={ID_SECRET}\n"
                      f'curl https://api.minimax.chat/v1/text -H "Authorization: Bearer {JWT}"\n',
            "deploy/docker-compose.yml": f"services:\n  a:\n    environment:\n      - AZURE_OPENAI_API_KEY={HEX}\n",
            "config.yaml": f"AZURE_OPENAI_API_KEY: {HEX}\n",
        })
        assert "AZURE_OPENAI_API_KEY" in out
        for secret in (HEX, ID_SECRET, JWT):
            assert secret not in out

    def test_mask_each_shape(self):
        assert HEX not in mask_secrets(f"export AZURE_OPENAI_API_KEY={HEX}")
        assert HEX not in mask_secrets(f"- AZURE_OPENAI_API_KEY={HEX}")
        assert HEX not in mask_secrets(f"AZURE_OPENAI_API_KEY: {HEX}")
        assert ID_SECRET not in mask_secrets(f"ZHIPU_API_KEY={ID_SECRET}")
        assert JWT not in mask_secrets(f'-H "Authorization: Bearer {JWT}"')

    def test_references_and_plain_values_stay_intact(self):
        for line in (
            'key = os.environ["API_KEY"]',
            "api_key=key_from_vault",
            "export OPENAI_API_KEY=$OPENAI_API_KEY",
            "OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}",
            "api_key = os.getenv('OPENAI_API_KEY')",
            "OPENAI_API_KEY=changeme_please",
            "Authorization: Bearer token_placeholder",
        ):
            assert mask_secrets(line) == line, line
