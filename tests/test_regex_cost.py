"""Audit F4: crafted long lines must not cause superlinear regex time."""

import time

from aibom_scanner.detectors.ai_sdk import scan_file
from aibom_scanner.detectors.secrets import mask_secrets

class TestRegexCost:
    def _fast(self, fn):
        t = time.perf_counter()
        fn()
        assert time.perf_counter() - t < 2

    def test_quote_run(self):
        self._fast(lambda: scan_file("a.py", "import openai\n" + '"' * 64000))

    def test_repeated_transformers_import(self):
        self._fast(lambda: scan_file("a.py", "from transformers import " * 2600))

    def test_repeated_secret_word(self):
        self._fast(lambda: mask_secrets("import openai " + "secret" * 11000))

    def test_long_line_is_truncated_but_still_detected(self):
        dets = scan_file("a.py", "import openai  " + "x" * 5000)
        assert dets and len(dets[0].code_snippet) <= 500

    def test_pipeline_and_model_still_detected(self):
        assert any(d.provider == "huggingface" for d in scan_file("a.py", "from transformers import AutoTokenizer, pipeline"))
        dets = scan_file("a.py", 'import openai\nclient.create(model="gpt-4o")')
        assert dets[0].model_name == "gpt-4o"
