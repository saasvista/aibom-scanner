# Contributing to aibom-scanner

Thanks for your interest in contributing.

## How to contribute

1. Fork the repo
2. Create a branch: `git checkout -b feat/your-feature`
3. Make your changes
4. Run tests: `PYTHONPATH=src pytest tests/ -v`
5. Submit a PR

## Adding detection patterns

Detection patterns live in `src/aibom_scanner/detectors/ai_sdk.py`. Each pattern is a tuple:

```python
(provider, sdk_name, regex_pattern, detection_type)
```

Where `detection_type` is one of: `import`, `api_call`, `config`, `dependency`.

## Adding risk rules

Risk rules live in `src/aibom_scanner/risk_engine.py` in the `RISK_RULES` list. Each rule needs:
- `category`, `title`, `severity`, `providers`, `remediation`, `framework_refs`

## Code style

- Python 3.10+
- Zero external dependencies (stdlib only)
- `ruff` for linting (line length 120)

## License

By contributing, you agree that your contributions will be licensed under Apache-2.0.
