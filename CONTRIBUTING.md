# Contributing to Scankeep

Contributions should be small, focused, and covered by tests.

## Development checks

From the repository root:

```bash
python -m pip install -r requirements.txt -r requirements-dev.txt
python -W error::ResourceWarning -m unittest discover -s tests -p "test_*.py"
python -m compileall -q scankeep tests
ruff check scankeep tests
ruff format --check scankeep tests
pip-audit --requirement requirements.txt
```

For deployment changes, also run:

```bash
cd deployment
./compose.sh config
./compose.sh build scankeep
```

Never commit deployment secrets, SQLite databases, scan logs, repository
tokens, SonarQube tokens, internal service URLs, or proprietary test fixtures.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
Use public issues for reproducible non-security defects and keep pull requests
limited to one clear change.

By contributing, you agree that your contribution is licensed under Apache
License 2.0.
