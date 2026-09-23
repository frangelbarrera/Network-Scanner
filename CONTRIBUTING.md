# Contributing

Thanks for your interest in contributing to Network-Scanner.

## Reporting issues

Use GitHub Issues. Please include:
- Network-Scanner version (`network-scanner --version`)
- Python version
- Operating system
- Minimal reproduction steps

## Development setup

```bash
git clone https://github.com/frangelbarrera/Network-Scanner.git
cd Network-Scanner
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Pull requests
1.
Fork the repository
2.
Create a feature branch (git checkout -b feature/my-change)
3.
Make your change
4.
Add or update tests under tests/
5.
Run ruff check . and pytest tests/ — both must pass
6.
Push and open a pull request against main
Code style
Python: ruff (config in pyproject.toml)
TypeScript: ESLint with the project config
Commit messages: imperative mood, ≤ 72 char subject
Security issues
See SECURITY.md for private disclosure instructions. Do not open public issues for security reports.
