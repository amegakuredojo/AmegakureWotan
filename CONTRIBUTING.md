# Contributing to Karasugakure

We welcome contributions to Karasugakure. To ensure code quality, compliance, and OPSEC safety, please follow these guidelines.

## Development Guidelines

1. **Keep Paths Dynamic**: Never hardcode absolute paths (especially home directories like `/home/lugh/...`). Use relative paths resolved dynamically from `Path(__file__)`.
2. **Secrets Scanning**: All commits are checked for secrets. We use `gitleaks` to detect hardcoded credentials. Ensure your commit passes the pre-commit hook.
3. **Database Integrity**: All graph operations modifying multiple entities or relationships must be executed atomically using transaction managers with auto-rollback.
4. **Forensic Quality**: Avoid injecting simulated or fake data into the forensic ledger. All lookups (ASN, certificates, dark web crawl data) must query real adapters or fall back to empty collections and log warnings if unavailable.
5. **Testing**: Write comprehensive unit tests for new features under `tests/`. All tests must pass before opening a pull request.

## Secrets Scan Configuration
Ensure your local environment has `gitleaks` installed. Staged commits are scanned automatically using `opsec/pre-commit-hooks.sh`.
