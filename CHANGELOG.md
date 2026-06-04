# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-06-04

### Added
- Non-interactive CLI (`argparse`) with `--role-name`, `--output-dir`,
  `--stdout`, and `--quiet`.
- Process exit codes for automation: `0` when no CRITICAL blockers are found,
  `2` when CRITICAL blockers exist, and `1` on a fatal error.
- Timestamped, account-scoped JSON output filenames
  (`aws-service-check-results-<account>-<timestamp>.json`) so re-runs no longer
  overwrite previous results.
- Test suite using `pytest` with fully mocked AWS calls.
- GitHub Actions workflows for tests and pylint across Python 3.9-3.14.
- `pyproject.toml` packaging metadata with an `aws-core-service-check`
  console-script entry point and a `dev` extras group.
- `Makefile`, `requirements-dev.txt`, `CHANGELOG.md`, `CONTRIBUTING.md`,
  `LICENSE`, and `.gitignore`.

### Changed
- Moved `src/check_services.py` to a top-level `check_services.py` module for
  packaging.
- Progress and report output now go to stderr, leaving stdout clean for piping
  JSON (`--stdout`).
- Pagination now uses boto3 paginators for accounts, SNS topics, and Backup
  vaults instead of partial manual paging.

### Fixed
- STS regional check now detects the correct `RegionDisabledException` instead
  of unreachable error codes, so disabled-region blockers are reported.
- Replaced bare `except:` clauses (which hid throttling and real failures, and
  swallowed `KeyboardInterrupt`) with targeted `ClientError` handling that only
  ignores access-denied and "not enabled" conditions.

[1.0.0]: https://github.com/jbarnes/aws-core-service-check/releases/tag/v1.0.0
