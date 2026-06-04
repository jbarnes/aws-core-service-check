# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `--external-id` to pass an ExternalId when assuming the member-account role,
  for roles whose trust policy requires it.

## [1.0.0] - 2026-06-04

### Added
- Additional Control Tower / migration blocker checks:
  - leftover `aws-controltower-*` / `AWSControlTowerExecution` IAM roles
    (CRITICAL: cause "role already exists" failures on re-enrollment);
  - leftover `AWSControlTowerBP-*` CloudFormation baseline stacks (CRITICAL);
  - account-level CloudTrail trails that double-bill once Control Tower enables
    its own org trail (INFO);
  - presence of a default VPC, which Control Tower removes during baselining
    (INFO).
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
- Console report output is plain text (e.g. `[CRITICAL]`, `[HIGH]`, `[INFO]`
  severity tags) instead of emoji/status icons.
- The CloudTrail check now de-duplicates multi-region shadow trails by only
  reporting a trail in its home region.
- Pagination now uses boto3 paginators for accounts, SNS topics, and Backup
  vaults instead of partial manual paging.

### Fixed
- STS regional check now detects the correct `RegionDisabledException` instead
  of unreachable error codes, so disabled-region blockers are reported.
- Replaced bare `except:` clauses (which hid throttling and real failures, and
  swallowed `KeyboardInterrupt`) with targeted `ClientError` handling that only
  ignores access-denied and "not enabled" conditions.

[1.0.0]: https://github.com/jbarnes/aws-core-service-check/releases/tag/v1.0.0
