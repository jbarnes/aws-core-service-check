# AWS Account Migration Pre-Check for Control Tower Enrollment

![Tests](https://github.com/jbarnes/aws-core-service-check/actions/workflows/test.yml/badge.svg)
![Pylint](https://github.com/jbarnes/aws-core-service-check/actions/workflows/pylint.yml/badge.svg)

Pre-migration validation script for AWS accounts being migrated from one organization to another organization with AWS Control Tower.

This tool is strictly **read-only**: it inspects your accounts and reports findings. It never creates, modifies, or deletes any AWS resource. Remediation steps are documented below for you to run deliberately.

## Use Case

You are migrating AWS member accounts from **Organization A** to **Organization B**, where Organization B uses AWS Control Tower. This script identifies services and configurations in the source accounts that will:
1. **Block Control Tower enrollment** in the new organization
2. **Break after migration** due to organization-tied resources
3. **Conflict with delegated administrators** in the new organization

## When to Use This Script

Run this script in **Organization A** (source organization) **before** migrating accounts to identify and remediate issues.

## Services Checked

Severity legend: **CRITICAL** blocks Control Tower enrollment and must be resolved first; **HIGH** breaks or is disrupted after migration; **INFO** is advisory (no action strictly required).

| Service | Scope | Severity | What's detected | Action required |
|---------|-------|----------|-----------------|-----------------|
| AWS Config | Regional | CRITICAL | Configuration recorders, delivery channels, and aggregation authorizations (Control Tower creates its own) | Delete recorders, delivery channels, and aggregation authorizations in all regions |
| STS (Security Token Service) | Regional | CRITICAL | STS disabled in a region | Enable STS in Account Settings for all regions |
| SNS Topics | Regional | CRITICAL | Topics conflicting with Control Tower names (`aws-controltower-SecurityNotifications`, `aws-controltower-AggregateSecurityNotifications`) | Rename or delete the conflicting topics |
| Leftover Control Tower IAM roles | Global | CRITICAL | Roles from a prior Control Tower (`AWSControlTowerExecution`, `aws-controltower-AdministratorExecutionRole`, `-ReadOnlyExecutionRole`, `-ConfigRecorderRole`, `-ForwardSnsNotificationRole`, `-CloudWatchLogsRole`) that cause "role already exists" failures | Delete these roles before re-enrolling |
| Leftover Control Tower CloudFormation stacks | Regional | CRITICAL | Baseline stacks named `AWSControlTowerBP-*` that cause resource-naming conflicts on re-enrollment | Delete the leftover stacks in every region they were deployed to |
| AWS Organizations | Global (mgmt) | CRITICAL | Organization structure, SCPs, and delegated administrators | Expected; documents what must be recreated in the destination org |
| AWS Control Tower | Global (mgmt) | CRITICAL | Whether the source org is already enrolled in Control Tower | Plan an alternate migration path if already enrolled |
| IAM Identity Center (SSO) | Global (mgmt) | CRITICAL | SSO instance present (cannot migrate between orgs) | Disable in the source org, reconfigure in the destination org |
| AWS Backup | Regional | HIGH | Backup vaults with organization-based access policies | Update vault policies to remove org references |
| AWS RAM (Resource Access Manager) | Global | HIGH | Resource shares shared with the organization | Re-share after migration or update principals |
| CloudTrail (org trails) | Regional | HIGH | Organization trails that stop logging when the account leaves the org | Create account-level trails or plan for a new org trail |
| Security Hub | Regional | HIGH | Delegated-admin membership to the source org's admin account | Disassociate before migration; re-associate in the destination org |
| GuardDuty | Regional | HIGH | Delegated-admin membership to the source org's admin account | Disassociate before migration; re-associate in the destination org |
| CloudTrail (account trails) | Regional | INFO | Account-level trails that bill in addition to the org trail Control Tower creates, causing duplicate charges | Consider deleting redundant trails after enrollment |
| EC2 Default VPC | Regional | INFO | Default VPC present (Control Tower removes it during baselining) | Be aware; a re-added default VPC can put the account in a Tainted state |

## Prerequisites

- Python 3.9 or higher
- Run from **Organization A's management account**
- AWS credentials with permissions to:
  - Assume `OrganizationAccountAccessRole` (or the role given via `--role-name`) in all member accounts
  - Read organization information (`organizations:*`)
  - Query all services listed above (read-only permissions)

## Installation

```bash
pip install -r requirements.txt
```

## Usage

Run from **Organization A's management account** with credentials that can assume roles in member accounts:

```bash
python3 check_services.py
```

Or, if installed as a package (`pip install .`):

```bash
aws-core-service-check
```

### Options

```
--role-name ROLE   IAM role to assume in member accounts
                   (default: OrganizationAccountAccessRole)
--output-dir DIR   Directory for the JSON results file (default: output/)
--stdout           Write JSON results to stdout instead of a file
--quiet            Suppress progress messages on stderr
```

### Using a custom cross-account role

By default the script assumes `OrganizationAccountAccessRole` in each member
account. Use `--role-name` to assume a different role instead:

```bash
python3 check_services.py --role-name MyReadOnlyScanRole
```

Notes:

- The role name must exist (with the same name) in **every** member account
  you want to scan, and its trust policy must allow the calling identity to
  assume it.
- The account you are **currently authenticated in** is scanned with your
  ambient credentials directly — the script does not assume a role into itself,
  so `--role-name` only applies to the other accounts.
- Accounts where the role cannot be assumed are reported as per-account errors;
  the scan continues with the remaining accounts.

Progress messages and the human-readable summary go to **stderr**, so stdout
stays clean for piping JSON:

```bash
python3 check_services.py --stdout --quiet | jq '.[].findings'
```

### Exit codes

The script returns a meaningful exit code so it can gate a migration pipeline:

| Code | Meaning |
|------|---------|
| `0`  | Completed; no CRITICAL blockers found |
| `2`  | Completed; one or more CRITICAL blockers found |
| `1`  | Fatal error (e.g. unable to read the organization) |

The script will:
1. Discover all accounts in Organization A
2. **Check management account FIRST** - Organizations, Control Tower, SSO status
3. Check each member account for:
   - AWS Config recorders (CRITICAL - blocks CT enrollment)
   - Organization-tied resources (AWS Backup, RAM, CloudTrail org trails)
   - Delegated admin memberships (Security Hub, GuardDuty)
4. Scan ALL enabled regions in each account
5. Generate prioritized report with **CRITICAL blockers at the top**
6. Output JSON file for detailed analysis

**Expected Runtime**: ~5-10 minutes per account (depending on number of enabled regions)

## Output

The script provides a two-tier output:

### Console Output
- Real-time progress as accounts are scanned
- **CRITICAL MANAGEMENT ACCOUNT BLOCKERS** section at the top
  - Shows issues that MUST be resolved before migration
  - Includes AWS Organizations, Control Tower, and SSO status
- Detailed findings by account with severity indicators:
  - CRITICAL issues
  - HIGH priority issues
  - Other informational findings

### JSON File Output
- File: `output/aws-service-check-results-<account>-<timestamp>.json` (timestamp is UTC; re-runs do not overwrite previous results)
- Use `--stdout` to emit the JSON to stdout instead of a file
- Complete structured data for all findings
- Includes criticality levels for automation/filtering
- Can be parsed by other tools or imported for analysis

## Example Output

```
AWS Core Services Check - Control Tower Migration Pre-Check
================================================================================

Retrieving all AWS accounts...
Found 5 accounts to check

================================================================================
Checking account: 123456789012 (Management Account)
================================================================================
  Found 16 enabled regions

  Checking CRITICAL management account-only services...
  (These services block migration and must be addressed first)

  Checking global services...

  Checking regional services across 16 regions...

================================================================================
SUMMARY REPORT
================================================================================

CRITICAL MANAGEMENT ACCOUNT BLOCKERS:
--------------------------------------------------------------------------------

  [CRITICAL] AWS Organizations
     Status: Enabled
     Org ID: o-abc123, Feature Set: ALL
     Action Required: Must be handled during migration

  [CRITICAL] IAM Identity Center (SSO)
     Status: Enabled
     Instance ARN: arn:aws:sso:::instance/ssoins-abc123
     Action Required: Must be disabled before migration

--------------------------------------------------------------------------------
These issues MUST be resolved before proceeding with migration!
--------------------------------------------------------------------------------

DETAILED FINDINGS BY ACCOUNT:
================================================================================

123456789012 (Management Account): 3 service(s) found
  [CRITICAL] AWS Organizations                   | global          | Enabled
    Org ID: o-abc123, Feature Set: ALL
    CRITICAL - Must be handled during migration

234567890123: 12 service(s) found
  [CRITICAL] AWS Config - Recorder               | us-east-1       | Recording
    Recorder: default
    CRITICAL - Must delete recorder before CT enrollment
  [CRITICAL] AWS Config - Delivery Channel       | us-east-1       | Exists
    Channel: default, S3: config-bucket-123
    CRITICAL - Must delete before CT enrollment
  [HIGH]     Security Hub - Delegated Admin      | us-east-1       | Member Account
    Admin Account: 123456789012
    HIGH - Must disassociate before migration
  [INFO]     CloudTrail - Account Trail          | us-east-1       | Account Trail Exists
    Trail: audit-trail - may double-bill once Control Tower enables its own org trail
    INFO - Consider deleting to avoid duplicate CloudTrail charges after enrollment

345678901234: No conflicting services found
```

## IAM Permissions Required

### Management Account Role
Needs these permissions to run the script:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "organizations:ListAccounts",
        "organizations:DescribeOrganization",
        "organizations:ListPolicies",
        "organizations:ListDelegatedAdministrators",
        "sts:AssumeRole",
        "ec2:DescribeRegions",
        "sso:ListInstances",
        "controltower:ListLandingZones",
        "ram:GetResourceShares",
        "ram:GetResourceShareAssociations"
      ],
      "Resource": "*"
    }
  ]
}
```

### Member Account Role (`OrganizationAccountAccessRole`, or your `--role-name`)
The assumed role in each member account needs read permissions for (these checks
also run against the management account):
- `config:Describe*`
- `cloudtrail:DescribeTrails`
- `sns:ListTopics`
- `securityhub:Describe*`, `securityhub:GetAdministratorAccount`
- `guardduty:List*`, `guardduty:GetAdministratorAccount`
- `backup:ListBackupVaults`, `backup:GetBackupVaultAccessPolicy`
- `iam:GetRole`
- `cloudformation:ListStacks`
- `ec2:DescribeRegions`, `ec2:DescribeVpcs`

## Next Steps After Running

### 1. Fix CRITICAL Blockers
These prevent Control Tower enrollment:

```bash
# Delete Config recorders and delivery channels in all regions
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  echo "Cleaning $region..."

  # Stop and delete recorder
  aws configservice stop-configuration-recorder --configuration-recorder-name default --region $region 2>/dev/null
  aws configservice delete-delivery-channel --delivery-channel-name default --region $region 2>/dev/null
  aws configservice delete-configuration-recorder --configuration-recorder-name default --region $region 2>/dev/null

  # Delete aggregation authorizations
  aws configservice describe-aggregation-authorizations --region $region --query 'AggregationAuthorizations[].{Account:AuthorizedAccountId,Region:AuthorizedAwsRegion}' --output text | while read account auth_region; do
    aws configservice delete-aggregation-authorization --authorized-account-id $account --authorized-aws-region $auth_region --region $region
  done
done

# Enable STS in all regions (via AWS Console -> Account Settings)
# Delete or rename conflicting SNS topics
```

### 2. Document Organization A Structure
- Export SCPs, OU structure, delegated administrators
- Document SSO configuration for recreation

### 3. Clean Up Delegated Admin Relationships
- Disassociate Security Hub member accounts
- Disassociate GuardDuty member accounts

### 4. Update Organization-Tied Resources
- Remove org references from Backup vault policies
- Update RAM share principals
- Plan for CloudTrail replacement

### 5. Migrate and Enroll
1. Remove accounts from Organization A
2. Invite/create accounts in Organization B
3. Enroll accounts in Control Tower
4. Re-establish delegated admin relationships in Organization B

## Development

Install development dependencies and run the checks:

```bash
make install   # runtime + dev dependencies (pytest, pylint)
make test      # pytest tests/ -v
make lint      # pylint check_services.py --fail-under=9.0
```

Tests use `pytest` with mocked AWS API calls, so no AWS credentials are required
to run them. See [CONTRIBUTING.md](CONTRIBUTING.md) for pull request and release
guidelines, and [CHANGELOG.md](CHANGELOG.md) for the version history.

## Feedback, improvements, issues

Please feel free to raise Pull Requests or Issues with identified problems or
feedback. Thank you.

---

## Development with Claude Code

This project is developed with assistance from [Claude Code](https://claude.ai/code),
Anthropic's agentic command-line tool. Claude Code is used throughout the
workflow: authoring and refactoring the CLI, hardening the AWS checks for
correctness, expanding the test suite, keeping the CI workflows consistent, and
reviewing changes for correctness and cleanups before they land.
