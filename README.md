# AWS Account Migration Pre-Check for Control Tower Enrollment

Pre-migration validation script for AWS accounts being migrated from one organization to another organization with AWS Control Tower.

## Use Case

You are migrating AWS member accounts from **Organization A** to **Organization B**, where Organization B uses AWS Control Tower. This script identifies services and configurations in the source accounts that will:
1. **Block Control Tower enrollment** in the new organization
2. **Break after migration** due to organization-tied resources
3. **Conflict with delegated administrators** in the new organization

## When to Use This Script

Run this script in **Organization A** (source organization) **before** migrating accounts to identify and remediate issues.

## Services Checked

### 🔴 CRITICAL - Blocks Control Tower Enrollment

These **MUST** be resolved before enrolling in Control Tower:

#### AWS Config (Regional)
- **Configuration Recorders** - Control Tower creates its own; existing recorders cause enrollment failure
- **Delivery Channels** - Must be deleted along with recorders
- **Aggregation Authorizations** - Existing authorizations may need cleanup
- **Action Required**: Delete all Config recorders, delivery channels, and aggregation authorizations in ALL regions

#### STS - Security Token Service (Regional)
- **STS Endpoint Status** - STS must be enabled in all regions
- **Action Required**: Enable STS in Account Settings for all regions

#### SNS Topics (Regional)
- **Naming Conflicts** - Topics with Control Tower naming patterns will block enrollment
  - `aws-controltower-SecurityNotifications`
  - `aws-controltower-AggregateSecurityNotifications`
- **Action Required**: Rename or delete conflicting SNS topics

### 🔴 CRITICAL - Management Account Only (Organization A)

These exist only in the management account of the source organization:

- **AWS Organizations**
  - Organization structure, SCPs, delegated administrators
  - **Note**: This is expected; documents what needs to be recreated in Organization B
- **AWS Control Tower**
  - Detects if already enrolled in CT in Organization A
- **IAM Identity Center (SSO)**
  - Cannot migrate SSO configuration between orgs
  - **Action Required**: Disable in Org A, reconfigure in Org B

### 🟡 HIGH - Organization-Tied Resources

These resources reference the organization and will break after migration:

#### AWS Backup (Regional)
- **Backup Vaults** with organization-based access policies
- **Action Required**: Update vault policies to remove org references

#### AWS RAM - Resource Access Manager (Global)
- **Resource Shares** shared with the organization
- **Action Required**: Re-share resources after migration or update principals

#### CloudTrail (Regional)
- **Organization Trails** - Will stop logging when account leaves org
- **Action Required**: Create account-level trails or plan for new org trail

### 🟡 HIGH - Delegated Administrator Membership

These services may have delegated admin relationships that will break:

#### Security Hub (Regional)
- **Delegated Admin Membership** - Member relationship to Org A admin account
- **Action Required**: Disassociate before migration; will re-associate in Org B

#### GuardDuty (Regional)
- **Delegated Admin Membership** - Member relationship to Org A admin account
- **Action Required**: Disassociate before migration; will re-associate in Org B

## Prerequisites

- Python 3.7+
- Run from **Organization A's management account**
- AWS credentials with permissions to:
  - Assume `OrganizationAccountAccessRole` in all member accounts
  - Read organization information (`organizations:*`)
  - Query all services listed above (read-only permissions)

## Installation

```bash
pip install -r requirements.txt
```

## Usage

Run from **Organization A's management account** with credentials that can assume roles in member accounts:

```bash
python src/check_services.py
```

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
  - 🔴 CRITICAL issues
  - 🟡 HIGH priority issues
  - Other informational findings

### JSON File Output
- File: `aws-service-check-results.json`
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

⚠️  CRITICAL MANAGEMENT ACCOUNT BLOCKERS:
--------------------------------------------------------------------------------

  ❌ AWS Organizations
     Status: Enabled
     Org ID: o-abc123, Feature Set: ALL
     Action Required: Must be handled during migration

  ❌ IAM Identity Center (SSO)
     Status: Enabled
     Instance ARN: arn:aws:sso:::instance/ssoins-abc123
     Action Required: Must be disabled before migration

--------------------------------------------------------------------------------
⚠️  These issues MUST be resolved before proceeding with migration!
--------------------------------------------------------------------------------

DETAILED FINDINGS BY ACCOUNT:
================================================================================

📋 123456789012 (Management Account): 3 service(s) found
  🔴 • AWS Organizations                      | global          | Enabled
    Org ID: o-abc123, Feature Set: ALL
    ⚠️  CRITICAL - Must be handled during migration

📋 234567890123: 12 service(s) found
  🔴 • AWS Config                             | us-east-1       | Recording
    Recorder: default
    ⚠️  CRITICAL - Must delete recorder and delivery channel before CT enrollment
  🔴 • AWS Config - Delivery Channel          | us-east-1       | Exists
    Channel: default, S3: config-bucket-123
    ⚠️  CRITICAL - Must delete before CT enrollment
  🟡 • Security Hub - Delegated Admin         | us-east-1       | Member Account
    Admin Account: 123456789012
    ⚠️  HIGH - Must disassociate before migration

✅ 345678901234: No conflicting services found
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

### Member Account Role (OrganizationAccountAccessRole)
Needs read permissions for:
- `config:Describe*`
- `cloudtrail:DescribeTrails`
- `securityhub:Describe*`, `securityhub:GetAdministratorAccount`
- `guardduty:List*`, `guardduty:GetAdministratorAccount`
- `backup:ListBackupVaults`, `backup:GetBackupVaultAccessPolicy`
- `ec2:DescribeRegions`

## Common Issues Found

Based on AWS Control Tower documentation, these are the most common enrollment blockers:

| Issue | Severity | Fix |
|-------|----------|-----|
| Config recorders exist | 🔴 CRITICAL | Delete using AWS CLI in all regions |
| Config delivery channels exist | 🔴 CRITICAL | Delete using AWS CLI in all regions |
| STS disabled in regions | 🔴 CRITICAL | Enable in Account Settings |
| SNS topic name conflicts | 🔴 CRITICAL | Rename or delete conflicting topics |
| Security Hub delegated admin | 🟡 HIGH | Disassociate from old org admin |
| GuardDuty delegated admin | 🟡 HIGH | Disassociate from old org admin |
| Organization CloudTrail trails | 🟡 HIGH | Create account-level trails |
| AWS Backup org policies | 🟡 HIGH | Update vault policies |
| RAM org shares | 🟡 HIGH | Update share principals |

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

# Enable STS in all regions (via AWS Console → Account Settings)
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
