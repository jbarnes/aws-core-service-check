"""AWS core services pre-check for Control Tower / organization migration.

Scans the accounts of an AWS organization for services and configurations that
will block AWS Control Tower enrollment or break when an account is moved to a
different organization. Read-only: it never modifies any AWS resource.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import argparse
import json
import os
import sys

import boto3
import botocore

# Region used for global-service clients and the initial region discovery call.
GLOBAL_REGION = "us-east-1"

# SNS topic names that AWS Control Tower creates; pre-existing topics with these
# names block enrollment.
CT_SNS_TOPIC_NAMES = (
    "aws-controltower-SecurityNotifications",
    "aws-controltower-AggregateSecurityNotifications",
)


def log(message: str, *, quiet: bool = False) -> None:
    """Write a progress message to stderr so stdout stays machine-readable."""
    if not quiet:
        print(message, file=sys.stderr)


# --------------------------------------------------------------------------- #
# Account / region discovery
# --------------------------------------------------------------------------- #
def aws_org_accounts() -> List[Dict[str, Any]]:
    """Return all AWS accounts in the organization (paginated)."""
    client = boto3.client("organizations")
    accounts: List[Dict[str, Any]] = []
    try:
        paginator = client.get_paginator("list_accounts")
        for page in paginator.paginate():
            accounts.extend(page["Accounts"])
    except botocore.exceptions.ClientError as error:
        log(f"Error retrieving AWS accounts: {error}")
        raise
    return accounts


def aws_org_management_account_id() -> str:
    """Return the organization's management account ID."""
    client = boto3.client("organizations")
    try:
        response = client.describe_organization()
    except botocore.exceptions.ClientError as error:
        log(f"Error retrieving the management account ID: {error}")
        raise
    organization = response["Organization"]
    # MasterAccountId is the legacy name for ManagementAccountId.
    return organization.get("ManagementAccountId") or organization["MasterAccountId"]


def get_all_account_ids(management_account_id: str) -> List[str]:
    """Return all account IDs, guaranteeing the management account is included."""
    account_ids = [account["Id"] for account in aws_org_accounts()]
    if management_account_id not in account_ids:
        account_ids.insert(0, management_account_id)
    return account_ids


def get_enabled_regions(session: boto3.Session) -> List[str]:
    """Return the regions enabled for the account behind ``session``."""
    client = session.client("ec2", region_name=GLOBAL_REGION)
    try:
        response = client.describe_regions(AllRegions=False)
    except botocore.exceptions.ClientError as error:
        log(f"  Error retrieving enabled regions: {error}")
        raise
    return sorted(region["RegionName"] for region in response["Regions"])


def assume_role(account_id: str, role_name: str) -> boto3.Session:
    """Assume ``role_name`` in ``account_id`` and return a scoped session."""
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    sts_client = boto3.client("sts")
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="CoreServiceCheck",
        )
    except botocore.exceptions.ClientError as error:
        log(f"  Failed to assume role {role_name} in {account_id}: {error}")
        raise

    log(f"  Assumed role: {role_name}")
    credentials = response["Credentials"]
    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _is_access_denied(error: botocore.exceptions.ClientError) -> bool:
    """Return True for permission errors, which we treat as "not checkable"."""
    return error.response["Error"]["Code"] in (
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
    )


# --------------------------------------------------------------------------- #
# Regional checks
# --------------------------------------------------------------------------- #
def check_config(session: Any, region: str, results: List[Dict]) -> None:
    """Flag AWS Config recorders/channels that block Control Tower enrollment."""
    client = session.client("config", region_name=region)
    try:
        recorders = client.describe_configuration_recorders()
        for recorder in recorders.get("ConfigurationRecorders", []):
            recorder_name = recorder.get("name", "N/A")
            is_recording = False
            try:
                status = client.describe_configuration_recorder_status(
                    ConfigurationRecorderNames=[recorder_name]
                )
                statuses = status.get("ConfigurationRecordersStatus", [])
                is_recording = bool(statuses) and statuses[0].get("recording", False)
            except botocore.exceptions.ClientError as error:
                if not _is_access_denied(error):
                    log(f"    Error reading Config recorder status in {region}: {error}")
            results.append({
                "service": "AWS Config - Recorder",
                "region": region,
                "status": "Recording" if is_recording else "Exists (Not Recording)",
                "details": f"Recorder: {recorder_name}",
                "criticality": "CRITICAL - Must delete recorder before CT enrollment",
            })

        channels = client.describe_delivery_channels()
        for channel in channels.get("DeliveryChannels", []):
            results.append({
                "service": "AWS Config - Delivery Channel",
                "region": region,
                "status": "Exists",
                "details": f"Channel: {channel.get('name', 'N/A')}, "
                           f"S3: {channel.get('s3BucketName', 'N/A')}",
                "criticality": "CRITICAL - Must delete before CT enrollment",
            })

        auths = client.describe_aggregation_authorizations()
        for auth in auths.get("AggregationAuthorizations", []):
            results.append({
                "service": "AWS Config - Aggregation Authorization",
                "region": region,
                "status": "Exists",
                "details": f"Authorized Account: {auth.get('AuthorizedAccountId')}, "
                           f"Region: {auth.get('AuthorizedAwsRegion')}",
                "criticality": "HIGH - May need to be recreated for CT audit account",
            })
    except botocore.exceptions.ClientError as error:
        if not _is_access_denied(error):
            log(f"    Error checking Config in {region}: {error}")


def check_cloudtrail_org_trails(session: Any, region: str, results: List[Dict]) -> None:
    """Flag organization CloudTrail trails that stop logging after migration."""
    client = session.client("cloudtrail", region_name=region)
    try:
        response = client.describe_trails(includeShadowTrails=True)
        for trail in response.get("trailList", []):
            if trail.get("IsOrganizationTrail"):
                results.append({
                    "service": "CloudTrail - Org Trail",
                    "region": region,
                    "status": "Org Trail Exists",
                    "details": f"Trail: {trail.get('Name')}, ARN: {trail.get('TrailARN')}",
                    "criticality": "HIGH - Org trail will stop working after migration",
                })
    except botocore.exceptions.ClientError as error:
        if not _is_access_denied(error):
            log(f"    Error checking CloudTrail in {region}: {error}")


def check_sns_topic_conflicts(session: Any, region: str, results: List[Dict]) -> None:
    """Flag SNS topics whose names conflict with Control Tower's own topics."""
    client = session.client("sns", region_name=region)
    try:
        paginator = client.get_paginator("list_topics")
        for page in paginator.paginate():
            for topic in page.get("Topics", []):
                topic_name = topic.get("TopicArn", "").split(":")[-1]
                if any(name in topic_name for name in CT_SNS_TOPIC_NAMES):
                    results.append({
                        "service": "SNS Topic",
                        "region": region,
                        "status": "Conflicting Name",
                        "details": f"Topic: {topic_name} - Conflicts with CT naming",
                        "criticality": "CRITICAL - Must rename or delete before CT enrollment",
                    })
    except botocore.exceptions.ClientError as error:
        if not _is_access_denied(error):
            log(f"    Error checking SNS topics in {region}: {error}")


def check_sts_region_enabled(session: Any, region: str, results: List[Dict]) -> None:
    """Flag regions where STS is disabled (Control Tower needs it everywhere).

    A disabled STS region raises ``RegionDisabledException`` when a regional STS
    endpoint is called.
    """
    client = session.client("sts", region_name=region)
    try:
        client.get_caller_identity()
    except botocore.exceptions.ClientError as error:
        error_code = error.response["Error"]["Code"]
        if error_code == "RegionDisabledException":
            results.append({
                "service": "STS (Security Token Service)",
                "region": region,
                "status": "Disabled",
                "details": "STS endpoint is disabled in this region",
                "criticality": "CRITICAL - Must enable STS in all regions for CT enrollment",
            })
        elif not _is_access_denied(error):
            log(f"    Error checking STS in {region}: {error}")


def check_securityhub_delegation(session: Any, region: str, results: List[Dict]) -> None:
    """Flag Security Hub member relationships tied to the current org's admin."""
    client = session.client("securityhub", region_name=region)
    try:
        client.describe_hub()
    except botocore.exceptions.ClientError as error:
        # Hub not enabled in this region, or no access; nothing to report.
        if not _is_access_denied(error) and error.response["Error"]["Code"] not in (
            "InvalidAccessException",
            "ResourceNotFoundException",
        ):
            log(f"    Error checking Security Hub in {region}: {error}")
        return

    try:
        admin = client.get_administrator_account()
        administrator = admin.get("Administrator")
        if administrator:
            results.append({
                "service": "Security Hub - Delegated Admin",
                "region": region,
                "status": "Member Account",
                "details": f"Admin Account: {administrator.get('AccountId')}",
                "criticality": "HIGH - Must disassociate before migration",
            })
    except botocore.exceptions.ClientError as error:
        if not _is_access_denied(error):
            log(f"    Error checking Security Hub admin in {region}: {error}")


def check_guardduty_delegation(session: Any, region: str, results: List[Dict]) -> None:
    """Flag GuardDuty member relationships tied to the current org's admin."""
    client = session.client("guardduty", region_name=region)
    try:
        detectors = client.list_detectors()
    except botocore.exceptions.ClientError as error:
        if not _is_access_denied(error):
            log(f"    Error checking GuardDuty in {region}: {error}")
        return

    for detector_id in detectors.get("DetectorIds", []):
        try:
            admin = client.get_administrator_account(DetectorId=detector_id)
            administrator = admin.get("Administrator")
            if administrator:
                results.append({
                    "service": "GuardDuty - Delegated Admin",
                    "region": region,
                    "status": "Member Account",
                    "details": f"Admin Account: {administrator.get('AccountId')}, "
                               f"Detector: {detector_id}",
                    "criticality": "HIGH - Must disassociate before migration",
                })
        except botocore.exceptions.ClientError as error:
            if not _is_access_denied(error):
                log(f"    Error checking GuardDuty admin in {region}: {error}")


def check_backup_org_resources(session: Any, region: str, results: List[Dict]) -> None:
    """Flag AWS Backup vaults whose access policies reference the organization."""
    client = session.client("backup", region_name=region)
    try:
        paginator = client.get_paginator("list_backup_vaults")
        vaults = []
        for page in paginator.paginate():
            vaults.extend(page.get("BackupVaultList", []))
    except botocore.exceptions.ClientError as error:
        if not _is_access_denied(error):
            log(f"    Error checking Backup in {region}: {error}")
        return

    for vault in vaults:
        vault_name = vault.get("BackupVaultName")
        if vault_name == "Default":
            continue
        try:
            policy = client.get_backup_vault_access_policy(BackupVaultName=vault_name)
            policy_str = policy.get("Policy", "")
            if "organization" in policy_str.lower():
                results.append({
                    "service": "AWS Backup",
                    "region": region,
                    "status": "Org-tied Vault Found",
                    "details": f"Vault: {vault_name} - Has org-based access policy",
                    "criticality": "HIGH - Vault policy references organization",
                })
        except botocore.exceptions.ClientError as error:
            # No policy attached is normal; only surface unexpected errors.
            if not _is_access_denied(error) and error.response["Error"]["Code"] != (
                "ResourceNotFoundException"
            ):
                log(f"    Error reading Backup vault policy in {region}: {error}")


REGIONAL_CHECKS = (
    check_sts_region_enabled,
    check_config,
    check_sns_topic_conflicts,
    check_cloudtrail_org_trails,
    check_securityhub_delegation,
    check_guardduty_delegation,
    check_backup_org_resources,
)


# --------------------------------------------------------------------------- #
# Global / management-account checks
# --------------------------------------------------------------------------- #
def check_control_tower(session: Any, results: List[Dict]) -> None:
    """Flag an existing Control Tower landing zone in the source organization."""
    client = session.client("controltower", region_name=GLOBAL_REGION)
    try:
        landing_zones = client.list_landing_zones()
        for lz in landing_zones.get("landingZones", []):
            results.append({
                "service": "AWS Control Tower",
                "region": "global",
                "status": "Enabled",
                "details": f"Landing Zone ARN: {lz.get('arn', 'N/A')}",
                "criticality": "CRITICAL - Already enrolled, migration path different",
            })
    except botocore.exceptions.ClientError as error:
        if not _is_access_denied(error) and error.response["Error"]["Code"] != (
            "InvalidRequestException"
        ):
            log(f"    Error checking Control Tower: {error}")


def check_ram_shares(session: Any, results: List[Dict]) -> None:
    """Flag RAM resource shares whose principals reference the organization."""
    client = session.client("ram", region_name=GLOBAL_REGION)
    try:
        shares = client.get_resource_shares(resourceOwner="SELF")
    except botocore.exceptions.ClientError as error:
        if not _is_access_denied(error):
            log(f"    Error checking RAM: {error}")
        return

    for share in shares.get("resourceShares", []):
        if share.get("status") != "ACTIVE":
            continue
        share_name = share.get("name", "N/A")
        share_arn = share.get("resourceShareArn", "")
        try:
            associations = client.get_resource_share_associations(
                associationType="PRINCIPAL",
                resourceShareArns=[share_arn],
            )
            for assoc in associations.get("resourceShareAssociations", []):
                principal = assoc.get("associatedEntity", "")
                if "organization" in principal.lower():
                    results.append({
                        "service": "AWS RAM",
                        "region": "global",
                        "status": "Org Share Exists",
                        "details": f"Share: {share_name}, Principal: {principal}",
                        "criticality": "HIGH - RAM share with organization will break "
                                       "after migration",
                    })
        except botocore.exceptions.ClientError as error:
            if not _is_access_denied(error):
                log(f"    Error checking RAM associations for {share_name}: {error}")


def check_sso(session: Any, results: List[Dict]) -> None:
    """Flag IAM Identity Center, which cannot be migrated between organizations."""
    client = session.client("sso-admin", region_name=GLOBAL_REGION)
    try:
        instances = client.list_instances()
        for instance in instances.get("Instances", []):
            results.append({
                "service": "IAM Identity Center (SSO)",
                "region": "global",
                "status": "Enabled",
                "details": f"Instance ARN: {instance.get('InstanceArn', 'N/A')}",
                "criticality": "CRITICAL - Must be disabled before migration",
            })
    except botocore.exceptions.ClientError as error:
        if not _is_access_denied(error):
            log(f"    Error checking IAM Identity Center: {error}")


def check_organizations(session: Any, results: List[Dict]) -> None:
    """Document the source AWS Organizations configuration."""
    client = session.client("organizations", region_name=GLOBAL_REGION)
    try:
        org_info = client.describe_organization()
    except botocore.exceptions.ClientError as error:
        if not _is_access_denied(error):
            log(f"    Error checking Organizations: {error}")
        return

    organization = org_info.get("Organization")
    if not organization:
        return

    results.append({
        "service": "AWS Organizations",
        "region": "global",
        "status": "Enabled",
        "details": f"Org ID: {organization.get('Id')}, "
                   f"Feature Set: {organization.get('FeatureSet')}",
        "criticality": "CRITICAL - Must be handled during migration",
    })

    try:
        policies = client.list_policies(Filter="SERVICE_CONTROL_POLICY")
        custom_scps = [
            p for p in policies.get("Policies", []) if p.get("Name") != "FullAWSAccess"
        ]
        if custom_scps:
            results.append({
                "service": "AWS Organizations - SCPs",
                "region": "global",
                "status": "Active",
                "details": f"Custom SCPs found: {len(custom_scps)}",
                "criticality": "HIGH - Must be reviewed and recreated",
            })
    except botocore.exceptions.ClientError as error:
        if not _is_access_denied(error):
            log(f"    Error listing SCPs: {error}")

    try:
        delegated = client.list_delegated_administrators()
        admins = delegated.get("DelegatedAdministrators", [])
        if admins:
            results.append({
                "service": "AWS Organizations - Delegated Admins",
                "region": "global",
                "status": "Configured",
                "details": f"Delegated admin accounts: {len(admins)}",
                "criticality": "HIGH - Must be reconfigured after migration",
            })
    except botocore.exceptions.ClientError as error:
        if not _is_access_denied(error):
            log(f"    Error listing delegated administrators: {error}")


def check_management_account_services(session: Any, results: List[Dict], *, quiet: bool) -> None:
    """Run checks for services that only exist in the management account."""
    log("\n  Checking CRITICAL management account-only services...", quiet=quiet)
    check_organizations(session, results)
    check_control_tower(session, results)
    check_sso(session, results)


def check_global_services(session: Any, results: List[Dict], *, quiet: bool) -> None:
    """Run checks for global, org-tied resources."""
    log("\n  Checking global services...", quiet=quiet)
    check_ram_shares(session, results)


def check_regional_services(
    session: Any, regions: List[str], results: List[Dict], *, quiet: bool
) -> None:
    """Run all regional checks across ``regions``."""
    log(f"\n  Checking regional services across {len(regions)} region(s)...", quiet=quiet)
    for region in regions:
        for check in REGIONAL_CHECKS:
            check(session, region, results)


def check_account_services(
    account_id: str, session: Any, management_account_id: str, *, quiet: bool
) -> Dict[str, Any]:
    """Check all services for a single account across its enabled regions."""
    results: List[Dict] = []
    is_mgmt = account_id == management_account_id
    label = f"{account_id} (Management Account)" if is_mgmt else account_id

    log(f"\n{'=' * 80}", quiet=quiet)
    log(f"Checking account: {label}", quiet=quiet)
    log("=" * 80, quiet=quiet)

    regions = get_enabled_regions(session)
    log(f"  Found {len(regions)} enabled region(s)", quiet=quiet)

    if is_mgmt:
        check_management_account_services(session, results, quiet=quiet)
    check_global_services(session, results, quiet=quiet)
    check_regional_services(session, regions, results, quiet=quiet)

    return {
        "account_id": account_id,
        "is_management_account": is_mgmt,
        "findings": results,
    }


# --------------------------------------------------------------------------- #
# Reporting / output
# --------------------------------------------------------------------------- #
def _criticality_rank(finding: Dict) -> int:
    criticality = finding.get("criticality", "")
    if criticality.startswith("CRITICAL"):
        return 0
    if criticality.startswith("HIGH"):
        return 1
    return 2


def count_critical_findings(all_results: List[Dict]) -> int:
    """Return the total number of CRITICAL findings across all accounts."""
    return sum(
        1
        for account in all_results
        for finding in account.get("findings", [])
        if finding.get("criticality", "").startswith("CRITICAL")
    )


def print_report(all_results: List[Dict], *, stream) -> None:
    """Print the human-readable summary report to ``stream``."""
    print("\n" + "=" * 80, file=stream)
    print("SUMMARY REPORT", file=stream)
    print("=" * 80, file=stream)

    mgmt_critical = [
        finding
        for account in all_results
        if account.get("is_management_account")
        for finding in account.get("findings", [])
        if finding.get("criticality", "").startswith("CRITICAL")
    ]
    if mgmt_critical:
        print("\n⚠️  CRITICAL MANAGEMENT ACCOUNT BLOCKERS:", file=stream)
        print("-" * 80, file=stream)
        for finding in mgmt_critical:
            criticality = finding.get("criticality", "")
            action = criticality.split(" - ", 1)[1] if " - " in criticality else criticality
            print(f"\n  ❌ {finding['service']}", file=stream)
            print(f"     Status: {finding['status']}", file=stream)
            print(f"     {finding['details']}", file=stream)
            print(f"     Action Required: {action}", file=stream)
        print("\n" + "-" * 80, file=stream)
        print("⚠️  These issues MUST be resolved before proceeding with migration!", file=stream)
        print("-" * 80, file=stream)

    print("\n\nDETAILED FINDINGS BY ACCOUNT:", file=stream)
    print("=" * 80, file=stream)
    for account in all_results:
        account_id = account["account_id"]
        is_mgmt = account.get("is_management_account", False)
        label = f"{account_id} (Management Account)" if is_mgmt else account_id
        findings = account.get("findings", [])

        if account.get("error"):
            print(f"\n❌ {label}: ERROR - {account['error']}", file=stream)
        elif findings:
            print(f"\n📋 {label}: {len(findings)} service(s) found", file=stream)
            for finding in sorted(findings, key=_criticality_rank):
                criticality = finding.get("criticality", "")
                marker = "🔴 " if criticality.startswith("CRITICAL") else (
                    "🟡 " if criticality.startswith("HIGH") else ""
                )
                print(
                    f"  {marker}• {finding['service']:35} | "
                    f"{finding['region']:15} | {finding['status']:20}",
                    file=stream,
                )
                print(f"    {finding['details']}", file=stream)
                if criticality:
                    print(f"    ⚠️  {criticality}", file=stream)
        else:
            print(f"\n✅ {label}: No conflicting services found", file=stream)


def write_json_output(all_results: List[Dict], output_dir: str, account_id: str) -> str:
    """Write results as timestamped JSON and return the file path."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"aws-service-check-results-{account_id}-{timestamp}.json"
    path = os.path.join(output_dir, filename)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(all_results, handle, indent=2, default=str)
    return path


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Pre-check AWS organization accounts for Control Tower / "
                    "migration blockers (read-only).",
    )
    parser.add_argument(
        "--role-name",
        default="OrganizationAccountAccessRole",
        help="IAM role to assume in member accounts "
             "(default: OrganizationAccountAccessRole).",
    )
    parser.add_argument(
        "--output-dir",
        default="output",
        help="Directory for the JSON results file (default: output/).",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Write JSON results to stdout instead of a file.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress messages on stderr.",
    )
    return parser.parse_args(argv)


def run(args: argparse.Namespace) -> int:
    """Execute the scan and return a process exit code."""
    log("AWS Core Services Check - Control Tower Migration Pre-Check", quiet=args.quiet)
    log("=" * 80, quiet=args.quiet)
    log("\nRetrieving all AWS accounts...", quiet=args.quiet)

    management_account_id = aws_org_management_account_id()
    account_ids = get_all_account_ids(management_account_id)
    log(f"Found {len(account_ids)} account(s) to check", quiet=args.quiet)

    # Check the management account first.
    sorted_accounts = sorted(
        account_ids, key=lambda acct: (acct != management_account_id, acct)
    )

    all_results: List[Dict] = []
    for account_id in sorted_accounts:
        try:
            if account_id == management_account_id:
                log("\nUsing default credentials for management account", quiet=args.quiet)
                session = boto3.Session()
            else:
                session = assume_role(account_id, args.role_name)
            all_results.append(
                check_account_services(
                    account_id, session, management_account_id, quiet=args.quiet
                )
            )
        except Exception as error:  # pylint: disable=broad-except
            log(f"\nFailed to check account {account_id}: {error}", quiet=args.quiet)
            all_results.append(
                {"account_id": account_id, "error": str(error), "findings": []}
            )

    # Human-readable report always goes to stderr so stdout can carry JSON.
    print_report(all_results, stream=sys.stderr)

    if args.stdout:
        json.dump(all_results, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
    else:
        path = write_json_output(all_results, args.output_dir, management_account_id)
        log(f"\nDetailed results written to: {path}", quiet=args.quiet)

    critical_count = count_critical_findings(all_results)
    if critical_count:
        log(f"\n❌ {critical_count} CRITICAL blocker(s) found.", quiet=args.quiet)
        return 2
    log("\n✅ Check complete - no CRITICAL blockers found.", quiet=args.quiet)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point."""
    args = parse_args(argv)
    try:
        return run(args)
    except botocore.exceptions.ClientError as error:
        print(f"\nFatal error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
