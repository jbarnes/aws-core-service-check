"""AWS Core services check"""
import sys
import boto3
import botocore
from typing import List, Dict, Any
import json


def get_all_accounts() -> List[str]:
    """Get all AWS accounts including management account."""
    print("Retrieving all AWS accounts...")
    org_account_list = aws_org_accounts()
    management_account_id = aws_org_management_account_id()

    account_ids = [account["Id"] for account in org_account_list]

    # Ensure management account is included
    if management_account_id not in account_ids:
        account_ids.insert(0, management_account_id)

    print(f"Found {len(account_ids)} accounts to check")
    return account_ids


def aws_org_accounts():
    """Get a list of all AWS accounts associated with the AWS organisation."""
    client = boto3.client("organizations")

    raw_account_list = []

    try:
        response = client.list_accounts(MaxResults=20)
        raw_account_list.extend(response["Accounts"])
        while "NextToken" in response:
            response = client.list_accounts(
                MaxResults=20,
                NextToken=response["NextToken"],
            )
            raw_account_list.extend(response["Accounts"])
    except botocore.exceptions.ClientError as error:
        print("An error occurred when trying to get a list of AWS accounts")
        raise error

    return raw_account_list

def aws_org_management_account_id():
    """Get the management AWS account ID associated with the AWS organisation."""
    client = boto3.client("organizations")

    try:
        response = client.describe_organization()
        # Use ManagementAccountId (MasterAccountId is deprecated)
        management_account_id = response["Organization"].get("ManagementAccountId") or response["Organization"].get("MasterAccountId")
    except botocore.exceptions.ClientError as error:
        print("An error occurred when trying to get the management AWS account ID")
        raise error

    return management_account_id

def get_enabled_regions(session) -> List[str]:
    """Get a list of all enabled AWS regions for the account."""
    client = session.client("ec2", region_name="us-east-1")
    enabled_regions = []

    try:
        response = client.describe_regions(AllRegions=False)
        for region in response["Regions"]:
            enabled_regions.append(region["RegionName"])
    except botocore.exceptions.ClientError as error:
        print(f"An error occurred when trying to get enabled AWS regions: {error}")
        raise error

    return enabled_regions


def assume_role(account_id: str, role_name: str = "OrganizationAccountAccessRole"):
    """Assume a role with adequate permissions in target account."""
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    try:
        sts_client = boto3.client("sts")
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="CoreServiceCheck",
        )

        print(f"  ✓ Assumed role: {role_name}")
    except botocore.exceptions.ClientError as error:
        print(f"  ✗ Failed to assume role {role_name}: {error}")
        raise error

    sts_session = boto3.Session(
        aws_access_key_id=response["Credentials"]["AccessKeyId"],
        aws_secret_access_key=response["Credentials"]["SecretAccessKey"],
        aws_session_token=response["Credentials"]["SessionToken"],
    )

    return sts_session


def check_config(session: Any, region: str, results: List[Dict]) -> None:
    """Check if AWS Config recorders exist (blocks Control Tower enrollment)."""
    config_client = session.client("config", region_name=region)

    try:
        # Check for configuration recorders
        recorders = config_client.describe_configuration_recorders()

        if recorders.get("ConfigurationRecorders"):
            for recorder in recorders["ConfigurationRecorders"]:
                recorder_name = recorder.get("name", "N/A")

                # Check recorder status
                try:
                    status_response = config_client.describe_configuration_recorder_status(
                        ConfigurationRecorderNames=[recorder_name]
                    )
                    is_recording = False
                    if status_response.get("ConfigurationRecordersStatus"):
                        is_recording = status_response["ConfigurationRecordersStatus"][0].get("recording", False)
                except:
                    is_recording = False

                results.append({
                    "service": "AWS Config - Recorder",
                    "region": region,
                    "status": "Recording" if is_recording else "Exists (Not Recording)",
                    "details": f"Recorder: {recorder_name}",
                    "criticality": "CRITICAL - Must delete recorder before CT enrollment"
                })

        # Check for delivery channels
        channels = config_client.describe_delivery_channels()
        if channels.get("DeliveryChannels"):
            for channel in channels["DeliveryChannels"]:
                results.append({
                    "service": "AWS Config - Delivery Channel",
                    "region": region,
                    "status": "Exists",
                    "details": f"Channel: {channel.get('name', 'N/A')}, S3: {channel.get('s3BucketName', 'N/A')}",
                    "criticality": "CRITICAL - Must delete before CT enrollment"
                })

        # Check for aggregation authorizations (must be cleaned up for CT)
        try:
            aggregation_auths = config_client.describe_aggregation_authorizations()
            if aggregation_auths.get("AggregationAuthorizations"):
                for auth in aggregation_auths["AggregationAuthorizations"]:
                    results.append({
                        "service": "AWS Config - Aggregation Authorization",
                        "region": region,
                        "status": "Exists",
                        "details": f"Authorized Account: {auth.get('AuthorizedAccountId')}, Region: {auth.get('AuthorizedAwsRegion')}",
                        "criticality": "HIGH - May need to be recreated for CT audit account"
                    })
        except:
            pass

    except config_client.exceptions.NoSuchConfigurationRecorderException:
        pass  # Not enabled
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] not in ['AccessDeniedException']:
            print(f"    Error checking Config in {region}: {error}")
    except Exception as error:
        pass  # Skip unsupported regions


def check_cloudtrail_org_trails(session: Any, region: str, results: List[Dict]) -> None:
    """Check for organization CloudTrail trails (will break when account leaves org)."""
    cloudtrail_client = session.client("cloudtrail", region_name=region)

    try:
        cloudtrail_status = cloudtrail_client.describe_trails(includeShadowTrails=True)
        if cloudtrail_status["trailList"]:
            org_trails = [t for t in cloudtrail_status["trailList"] if t.get("IsOrganizationTrail")]

            if org_trails:
                for trail in org_trails:
                    results.append({
                        "service": "CloudTrail - Org Trail",
                        "region": region,
                        "status": "Org Trail Exists",
                        "details": f"Trail: {trail.get('Name')}, ARN: {trail.get('TrailARN')}",
                        "criticality": "HIGH - Org trail will stop working after migration"
                    })
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] not in ['AccessDeniedException']:
            print(f"    Error checking CloudTrail in {region}: {error}")


def check_sns_topic_conflicts(session: Any, region: str, results: List[Dict]) -> None:
    """Check for SNS topics that might conflict with Control Tower naming."""
    sns_client = session.client("sns", region_name=region)

    # Control Tower creates specific SNS topics - check if they already exist
    ct_topic_names = [
        "aws-controltower-SecurityNotifications",
        "aws-controltower-AggregateSecurityNotifications"
    ]

    try:
        topics = sns_client.list_topics()
        existing_topics = [t.get("TopicArn", "") for t in topics.get("Topics", [])]

        for topic_arn in existing_topics:
            topic_name = topic_arn.split(":")[-1]
            if any(ct_name in topic_name for ct_name in ct_topic_names):
                results.append({
                    "service": "SNS Topic",
                    "region": region,
                    "status": "Conflicting Name",
                    "details": f"Topic: {topic_name} - Conflicts with CT naming",
                    "criticality": "CRITICAL - Must rename or delete before CT enrollment"
                })
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] not in ['AccessDeniedException']:
            print(f"    Error checking SNS topics in {region}: {error}")


def check_sts_enabled(session: Any, region: str, results: List[Dict]) -> None:
    """Check if STS is enabled in the region (required for CT enrollment)."""
    sts_client = session.client("sts", region_name=region)

    try:
        # Try to get caller identity - if STS is disabled, this will fail
        sts_client.get_caller_identity()
    except botocore.exceptions.ClientError as error:
        error_code = error.response['Error']['Code']
        if 'InvalidClientTokenId' in error_code or 'SignatureDoesNotMatch' in error_code:
            results.append({
                "service": "STS (Security Token Service)",
                "region": region,
                "status": "Disabled",
                "details": "STS endpoints are disabled in this region",
                "criticality": "CRITICAL - Must enable STS in all regions for CT enrollment"
            })
        elif error_code not in ['AccessDeniedException']:
            print(f"    Error checking STS in {region}: {error}")
    except Exception:
        pass  # Skip if region not accessible


def check_securityhub_delegation(session: Any, region: str, results: List[Dict]) -> None:
    """Check if Security Hub has delegated admin (will conflict with new org)."""
    securityhub_client = session.client("securityhub", region_name=region)

    try:
        # Check if this account is a delegated admin
        securityhub_status = securityhub_client.describe_hub()
        if securityhub_status.get("HubArn"):
            # Check for delegated admin membership
            try:
                admin_account = securityhub_client.get_administrator_account()
                if admin_account.get("Administrator"):
                    results.append({
                        "service": "Security Hub - Delegated Admin",
                        "region": region,
                        "status": "Member Account",
                        "details": f"Admin Account: {admin_account['Administrator'].get('AccountId')}",
                        "criticality": "HIGH - Must disassociate before migration"
                    })
            except:
                pass
    except securityhub_client.exceptions.InvalidAccessException:
        pass  # Not enabled
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] not in ['AccessDeniedException']:
            print(f"    Error checking Security Hub delegation in {region}: {error}")


def check_guardduty_delegation(session: Any, region: str, results: List[Dict]) -> None:
    """Check if GuardDuty has delegated admin (will conflict with new org)."""
    guardduty_client = session.client("guardduty", region_name=region)

    try:
        detectors = guardduty_client.list_detectors()
        if detectors.get("DetectorIds"):
            for detector_id in detectors["DetectorIds"]:
                # Check if this is a member account
                try:
                    admin_account = guardduty_client.get_administrator_account(DetectorId=detector_id)
                    if admin_account.get("Administrator"):
                        results.append({
                            "service": "GuardDuty - Delegated Admin",
                            "region": region,
                            "status": "Member Account",
                            "details": f"Admin Account: {admin_account['Administrator'].get('AccountId')}, Detector: {detector_id}",
                            "criticality": "HIGH - Must disassociate before migration"
                        })
                except:
                    pass
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] not in ['AccessDeniedException']:
            print(f"    Error checking GuardDuty delegation in {region}: {error}")


def check_backup_org_resources(session: Any, region: str, results: List[Dict]) -> None:
    """Check for AWS Backup resources tied to the organization."""
    backup_client = session.client("backup", region_name=region)

    try:
        # Check for backup vaults that might have org policies
        vaults = backup_client.list_backup_vaults()
        for vault in vaults.get("BackupVaultList", []):
            vault_name = vault.get("BackupVaultName")
            # Skip default vault
            if vault_name == "Default":
                continue

            try:
                # Check vault access policy for organization references
                policy = backup_client.get_backup_vault_access_policy(BackupVaultName=vault_name)
                policy_str = policy.get("Policy", "")
                if "organizations" in policy_str.lower() or "arn:aws:organizations" in policy_str:
                    results.append({
                        "service": "AWS Backup",
                        "region": region,
                        "status": "Org-tied Vault Found",
                        "details": f"Vault: {vault_name} - Has org-based access policy",
                        "criticality": "HIGH - Vault policy references organization"
                    })
            except backup_client.exceptions.ResourceNotFoundException:
                pass
            except Exception:
                pass

    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] not in ['AccessDeniedException']:
            print(f"    Error checking Backup in {region}: {error}")


def check_control_tower(session: Any, results: List[Dict]) -> None:
    """Check if AWS Control Tower is already enabled."""
    ct_client = session.client("controltower", region_name="us-east-1")

    try:
        # Check for landing zone
        landing_zones = ct_client.list_landing_zones()
        if landing_zones.get("landingZones"):
            for lz in landing_zones["landingZones"]:
                results.append({
                    "service": "AWS Control Tower",
                    "region": "global",
                    "status": "Enabled",
                    "details": f"Landing Zone ARN: {lz.get('arn', 'N/A')}",
                    "criticality": "CRITICAL - Already enrolled, migration path different"
                })
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] not in ['AccessDeniedException', 'InvalidRequestException']:
            print(f"    Error checking Control Tower: {error}")


def check_ram_shares(session: Any, results: List[Dict]) -> None:
    """Check for AWS RAM resource shares tied to the organization."""
    ram_client = session.client("ram", region_name="us-east-1")

    try:
        # Check for resource shares owned by this account
        shares = ram_client.get_resource_shares(resourceOwner="SELF")

        for share in shares.get("resourceShares", []):
            # Check if shared with organization
            if share.get("status") == "ACTIVE":
                share_name = share.get("name", "N/A")
                share_arn = share.get("resourceShareArn", "")

                # Check principals (who it's shared with)
                try:
                    principals = ram_client.get_resource_share_associations(
                        associationType="PRINCIPAL",
                        resourceShareArns=[share_arn]
                    )

                    for assoc in principals.get("resourceShareAssociations", []):
                        principal = assoc.get("associatedEntity", "")
                        if "organizations" in principal.lower() or ":organization/" in principal:
                            results.append({
                                "service": "AWS RAM",
                                "region": "global",
                                "status": "Org Share Exists",
                                "details": f"Share: {share_name}, Principal: {principal}",
                                "criticality": "HIGH - RAM share with organization will break after migration"
                            })
                except:
                    pass

    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] not in ['AccessDeniedException']:
            print(f"    Error checking RAM: {error}")


def check_sso(session: Any, results: List[Dict]) -> None:
    """Check if IAM Identity Center (SSO) is enabled."""
    sso_admin_client = session.client("sso-admin", region_name="us-east-1")

    try:
        instances = sso_admin_client.list_instances()
        if instances.get("Instances"):
            for instance in instances["Instances"]:
                results.append({
                    "service": "IAM Identity Center (SSO)",
                    "region": "global",
                    "status": "Enabled",
                    "details": f"Instance ARN: {instance.get('InstanceArn', 'N/A')}",
                    "criticality": "CRITICAL - Must be disabled before migration"
                })
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] not in ['AccessDeniedException']:
            print(f"    Error checking IAM Identity Center: {error}")


def check_organizations(session: Any, results: List[Dict]) -> None:
    """Check AWS Organizations configuration (management account only)."""
    org_client = session.client("organizations", region_name="us-east-1")

    try:
        org_info = org_client.describe_organization()
        organization = org_info.get("Organization")

        if organization:
            results.append({
                "service": "AWS Organizations",
                "region": "global",
                "status": "Enabled",
                "details": f"Org ID: {organization.get('Id')}, Feature Set: {organization.get('FeatureSet')}",
                "criticality": "CRITICAL - Must be handled during migration"
            })

            # Check for SCPs
            try:
                policies = org_client.list_policies(Filter="SERVICE_CONTROL_POLICY")
                scp_count = len([p for p in policies.get("Policies", []) if p.get("Name") != "FullAWSAccess"])
                if scp_count > 0:
                    results.append({
                        "service": "AWS Organizations - SCPs",
                        "region": "global",
                        "status": "Active",
                        "details": f"Custom SCPs found: {scp_count}",
                        "criticality": "HIGH - Must be reviewed and recreated"
                    })
            except Exception:
                pass

            # Check for delegated administrators
            try:
                delegated_admins = org_client.list_delegated_administrators()
                if delegated_admins.get("DelegatedAdministrators"):
                    results.append({
                        "service": "AWS Organizations - Delegated Admins",
                        "region": "global",
                        "status": "Configured",
                        "details": f"Delegated admin accounts: {len(delegated_admins['DelegatedAdministrators'])}",
                        "criticality": "HIGH - Must be reconfigured after migration"
                    })
            except Exception:
                pass

    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] not in ['AccessDeniedException']:
            print(f"    Error checking Organizations: {error}")


def check_management_account_services(session: Any, results: List[Dict]) -> None:
    """Check services that only exist in the management account."""
    print(f"\n  Checking CRITICAL management account-only services...")
    print(f"  (These services block migration and must be addressed first)")

    check_organizations(session, results)
    check_control_tower(session, results)
    check_sso(session, results)


def check_global_services(session: Any, results: List[Dict]) -> None:
    """Check global services for org-tied resources."""
    print(f"\n  Checking global services...")

    check_ram_shares(session, results)


def check_regional_services(session: Any, regions: List[str], results: List[Dict]) -> None:
    """Check regional services that block Control Tower enrollment."""
    print(f"\n  Checking regional services across {len(regions)} regions...")

    for region in regions:
        check_sts_enabled(session, region, results)
        check_config(session, region, results)
        check_sns_topic_conflicts(session, region, results)
        check_cloudtrail_org_trails(session, region, results)
        check_securityhub_delegation(session, region, results)
        check_guardduty_delegation(session, region, results)
        check_backup_org_resources(session, region, results)


def check_account_services(account_id: str, session: Any, management_account_id: str) -> Dict[str, List[Dict]]:
    """Check all services for a single account across all enabled regions."""
    account_results = []

    is_mgmt_account = (account_id == management_account_id)
    account_label = f"{account_id} (Management Account)" if is_mgmt_account else account_id

    print(f"\n{'='*80}")
    print(f"Checking account: {account_label}")
    print(f"{'='*80}")

    # Get enabled regions
    regions = get_enabled_regions(session)
    print(f"  Found {len(regions)} enabled regions")

    # Management account gets additional critical checks
    if is_mgmt_account:
        check_management_account_services(session, account_results)

    # All accounts get global service checks
    check_global_services(session, account_results)

    # All accounts get regional service checks
    check_regional_services(session, regions, account_results)

    return {
        "account_id": account_id,
        "is_management_account": is_mgmt_account,
        "findings": account_results
    }


def main():
    """Primary function execution point."""
    print("AWS Core Services Check - Control Tower Migration Pre-Check")
    print("="*80)
    print("\nThis script checks for services that may conflict with AWS Organization migration")
    print("or Control Tower enrollment.\n")

    try:
        # Get all accounts
        all_accounts = get_all_accounts()
        management_account_id = aws_org_management_account_id()

        # Sort so management account is checked first
        sorted_accounts = sorted(all_accounts,
                                key=lambda x: (x != management_account_id, x))

        all_results = []
        management_account_critical_findings = []

        for account_id in sorted_accounts:
            try:
                # Get session for account
                if account_id == management_account_id:
                    session = boto3.Session()
                    print(f"\nUsing default credentials for management account")
                else:
                    session = assume_role(account_id)

                # Check services
                account_result = check_account_services(account_id, session, management_account_id)
                all_results.append(account_result)

                # Track critical management account findings
                if account_id == management_account_id:
                    management_account_critical_findings = [
                        f for f in account_result.get("findings", [])
                        if f.get("criticality", "").startswith("CRITICAL")
                    ]

            except Exception as error:
                print(f"\n✗ Failed to check account {account_id}: {error}")
                all_results.append({
                    "account_id": account_id,
                    "error": str(error),
                    "findings": []
                })

        # Output results
        print("\n\n" + "="*80)
        print("SUMMARY REPORT")
        print("="*80)

        # Show critical management account findings first
        if management_account_critical_findings:
            print("\n⚠️  CRITICAL MANAGEMENT ACCOUNT BLOCKERS:")
            print("-" * 80)
            for finding in management_account_critical_findings:
                criticality = finding.get("criticality", "")
                print(f"\n  ❌ {finding['service']}")
                print(f"     Status: {finding['status']}")
                print(f"     {finding['details']}")
                print(f"     Action Required: {criticality.split(' - ')[1] if ' - ' in criticality else criticality}")
            print("\n" + "-" * 80)
            print("⚠️  These issues MUST be resolved before proceeding with migration!")
            print("-" * 80)

        # Show all account findings
        print("\n\nDETAILED FINDINGS BY ACCOUNT:")
        print("="*80)

        for account_result in all_results:
            account_id = account_result["account_id"]
            is_mgmt = account_result.get("is_management_account", False)
            findings = account_result.get("findings", [])

            account_label = f"{account_id} (Management Account)" if is_mgmt else account_id

            if account_result.get("error"):
                print(f"\n❌ {account_label}: ERROR - {account_result['error']}")
            elif findings:
                print(f"\n📋 {account_label}: {len(findings)} service(s) found")
                # Group by criticality
                critical = [f for f in findings if f.get("criticality", "").startswith("CRITICAL")]
                high = [f for f in findings if f.get("criticality", "").startswith("HIGH")]
                other = [f for f in findings if not f.get("criticality", "").startswith(("CRITICAL", "HIGH"))]

                for finding in critical + high + other:
                    criticality_marker = ""
                    if finding.get("criticality", "").startswith("CRITICAL"):
                        criticality_marker = "🔴 "
                    elif finding.get("criticality", "").startswith("HIGH"):
                        criticality_marker = "🟡 "

                    print(f"  {criticality_marker}• {finding['service']:35} | {finding['region']:15} | {finding['status']:20}")
                    print(f"    {finding['details']}")
                    if finding.get("criticality"):
                        print(f"    ⚠️  {finding['criticality']}")
            else:
                print(f"\n✅ {account_label}: No conflicting services found")

        # Write JSON output
        output_file = "aws-service-check-results.json"
        with open(output_file, 'w') as f:
            json.dump(all_results, f, indent=2, default=str)

        print(f"\n\n{'='*80}")
        print(f"Detailed results written to: {output_file}")
        print("="*80)
        print("\n✅ Check complete!")

    except Exception as error:
        print(f"\n❌ Fatal error: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()