"""AWS Core services check"""
import sys
import boto3
import questionary as qst
import botocore
import time


def aws_accounts_prompt():
    """Prompt the executing user to select which AWS accounts to map."""
    init_accounts_list = ["all"]
    print("Retrieving a list of AWS accounts...")
    org_account_list = aws_org_accounts()

    for account in org_account_list:
        init_accounts_list.append(account["Id"])

    account_selection = qst.checkbox(
        "Which AWS accounts do you want to check (note: Management Account is not available)?",
        choices=init_accounts_list,
    ).ask()

    if "all" in account_selection:
        init_accounts_list.remove("all")
        return init_accounts_list

    if not account_selection:
        print("No accounts were selected, exiting.")
        sys.exit()

    return account_selection


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

def aws_org_master_account_id():
    """Get the master AWS account ID associated with the AWS organisation."""
    client = boto3.client("organizations")

    try:
        response = client.describe_organization()
        master_account_id = response["Organization"]["MasterAccountId"]
    except botocore.exceptions.ClientError as error:
        print("An error occurred when trying to get the master AWS account ID")
        raise error

    return master_account_id

# Use ec2 describe regions to get a list of enabled regions
def enabled_aws_regions(account, session):
    """Get a list of enabled AWS regions for a given AWS account."""
    client = session.client("ec2")

    enabled_regions = ["all"]

    try:
        response = client.describe_regions()
        for region in response["Regions"]:
            enabled_regions.append(region["RegionName"])
    except botocore.exceptions.ClientError as error:
        print(
            f"An error occurred when trying to get a list of enabled AWS regions for account: {account}"
        )
        raise error

    return enabled_regions


def aws_regions_prompt(account, session):
    """Prompts the executing user to select which AWS regions they wish to map."""
    regions = enabled_aws_regions(account, session)

    region_selection = qst.checkbox(
        "Which AWS regions do you want to check?", choices=regions
    ).ask()

    if "all" in region_selection:
        regions.remove("all")
        return regions

    return region_selection


def assume_role(account_id, role_name):
    """
    Assume a role with adequate permissions
    """

    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    try:
        sts_client = boto3.client("sts")
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="CoreServiceCheck",
        )

        print(
            f"Successfully assumed role: {role_name} for AWS account: {account_id}")
    except botocore.exceptions.ClientError as error:
        print(
            f"An error occurred when trying to assume role: {role_name} for this account")
        raise error

    sts_session = boto3.Session(
        aws_access_key_id=response["Credentials"]["AccessKeyId"],
        aws_secret_access_key=response["Credentials"]["SecretAccessKey"],
        aws_session_token=response["Credentials"]["SessionToken"],
    )

    return sts_session



def role_assertion_prompt():
    """Prompt executing user to provide the role to use for role assertion."""
    role_name = qst.text(
        "Please provide the AWS IAM role NAME az-mapper must use for role assertion:", default="OrganizationAccountAccessRole"
    ).ask()

    return role_name


def check_config(session, region):
    """Check if AWS Config is enabled."""

    # Create a Config service client
    config_client = session.client("config", region_name=region)

    try:
        # Get the Config status
        config_status = config_client.describe_configuration_recorder_status()

        # Check if Config is enabled in the region
        if config_status["ConfigurationRecordersStatus"]:
            if config_status["ConfigurationRecordersStatus"][0]["recording"]:
                print(f"AWS Config - {region}: Enabled")
    except botocore.exceptions.ClientError as error:
        print(f"An error occurred when trying to check AWS Config status in {region}")
        raise error
    except botocore.exceptions.UnrecognizedClientException as error:
        print(f"{error} in {region}, skipping...")
        pass


def check_guardduty(session, region):
    """Check if AWS GuardDuty is enabled."""
    guardduty_client = session.client("guardduty", region_name=region)
    try:
        guardduty_status = guardduty_client.list_detectors()
        if guardduty_status["DetectorIds"]:
            print(f"AWS GuardDuty - {region}: Enabled")
    except botocore.exceptions.ClientError as error:
        print("An error occurred when trying to check AWS GuardDuty status")
        raise error


def check_securityhub(session, region):
    """Check if AWS Security Hub is enabled."""
    securityhub_client = session.client("securityhub", region_name=region)

    try:
        securityhub_status = securityhub_client.describe_hub()
        if securityhub_status["HubArn"]:
            print(f"AWS Security Hub status")
            print(f"{region}: Enabled")
    except securityhub_client.exceptions.InvalidAccessException as error:
        pass
    except botocore.exceptions.ClientError as error:
        print(f"An error occurred when trying to check AWS Security Hub status in {region}")
        raise error

def check_cloudtrail(session, region):
    """Check if AWS CloudTrail is enabled."""
    cloudtrail_client = session.client("cloudtrail", region_name=region)

    try:
        cloudtrail_status = cloudtrail_client.describe_trails()
        if cloudtrail_status["trailList"]:
            print("AWS CloudTrail Status")
            print(f"{region}: Enabled")
            print(f"{region}: Total:{len(cloudtrail_status['trailList'])}")
            for trail in cloudtrail_status["trailList"]:
                multi_counter = 0
                if trail["IsMultiRegionTrail"]:
                    # Update multi_counter if trail is multi-region
                    multi_counter += 1
            print(f"{region}: Multi-Region:{multi_counter}")
    except botocore.exceptions.ClientError as error:
        print("An error occurred when trying to check AWS CloudTrail status")
        raise error

def check_savings_plans(session, region):
    """Check if AWS Savings Plans are enabled."""
    savings_plans_client = session.client("savingsplans", region_name=region)

    try:
        savings_plans_status = savings_plans_client.describe_savings_plans(states=["active"])
        if savings_plans_status["savingsPlans"]:
            print("AWS Savings Plans Status")
            print(f"{region}: Enabled")
    except botocore.exceptions.ClientError as error:
        print("An error occurred when trying to check AWS Savings Plans status")
        raise error


# Main function
def main():
    """Primary function execution point."""

    # Get basic mapping info from user
    accounts_map = aws_accounts_prompt()
    master_account_id = aws_org_master_account_id()
    role_to_assume = role_assertion_prompt()
    
    for account in accounts_map:
        if account == master_account_id:
            session = boto3.Session()
        else:
            session = assume_role(account, role_to_assume)
        region_map = aws_regions_prompt(account, session)
        print(f"{region_map} debug")
        print(f"Checking services for AWS account id: {account}...")
        for region in region_map:
            check_config(session, region)
            check_guardduty(session, region)
            check_securityhub(session, region)
            check_cloudtrail(session, region)
            check_savings_plans(session, region)

            time.sleep(1)
        print(f"Finished checking services for AWS account id: {account}.")
        qst.confirm("Continue?").ask()

    print("Finished checking services for all accounts.")


if __name__ == "__main__":
    main()