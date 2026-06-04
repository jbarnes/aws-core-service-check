"""Unit tests for check_services. All AWS calls are mocked; no credentials needed."""
import io
import json
from unittest.mock import MagicMock

import botocore.exceptions
import pytest

import check_services


def make_client_error(code: str) -> botocore.exceptions.ClientError:
    """Build a botocore ClientError with the given error code."""
    return botocore.exceptions.ClientError(
        {"Error": {"Code": code, "Message": code}}, "OperationName"
    )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def test_is_access_denied_true_for_known_codes():
    for code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
        assert check_services._is_access_denied(make_client_error(code)) is True


def test_is_access_denied_false_for_other_codes():
    assert check_services._is_access_denied(make_client_error("ThrottlingException")) is False


def test_criticality_rank_orders_critical_first():
    critical = {"criticality": "CRITICAL - x"}
    high = {"criticality": "HIGH - y"}
    other = {"criticality": ""}
    ordered = sorted([other, high, critical], key=check_services._criticality_rank)
    assert ordered == [critical, high, other]


def test_count_critical_findings():
    results = [
        {"findings": [{"criticality": "CRITICAL - a"}, {"criticality": "HIGH - b"}]},
        {"findings": [{"criticality": "CRITICAL - c"}]},
        {"findings": []},
    ]
    assert check_services.count_critical_findings(results) == 2


# --------------------------------------------------------------------------- #
# STS regional check (the previously-broken one)
# --------------------------------------------------------------------------- #
def test_sts_region_disabled_is_flagged_critical():
    session = MagicMock()
    client = session.client.return_value
    client.get_caller_identity.side_effect = make_client_error("RegionDisabledException")
    results = []
    check_services.check_sts_region_enabled(session, "ap-east-1", results)
    assert len(results) == 1
    assert results[0]["service"].startswith("STS")
    assert results[0]["criticality"].startswith("CRITICAL")


def test_sts_region_enabled_produces_no_finding():
    session = MagicMock()
    session.client.return_value.get_caller_identity.return_value = {"Account": "123"}
    results = []
    check_services.check_sts_region_enabled(session, "us-east-1", results)
    assert results == []


def test_sts_access_denied_is_swallowed():
    session = MagicMock()
    session.client.return_value.get_caller_identity.side_effect = make_client_error(
        "AccessDenied"
    )
    results = []
    check_services.check_sts_region_enabled(session, "us-east-1", results)
    assert results == []


# --------------------------------------------------------------------------- #
# Config check
# --------------------------------------------------------------------------- #
def test_config_recorder_and_channel_flagged():
    session = MagicMock()
    client = session.client.return_value
    client.describe_configuration_recorders.return_value = {
        "ConfigurationRecorders": [{"name": "default"}]
    }
    client.describe_configuration_recorder_status.return_value = {
        "ConfigurationRecordersStatus": [{"recording": True}]
    }
    client.describe_delivery_channels.return_value = {
        "DeliveryChannels": [{"name": "default", "s3BucketName": "bkt"}]
    }
    client.describe_aggregation_authorizations.return_value = {"AggregationAuthorizations": []}
    results = []
    check_services.check_config(session, "us-east-1", results)
    services = {r["service"] for r in results}
    assert "AWS Config - Recorder" in services
    assert "AWS Config - Delivery Channel" in services
    assert results[0]["status"] == "Recording"


def test_config_empty_produces_no_findings():
    session = MagicMock()
    client = session.client.return_value
    client.describe_configuration_recorders.return_value = {"ConfigurationRecorders": []}
    client.describe_delivery_channels.return_value = {"DeliveryChannels": []}
    client.describe_aggregation_authorizations.return_value = {"AggregationAuthorizations": []}
    results = []
    check_services.check_config(session, "us-east-1", results)
    assert results == []


# --------------------------------------------------------------------------- #
# SNS conflict check
# --------------------------------------------------------------------------- #
def test_sns_conflicting_topic_flagged():
    session = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {"Topics": [
            {"TopicArn": "arn:aws:sns:us-east-1:1:aws-controltower-SecurityNotifications"},
            {"TopicArn": "arn:aws:sns:us-east-1:1:my-own-topic"},
        ]}
    ]
    session.client.return_value.get_paginator.return_value = paginator
    results = []
    check_services.check_sns_topic_conflicts(session, "us-east-1", results)
    assert len(results) == 1
    assert "SecurityNotifications" in results[0]["details"]


# --------------------------------------------------------------------------- #
# CloudTrail org-trail check
# --------------------------------------------------------------------------- #
def test_cloudtrail_org_and_account_trails_flagged():
    session = MagicMock()
    session.client.return_value.describe_trails.return_value = {
        "trailList": [
            {"Name": "org", "TrailARN": "arn:org", "IsOrganizationTrail": True},
            {"Name": "local", "TrailARN": "arn:local", "IsOrganizationTrail": False},
        ]
    }
    results = []
    check_services.check_cloudtrail_trails(session, "us-east-1", results)
    services = {r["service"] for r in results}
    assert "CloudTrail - Org Trail" in services
    assert "CloudTrail - Account Trail" in services
    org = next(r for r in results if r["service"] == "CloudTrail - Org Trail")
    assert org["criticality"].startswith("HIGH")


def test_cloudtrail_multiregion_shadow_skipped():
    session = MagicMock()
    session.client.return_value.describe_trails.return_value = {
        "trailList": [
            {
                "Name": "mr", "TrailARN": "arn:mr", "IsOrganizationTrail": False,
                "IsMultiRegionTrail": True, "HomeRegion": "us-east-1",
            }
        ]
    }
    results = []
    # In a non-home region the shadow copy should be ignored.
    check_services.check_cloudtrail_trails(session, "eu-west-1", results)
    assert results == []


# --------------------------------------------------------------------------- #
# GuardDuty / Security Hub delegation
# --------------------------------------------------------------------------- #
def test_guardduty_member_flagged():
    session = MagicMock()
    client = session.client.return_value
    client.list_detectors.return_value = {"DetectorIds": ["det-1"]}
    client.get_administrator_account.return_value = {"Administrator": {"AccountId": "999"}}
    results = []
    check_services.check_guardduty_delegation(session, "us-east-1", results)
    assert len(results) == 1
    assert "999" in results[0]["details"]


def test_securityhub_not_enabled_is_swallowed():
    session = MagicMock()
    session.client.return_value.describe_hub.side_effect = make_client_error(
        "InvalidAccessException"
    )
    results = []
    check_services.check_securityhub_delegation(session, "us-east-1", results)
    assert results == []


# --------------------------------------------------------------------------- #
# Leftover Control Tower resources (new checks)
# --------------------------------------------------------------------------- #
def test_iam_leftover_ct_role_flagged_critical():
    session = MagicMock()
    client = session.client.return_value

    def get_role(RoleName):  # noqa: N803 - matches boto3 kwarg
        if RoleName == "AWSControlTowerExecution":
            return {"Role": {"RoleName": RoleName}}
        raise make_client_error("NoSuchEntity")

    client.get_role.side_effect = get_role
    results = []
    check_services.check_controltower_iam_roles(session, results)
    assert len(results) == 1
    assert results[0]["service"] == "IAM - Control Tower Role"
    assert results[0]["criticality"].startswith("CRITICAL")
    assert "AWSControlTowerExecution" in results[0]["details"]


def test_iam_no_leftover_roles_is_clean():
    session = MagicMock()
    session.client.return_value.get_role.side_effect = make_client_error("NoSuchEntity")
    results = []
    check_services.check_controltower_iam_roles(session, results)
    assert results == []


def test_cfn_leftover_ct_stack_flagged_critical():
    session = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {"StackSummaries": [
            {"StackName": "AWSControlTowerBP-BASELINE-CLOUDTRAIL"},
            {"StackName": "my-own-stack"},
        ]}
    ]
    session.client.return_value.get_paginator.return_value = paginator
    results = []
    check_services.check_controltower_cfn_stacks(session, "us-east-1", results)
    assert len(results) == 1
    assert results[0]["criticality"].startswith("CRITICAL")
    assert "AWSControlTowerBP-BASELINE-CLOUDTRAIL" in results[0]["details"]


def test_default_vpc_flagged():
    session = MagicMock()
    session.client.return_value.describe_vpcs.return_value = {
        "Vpcs": [{"VpcId": "vpc-123"}]
    }
    results = []
    check_services.check_default_vpc(session, "us-east-1", results)
    assert len(results) == 1
    assert results[0]["service"] == "EC2 - Default VPC"
    assert "vpc-123" in results[0]["details"]


def test_no_default_vpc_is_clean():
    session = MagicMock()
    session.client.return_value.describe_vpcs.return_value = {"Vpcs": []}
    results = []
    check_services.check_default_vpc(session, "us-east-1", results)
    assert results == []


# --------------------------------------------------------------------------- #
# Global checks
# --------------------------------------------------------------------------- #
def test_sso_enabled_flagged_critical():
    session = MagicMock()
    session.client.return_value.list_instances.return_value = {
        "Instances": [{"InstanceArn": "arn:sso:instance"}]
    }
    results = []
    check_services.check_sso(session, results)
    assert len(results) == 1
    assert results[0]["criticality"].startswith("CRITICAL")


def test_organizations_documents_org_and_scps():
    session = MagicMock()
    client = session.client.return_value
    client.describe_organization.return_value = {
        "Organization": {"Id": "o-abc", "FeatureSet": "ALL"}
    }
    client.list_policies.return_value = {
        "Policies": [{"Name": "FullAWSAccess"}, {"Name": "DenyStuff"}]
    }
    client.list_delegated_administrators.return_value = {"DelegatedAdministrators": []}
    results = []
    check_services.check_organizations(session, results)
    services = {r["service"] for r in results}
    assert "AWS Organizations" in services
    assert "AWS Organizations - SCPs" in services  # FullAWSAccess excluded


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #
def test_get_all_account_ids_inserts_management(monkeypatch):
    monkeypatch.setattr(
        check_services, "aws_org_accounts", lambda: [{"Id": "111"}, {"Id": "222"}]
    )
    ids = check_services.get_all_account_ids("999")
    assert "999" in ids and "111" in ids and "222" in ids


def test_get_all_account_ids_keeps_management_when_present(monkeypatch):
    monkeypatch.setattr(
        check_services, "aws_org_accounts", lambda: [{"Id": "999"}, {"Id": "111"}]
    )
    ids = check_services.get_all_account_ids("999")
    assert ids.count("999") == 1


def test_get_all_account_ids_handles_unknown_management(monkeypatch):
    # When the management account cannot be identified (None), just list accounts.
    monkeypatch.setattr(
        check_services, "aws_org_accounts", lambda: [{"Id": "111"}, {"Id": "222"}]
    )
    ids = check_services.get_all_account_ids(None)
    assert ids == ["111", "222"]


def test_management_account_id_returns_none_on_access_denied(monkeypatch):
    client = MagicMock()
    client.describe_organization.side_effect = make_client_error("AccessDeniedException")
    monkeypatch.setattr(check_services.boto3, "client", lambda service: client)
    assert check_services.aws_org_management_account_id() is None


# --------------------------------------------------------------------------- #
# Reporting / output
# --------------------------------------------------------------------------- #
def test_print_report_shows_management_blockers():
    results = [
        {
            "account_id": "999",
            "is_management_account": True,
            "findings": [
                {
                    "service": "IAM Identity Center (SSO)",
                    "region": "global",
                    "status": "Enabled",
                    "details": "Instance ARN: arn:x",
                    "criticality": "CRITICAL - Must be disabled before migration",
                }
            ],
        }
    ]
    stream = io.StringIO()
    check_services.print_report(results, stream=stream)
    out = stream.getvalue()
    assert "CRITICAL MANAGEMENT ACCOUNT BLOCKERS" in out
    assert "IAM Identity Center" in out
    assert "[CRITICAL]" in out
    # Output must be plain text: no emoji / status icons.
    assert out.isascii()


def test_severity_tag_levels():
    assert check_services._severity_tag("CRITICAL - x") == "[CRITICAL]"
    assert check_services._severity_tag("HIGH - x") == "[HIGH]"
    assert check_services._severity_tag("INFO - x") == "[INFO]"
    assert check_services._severity_tag("") == "[----]"


def test_write_json_output_creates_timestamped_file(tmp_path):
    results = [{"account_id": "999", "findings": []}]
    path = check_services.write_json_output(results, str(tmp_path), "999")
    assert path.endswith(".json")
    assert "999" in path
    with open(path, encoding="utf-8") as handle:
        assert json.load(handle) == results


# --------------------------------------------------------------------------- #
# CLI / run()
# --------------------------------------------------------------------------- #
def test_parse_args_defaults():
    args = check_services.parse_args([])
    assert args.role_name == "OrganizationAccountAccessRole"
    assert args.external_id is None
    assert args.output_dir == "output"
    assert args.stdout is False
    assert args.quiet is False


def test_parse_args_external_id():
    args = check_services.parse_args(["--external-id", "secret123"])
    assert args.external_id == "secret123"


def test_assume_role_omits_external_id_when_absent(monkeypatch):
    sts = MagicMock()
    sts.assume_role.return_value = {"Credentials": {
        "AccessKeyId": "a", "SecretAccessKey": "b", "SessionToken": "c"
    }}
    monkeypatch.setattr(check_services.boto3, "client", lambda service: sts)
    monkeypatch.setattr(check_services.boto3, "Session", lambda **kw: kw)
    check_services.assume_role("111122223333", "MyRole")
    _, kwargs = sts.assume_role.call_args
    assert kwargs["RoleArn"] == "arn:aws:iam::111122223333:role/MyRole"
    assert "ExternalId" not in kwargs


def test_assume_role_passes_external_id(monkeypatch):
    sts = MagicMock()
    sts.assume_role.return_value = {"Credentials": {
        "AccessKeyId": "a", "SecretAccessKey": "b", "SessionToken": "c"
    }}
    monkeypatch.setattr(check_services.boto3, "client", lambda service: sts)
    monkeypatch.setattr(check_services.boto3, "Session", lambda **kw: kw)
    check_services.assume_role("111122223333", "MyRole", external_id="secret123")
    _, kwargs = sts.assume_role.call_args
    assert kwargs["ExternalId"] == "secret123"


def test_run_returns_2_on_critical(monkeypatch, capsys):
    monkeypatch.setattr(check_services, "aws_org_management_account_id", lambda: "999")
    monkeypatch.setattr(check_services, "get_all_account_ids", lambda mgmt: ["999"])
    monkeypatch.setattr(check_services, "boto3", MagicMock())

    def fake_check(account_id, session, mgmt, *, quiet):
        return {
            "account_id": account_id,
            "is_management_account": True,
            "findings": [{"criticality": "CRITICAL - x", "service": "s",
                          "region": "global", "status": "Enabled", "details": "d"}],
        }

    monkeypatch.setattr(check_services, "check_account_services", fake_check)
    args = check_services.parse_args(["--stdout", "--quiet"])
    assert check_services.run(args) == 2
    # stdout should be valid JSON.
    out = capsys.readouterr().out
    assert json.loads(out)[0]["account_id"] == "999"


def test_run_returns_0_when_clean(monkeypatch):
    monkeypatch.setattr(check_services, "aws_org_management_account_id", lambda: "999")
    monkeypatch.setattr(check_services, "get_all_account_ids", lambda mgmt: ["999"])
    monkeypatch.setattr(check_services, "boto3", MagicMock())
    monkeypatch.setattr(
        check_services,
        "check_account_services",
        lambda account_id, session, mgmt, *, quiet: {
            "account_id": account_id, "is_management_account": True, "findings": []
        },
    )
    args = check_services.parse_args(["--stdout", "--quiet"])
    assert check_services.run(args) == 0


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
