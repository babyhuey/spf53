"""Tests for spf53.route53."""

from __future__ import annotations

from collections.abc import Iterator
from unittest import mock

import boto3
import pytest
from moto import mock_aws

from spf53 import chunker, route53

DOMAIN = "example.com"


@pytest.fixture(autouse=True)
def aws_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture
def zone_id() -> Iterator[str]:
    with mock_aws():
        client = boto3.client("route53", region_name="us-east-1")
        resp = client.create_hosted_zone(
            Name=f"{DOMAIN}.",
            CallerReference="spf53-test",
        )
        yield resp["HostedZone"]["Id"].removeprefix("/hostedzone/")


def _put_txt(zone_id: str, name: str, strings: list[str], ttl: int = 300) -> None:
    """Seed a TXT record directly via boto3, bypassing route53.apply_changes."""
    client = boto3.client("route53", region_name="us-east-1")
    client.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Changes": [
                {
                    "Action": "UPSERT",
                    "ResourceRecordSet": {
                        "Name": name,
                        "Type": "TXT",
                        "TTL": ttl,
                        "ResourceRecords": [{"Value": chunker.to_route53_value(strings)}],
                    },
                }
            ]
        },
    )


def test_get_txt_records_apex_and_chunks(zone_id: str) -> None:
    _put_txt(zone_id, DOMAIN, ["v=spf1 include:_spf53-1.example.com ~all"])
    _put_txt(
        zone_id,
        f"_spf53-1.{DOMAIN}",
        ["v=spf1 ip4:1.2.3.0/24", "include:_spf53-2.example.com"],
    )
    _put_txt(zone_id, f"_spf53-2.{DOMAIN}", ["v=spf1 ip4:5.6.7.0/24 ~all"])

    client = boto3.client("route53", region_name="us-east-1")
    client.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Changes": [
                {
                    "Action": "UPSERT",
                    "ResourceRecordSet": {
                        "Name": f"noise.{DOMAIN}",
                        "Type": "A",
                        "TTL": 300,
                        "ResourceRecords": [{"Value": "10.0.0.1"}],
                    },
                }
            ]
        },
    )

    result, _ttls = route53.get_txt_records(zone_id, DOMAIN)

    assert result == {
        DOMAIN: ["v=spf1 include:_spf53-1.example.com ~all"],
        f"_spf53-1.{DOMAIN}": ["v=spf1 ip4:1.2.3.0/24", "include:_spf53-2.example.com"],
        f"_spf53-2.{DOMAIN}": ["v=spf1 ip4:5.6.7.0/24 ~all"],
    }


def test_get_txt_records_keys_have_no_trailing_dot(zone_id: str) -> None:
    _put_txt(zone_id, DOMAIN, ["v=spf1 ~all"])

    result, _ttls = route53.get_txt_records(zone_id, DOMAIN)

    assert all(not key.endswith(".") for key in result)


def test_get_txt_records_ignores_non_matching_names(zone_id: str) -> None:
    _put_txt(zone_id, DOMAIN, ["v=spf1 ~all"])
    # wrong sub-apex: extra label between the chunk index and the domain
    _put_txt(zone_id, f"_spf53-1.other.{DOMAIN}", ["decoy"])
    # non-numeric chunk index
    _put_txt(zone_id, f"_spf53-abc.{DOMAIN}", ["decoy"])
    # unrelated name
    _put_txt(zone_id, f"notspf53.{DOMAIN}", ["decoy"])

    result, _ttls = route53.get_txt_records(zone_id, DOMAIN)

    assert set(result) == {DOMAIN}


def test_get_txt_records_decodes_escaped_values(zone_id: str) -> None:
    tricky = ['has "quotes" inside', "and a \\ backslash"]
    _put_txt(zone_id, f"_spf53-1.{DOMAIN}", tricky)

    result, _ttls = route53.get_txt_records(zone_id, DOMAIN)

    assert result[f"_spf53-1.{DOMAIN}"] == tricky


def test_get_txt_records_trailing_dot_domain_input(zone_id: str) -> None:
    _put_txt(zone_id, DOMAIN, ["v=spf1 ~all"])

    result, _ttls = route53.get_txt_records(zone_id, f"{DOMAIN}.")

    assert DOMAIN in result


def test_get_txt_records_paginates_across_pages(zone_id: str) -> None:
    # moto's list_resource_record_sets defaults to a 300-item page when no
    # MaxItems is supplied. Route53 sorts by reversed name, so the apex
    # ("example.com") sorts first, "0filler*" records (leading digit < '_')
    # sort next, and "_spf53-N" chunk records sort after that — pushing them
    # onto the second page and exercising the paginator's page-merging.
    changes: list[dict] = [
        {
            "Action": "UPSERT",
            "ResourceRecordSet": {
                "Name": DOMAIN,
                "Type": "TXT",
                "TTL": 300,
                "ResourceRecords": [
                    {
                        "Value": chunker.to_route53_value(
                            ["v=spf1 include:_spf53-1.example.com ~all"]
                        )
                    }
                ],
            },
        }
    ]
    for i in range(305):
        changes.append(
            {
                "Action": "UPSERT",
                "ResourceRecordSet": {
                    "Name": f"0filler{i:04d}.{DOMAIN}",
                    "Type": "A",
                    "TTL": 300,
                    "ResourceRecords": [{"Value": "10.0.0.1"}],
                },
            }
        )
    expected_chunks = {}
    for n in (1, 2, 3):
        strings = [f"v=spf1 ip4:{n}.0.0.0/24 ~all"]
        expected_chunks[f"_spf53-{n}.{DOMAIN}"] = strings
        changes.append(
            {
                "Action": "UPSERT",
                "ResourceRecordSet": {
                    "Name": f"_spf53-{n}.{DOMAIN}",
                    "Type": "TXT",
                    "TTL": 300,
                    "ResourceRecords": [{"Value": chunker.to_route53_value(strings)}],
                },
            }
        )

    client = boto3.client("route53", region_name="us-east-1")
    client.change_resource_record_sets(HostedZoneId=zone_id, ChangeBatch={"Changes": changes})

    result, _ttls = route53.get_txt_records(zone_id, DOMAIN)

    assert result[DOMAIN] == ["v=spf1 include:_spf53-1.example.com ~all"]
    for name, strings in expected_chunks.items():
        assert result[name] == strings
    assert len(result) == 4  # apex + 3 chunks; filler A records excluded


def test_apply_changes_upsert_and_delete_in_one_batch(zone_id: str) -> None:
    _put_txt(zone_id, f"_spf53-1.{DOMAIN}", ["old chunk 1"])
    _put_txt(zone_id, f"_spf53-3.{DOMAIN}", ["stale chunk 3"])

    route53.apply_changes(
        zone_id,
        upserts={
            f"_spf53-1.{DOMAIN}": ["v=spf1 ip4:1.2.3.0/24 include:_spf53-2.example.com"],
            f"_spf53-2.{DOMAIN}": ["v=spf1 ip4:5.6.7.0/24 ~all"],
        },
        deletes={f"_spf53-3.{DOMAIN}": ["stale chunk 3"]},
    )

    result, _ttls = route53.get_txt_records(zone_id, DOMAIN)
    assert result[f"_spf53-1.{DOMAIN}"] == ["v=spf1 ip4:1.2.3.0/24 include:_spf53-2.example.com"]
    assert result[f"_spf53-2.{DOMAIN}"] == ["v=spf1 ip4:5.6.7.0/24 ~all"]
    assert f"_spf53-3.{DOMAIN}" not in result


def test_apply_changes_is_a_single_api_call(zone_id: str) -> None:
    import botocore.client

    orig_make_api_call = botocore.client.BaseClient._make_api_call
    calls: list[dict] = []

    def spy(self: object, operation_name: str, kwargs: dict) -> object:
        if operation_name == "ChangeResourceRecordSets":
            calls.append(kwargs)
        return orig_make_api_call(self, operation_name, kwargs)

    with mock.patch.object(botocore.client.BaseClient, "_make_api_call", spy):
        route53.apply_changes(
            zone_id,
            upserts={f"_spf53-1.{DOMAIN}": ["v=spf1 ~all"]},
            deletes={},
        )

    assert len(calls) == 1


def test_apply_changes_default_ttl_is_300(zone_id: str) -> None:
    route53.apply_changes(
        zone_id,
        upserts={f"_spf53-1.{DOMAIN}": ["v=spf1 ~all"]},
        deletes={},
    )

    client = boto3.client("route53", region_name="us-east-1")
    resp = client.list_resource_record_sets(HostedZoneId=zone_id)
    rrset = next(
        r for r in resp["ResourceRecordSets"] if r["Name"].rstrip(".") == f"_spf53-1.{DOMAIN}"
    )
    assert rrset["TTL"] == 300


def test_apply_changes_empty_dicts_is_noop(zone_id: str) -> None:
    with mock.patch("boto3.client") as mock_client:
        route53.apply_changes(zone_id, {}, {})
    mock_client.assert_not_called()


def test_get_txt_records_captures_live_ttl(zone_id: str) -> None:
    _put_txt(zone_id, f"_spf53-1.{DOMAIN}", ["v=spf1 ~all"], ttl=600)

    _records, ttls = route53.get_txt_records(zone_id, DOMAIN)

    assert ttls[f"_spf53-1.{DOMAIN}"] == 600


def test_apply_changes_delete_uses_live_ttl(zone_id: str) -> None:
    """A hand-edited record's TTL may not be the default 300; Route53 requires

    DELETE to match the live TTL exactly, so the whole batch must fail if the
    wrong TTL is sent. Capturing and reusing the live TTL must let it succeed.
    """
    _put_txt(zone_id, f"_spf53-1.{DOMAIN}", ["stale chunk"], ttl=600)

    live, ttls = route53.get_txt_records(zone_id, DOMAIN)
    assert ttls[f"_spf53-1.{DOMAIN}"] == 600

    route53.apply_changes(
        zone_id,
        upserts={},
        deletes={f"_spf53-1.{DOMAIN}": live[f"_spf53-1.{DOMAIN}"]},
        delete_ttls=ttls,
    )

    result, _ttls = route53.get_txt_records(zone_id, DOMAIN)
    assert f"_spf53-1.{DOMAIN}" not in result


def test_apply_changes_delete_with_wrong_ttl_fails_whole_batch(zone_id: str) -> None:
    """Without the live TTL, the DELETE (and thus the atomic batch) is rejected."""
    from botocore.exceptions import ClientError

    _put_txt(zone_id, f"_spf53-1.{DOMAIN}", ["stale chunk"], ttl=600)

    with pytest.raises(ClientError):
        route53.apply_changes(
            zone_id,
            upserts={f"_spf53-2.{DOMAIN}": ["v=spf1 ~all"]},
            deletes={f"_spf53-1.{DOMAIN}": ["stale chunk"]},
            # no delete_ttls passed, so the default ttl=300 is used instead of the live 600
        )

    # the atomic batch was rejected, so the bundled upsert never landed either
    result, _ttls = route53.get_txt_records(zone_id, DOMAIN)
    assert f"_spf53-2.{DOMAIN}" not in result
