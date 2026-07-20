"""Route53 TXT record read/write for spf53 chunk records."""

from __future__ import annotations

import re

import boto3

from spf53 import chunker


def get_txt_records(zone_id: str, domain: str) -> dict[str, list[str]]:
    """Return the apex TXT record and all _spf53-N TXT records for `domain`.

    Keys are record names with the trailing dot stripped. Values are the
    decoded string lists (via chunker.from_route53_value).
    """
    domain = domain.rstrip(".")
    chunk_re = re.compile(rf"^_spf53-\d+\.{re.escape(domain)}$")

    client = boto3.client("route53")
    paginator = client.get_paginator("list_resource_record_sets")

    records: dict[str, list[str]] = {}
    for page in paginator.paginate(HostedZoneId=zone_id):
        for rrset in page["ResourceRecordSets"]:
            if rrset["Type"] != "TXT":
                continue
            name = rrset["Name"].rstrip(".")
            if name != domain and not chunk_re.match(name):
                continue
            strings: list[str] = []
            for rr in rrset.get("ResourceRecords", []):
                strings.extend(chunker.from_route53_value(rr["Value"]))
            records[name] = strings

    return records


def apply_changes(
    zone_id: str,
    upserts: dict[str, list[str]],
    deletes: dict[str, list[str]],
    ttl: int = 300,
) -> None:
    """Apply UPSERTs and DELETEs in a single atomic change batch.

    `deletes` values must be the current live strings for that record (and
    `ttl` must match the live TTL), since Route53 requires an exact match to
    delete a record set.
    """
    if not upserts and not deletes:
        return

    changes = [
        {
            "Action": "UPSERT",
            "ResourceRecordSet": {
                "Name": name,
                "Type": "TXT",
                "TTL": ttl,
                "ResourceRecords": [{"Value": chunker.to_route53_value(strings)}],
            },
        }
        for name, strings in upserts.items()
    ] + [
        {
            "Action": "DELETE",
            "ResourceRecordSet": {
                "Name": name,
                "Type": "TXT",
                "TTL": ttl,
                "ResourceRecords": [{"Value": chunker.to_route53_value(strings)}],
            },
        }
        for name, strings in deletes.items()
    ]

    client = boto3.client("route53")
    client.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={"Changes": changes},
    )
