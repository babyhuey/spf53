"""Route53 TXT record read/write for spf53 chunk records."""

from __future__ import annotations

import functools
import re
from typing import Any

import boto3

from spf53 import chunker


@functools.cache
def _client() -> Any:
    return boto3.client("route53")


def get_txt_records(zone_id: str, domain: str) -> tuple[dict[str, list[str]], dict[str, int]]:
    """Return the apex TXT record and all _spf53-N TXT records for `domain`.

    Keys are record names with the trailing dot stripped. Values are the
    decoded string lists (via chunker.from_route53_value). Also returns each
    record's live TTL keyed by the same record name — Route53 DELETE requires
    an exact TTL match, so callers need it to build a correct delete.
    """
    domain = domain.rstrip(".")
    chunk_re = re.compile(rf"^_spf53-\d+\.{re.escape(domain)}$")

    paginator = _client().get_paginator("list_resource_record_sets")

    records: dict[str, list[str]] = {}
    ttls: dict[str, int] = {}
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
            ttls[name] = rrset["TTL"]

    return records, ttls


def apply_changes(
    zone_id: str,
    upserts: dict[str, list[str]],
    deletes: dict[str, list[str]],
    delete_ttls: dict[str, int] | None = None,
    ttl: int = 300,
) -> None:
    """Apply UPSERTs and DELETEs in a single atomic change batch.

    `deletes` values must be the current live strings for that record, and
    Route53 requires the DELETE's TTL to exactly match the live record's TTL
    too. `delete_ttls` (name -> live TTL, e.g. from `get_txt_records`) supplies
    that; a name missing from it falls back to `ttl`.
    """
    if not upserts and not deletes:
        return

    delete_ttls = delete_ttls or {}

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
                "TTL": delete_ttls.get(name, ttl),
                "ResourceRecords": [{"Value": chunker.to_route53_value(strings)}],
            },
        }
        for name, strings in deletes.items()
    ]

    _client().change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={"Changes": changes},
    )
