"""Route53 TXT record read/write for spf53 chunk records."""

from __future__ import annotations

import re
from typing import Any

from spf53 import _boto, chunker


class AmbiguousTxtRecordError(ValueError):
    """Raised when an spf53-owned TXT rrset has more than one ResourceRecord.

    A subclass of ValueError so it's caught by the same per-domain error
    handling that already covers other ValueErrors from this module's output
    (e.g. chunker.from_route53_value's malformed-value errors).
    """


def _client() -> Any:
    return _boto.get_client("route53")


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
            is_chunk = chunk_re.match(name)
            if name != domain and not is_chunk:
                continue
            resource_records = rrset.get("ResourceRecords", [])
            if is_chunk and len(resource_records) > 1:
                # spf53 only ever writes a chunk rrset as a single
                # ResourceRecord (whose Value may itself hold up to
                # MAX_STRINGS_PER_RECORD concatenated character-strings, see
                # chunker.py). Multiple separate ResourceRecords here is
                # foreign, ambiguous state -- e.g. leftover from another
                # flattener -- that apply_changes' DELETE (built as a single
                # ResourceRecord) can't reconstruct. Refuse rather than
                # silently concatenating and risking a rejected change batch
                # or a false "no change" diff.
                raise AmbiguousTxtRecordError(
                    f"{name!r} has {len(resource_records)} separate Route53 "
                    "ResourceRecords in one TXT rrset, which spf53 does not "
                    "manage -- clean it up manually in Route53 before spf53 "
                    "can manage this record again"
                )
            strings: list[str] = []
            for rr in resource_records:
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
