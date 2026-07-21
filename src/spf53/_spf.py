"""Shared SPF qualifier-stripping helper.

A mechanism may be prefixed with a single qualifier character (+, -, ~, ?)
per RFC 7208 4.6.1; this module strips it before mechanism-name matching.
"""

QUALIFIERS = "+-~?"


def strip_qualifier(term: str) -> str:
    return term[1:] if term and term[0] in QUALIFIERS else term
