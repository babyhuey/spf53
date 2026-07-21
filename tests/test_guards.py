"""Tests for spf53.guards."""

from ipaddress import IPv4Network, IPv6Network

from spf53.guards import GuardResult, check_guards, check_lookup_cost


def test_empty_new_set_refused() -> None:
    result = check_guards([], [], max_shrink_pct=30)
    assert isinstance(result, GuardResult)
    assert result.ok is False
    assert result.reasons


def test_empty_new_set_refused_even_with_nonempty_live() -> None:
    live = [IPv4Network("192.0.2.0/24")]
    result = check_guards(live, [], max_shrink_pct=30)
    assert result.ok is False
    assert result.reasons


def test_first_run_passes_with_no_live_records() -> None:
    new = [IPv4Network("192.0.2.0/24")]
    result = check_guards([], new, max_shrink_pct=30)
    assert result.ok is True
    assert result.reasons == ()


def test_growth_passes() -> None:
    live = [IPv4Network("192.0.2.0/28")]  # 16 addresses
    new = [IPv4Network("192.0.2.0/24")]  # 256 addresses
    result = check_guards(live, new, max_shrink_pct=30)
    assert result.ok is True
    assert result.reasons == ()


def test_shrink_over_threshold_refused() -> None:
    live = [IPv4Network("192.0.2.0/24")]  # 256 addresses
    new = [IPv4Network("192.0.2.0/28")]  # 16 addresses -> 93.75% shrink
    result = check_guards(live, new, max_shrink_pct=30)
    assert result.ok is False
    assert result.reasons
    assert "shrank" in result.reasons[0]


def test_shrink_exactly_at_threshold_passes() -> None:
    # 100 host addresses -> 70 host addresses is exactly a 30% shrink.
    live = [IPv4Network(f"10.0.0.{i}/32") for i in range(100)]
    new = [IPv4Network(f"10.0.0.{i}/32") for i in range(70)]
    result = check_guards(live, new, max_shrink_pct=30)
    assert result.ok is True
    assert result.reasons == ()


def test_shrink_just_over_threshold_refused() -> None:
    # 100 host addresses -> 69 host addresses is a 31% shrink.
    live = [IPv4Network(f"10.0.0.{i}/32") for i in range(100)]
    new = [IPv4Network(f"10.0.0.{i}/32") for i in range(69)]
    result = check_guards(live, new, max_shrink_pct=30)
    assert result.ok is False
    assert result.reasons


def test_mixed_family_ipv4_wipeout_refused_despite_stable_ipv6() -> None:
    # Regression test: a broken include drops the entire IPv4 block while a
    # vastly larger, unchanged IPv6 block remains. Summed into one combined
    # address count, the IPv4 loss (256 addresses) is computationally
    # negligible next to the IPv6 block (2**96 addresses), so the combined
    # shrink_pct rounds to ~0% and the old guard wrongly passed this. Each
    # family must be checked independently so the IPv4 wipeout is caught.
    live = [IPv4Network("203.0.113.0/24"), IPv6Network("2001:db8::/32")]
    new = [IPv6Network("2001:db8::/32")]  # IPv4 gone entirely, IPv6 unchanged
    result = check_guards(live, new, max_shrink_pct=30)
    assert result.ok is False
    assert result.reasons
    assert any("IPv4" in reason and "shrank 100.0%" in reason for reason in result.reasons)


def test_mixed_family_ipv6_shrink_over_threshold_refused_despite_stable_ipv4() -> None:
    live = [IPv4Network("203.0.113.0/24"), IPv6Network("2001:db8::/32")]
    # IPv6 shrinks from a /32 to a /34 -> 75% shrink, IPv4 unchanged.
    new = [IPv4Network("203.0.113.0/24"), IPv6Network("2001:db8::/34")]
    result = check_guards(live, new, max_shrink_pct=30)
    assert result.ok is False
    assert result.reasons
    assert any("IPv6" in reason and "shrank" in reason for reason in result.reasons)


def test_mixed_family_both_shrink_within_threshold_passes() -> None:
    live = [IPv4Network("203.0.113.0/24"), IPv6Network("2001:db8::/32")]
    # IPv4 /24 (256) -> /25 (128) is a 50%... too much; use a smaller shrink.
    # 256 -> 200 addresses is a ~21.9% shrink (within 30% threshold).
    new_v4 = [IPv4Network(f"203.0.113.{i}/32") for i in range(200)]
    # /32 (2**96) -> a /33 (2**95) is exactly a 50% shrink; use /32 minus a
    # sliver instead: two /33s cover the same space as one /32, so split
    # into a /33 plus a /34 to shrink by 25% (within threshold).
    new = [*new_v4, IPv6Network("2001:db8::/33"), IPv6Network("2001:db8:8000::/34")]
    result = check_guards(live, new, max_shrink_pct=30)
    assert result.ok is True
    assert result.reasons == ()


def test_mixed_family_new_family_first_time_passes() -> None:
    # Live is IPv4-only; new adds IPv6 for the first time with IPv4
    # unchanged. IPv6 has no live baseline, so it must not trigger a refusal.
    live = [IPv4Network("203.0.113.0/24")]
    new = [IPv4Network("203.0.113.0/24"), IPv6Network("2001:db8::/32")]
    result = check_guards(live, new, max_shrink_pct=30)
    assert result.ok is True
    assert result.reasons == ()


def test_lookup_cost_exactly_at_hard_limit_passes() -> None:
    # RFC 7208: exactly 10 lookups is still valid, just at capacity.
    result = check_lookup_cost(10)
    assert result.ok is True
    assert result.reasons == ()


def test_lookup_cost_over_hard_limit_refused() -> None:
    result = check_lookup_cost(11)
    assert result.ok is False
    assert result.reasons
    assert "RFC 7208" in result.reasons[0]


def test_lookup_cost_well_under_limit_passes() -> None:
    result = check_lookup_cost(2)
    assert result.ok is True
    assert result.reasons == ()
