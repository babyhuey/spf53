"""Tests for spf53.guards."""

from ipaddress import IPv4Network

from spf53.guards import GuardResult, check_guards


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
