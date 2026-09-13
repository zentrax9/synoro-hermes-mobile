import pytest

from hermes_cli.mobile_rate_limit import MobileRateLimitExceeded, MobileRateLimiter


def test_limits_are_partitioned_by_authenticated_dimension_and_action(tmp_path):
    now = [100.0]
    limiter = MobileRateLimiter(tmp_path / "limits.sqlite", clock=lambda: now[0])
    for _ in range(2):
        limiter.check(
            dimension="device",
            principal="device-a",
            action="message.send",
            limit=2,
            window_seconds=60,
        )

    with pytest.raises(MobileRateLimitExceeded) as error:
        limiter.check(
            dimension="device",
            principal="device-a",
            action="message.send",
            limit=2,
            window_seconds=60,
        )

    assert error.value.retry_after == 20
    limiter.check(
        dimension="device",
        principal="device-b",
        action="message.send",
        limit=2,
        window_seconds=60,
    )
    limiter.check(
        dimension="device",
        principal="device-a",
        action="sync.read",
        limit=2,
        window_seconds=60,
    )


def test_new_window_allows_requests_without_resetting_other_dimensions(tmp_path):
    now = [119.0]
    limiter = MobileRateLimiter(tmp_path / "limits.sqlite", clock=lambda: now[0])
    limiter.check(dimension="user", principal="u", action="sync", limit=1, window_seconds=60)
    now[0] = 120.0

    limiter.check(dimension="user", principal="u", action="sync", limit=1, window_seconds=60)
