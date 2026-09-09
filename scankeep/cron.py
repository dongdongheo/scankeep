"""Validation and UTC evaluation for scan schedule expressions."""

from __future__ import annotations

import datetime as dt

from croniter import CroniterBadCronError, CroniterBadDateError, croniter


def normalize_cron(expression: str) -> str:
    value = " ".join(expression.strip().split())
    if len(value.split()) != 5:
        raise ValueError("cron_expression must contain exactly five fields")
    try:
        croniter(value, dt.datetime.now(dt.UTC)).get_next(dt.datetime)
    except (
        CroniterBadCronError,
        CroniterBadDateError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise ValueError("cron_expression is invalid") from exc
    return value


def next_cron_run(expression: str, after: str | dt.datetime) -> str:
    base = dt.datetime.fromisoformat(after) if isinstance(after, str) else after
    if base.tzinfo is None:
        base = base.replace(tzinfo=dt.UTC)
    else:
        base = base.astimezone(dt.UTC)
    return (
        croniter(expression, base)
        .get_next(dt.datetime)
        .astimezone(dt.UTC)
        .isoformat(timespec="seconds")
    )
