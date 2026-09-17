#!/usr/bin/env python3
"""Export safe Cowrie aggregates and optionally publish the changed JSON."""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import sqlite3
import subprocess
import tempfile
import time

DAY = 86400
COMMAND_TOKEN = re.compile(r"^[A-Za-z0-9_.+-]{1,40}$")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
SEPARATORS = re.compile(r"&&|\|\||[;|&()\r\n]")
WRAPPERS = {"command", "env", "nohup", "sudo", "timeout"}


def utc(value: float) -> str:
    return dt.datetime.fromtimestamp(value, dt.timezone.utc).isoformat().replace("+00:00", "Z")


def public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def command_name(value: str) -> str:
    """Return only a conservative executable label, never a full command line."""
    first = SEPARATORS.split(value.strip(), maxsplit=1)[0]
    try:
        tokens = shlex.split(first, posix=True)
    except ValueError:
        tokens = first.split()
    tokens = [token for token in tokens if not ASSIGNMENT.match(token)]
    while tokens and Path(tokens[0]).name.lower() in WRAPPERS:
        tokens.pop(0)
        while tokens and tokens[0].startswith("-"):
            tokens.pop(0)
    if not tokens:
        return "other"
    name = Path(tokens[0]).name.lower()
    if name == "busybox" and len(tokens) > 1:
        name = Path(tokens[1]).name.lower()
    return name if COMMAND_TOKEN.fullmatch(name) else "other"


def connect_readonly(path: Path) -> sqlite3.Connection:
    uri = path.resolve().as_uri() + "?mode=ro"
    db = sqlite3.connect(uri, uri=True, timeout=10)
    db.execute("PRAGMA query_only=ON")
    db.execute("PRAGMA busy_timeout=10000")
    return db


def ranking(rows, limit: int = 10):
    return [{"label": label, "count": int(count)} for label, count in rows[:limit]]


def build_snapshot(db_path: Path, days: int, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    cutoff = now - days * DAY
    with connect_readonly(db_path) as db:
        first, last = db.execute("SELECT min(ts),max(ts) FROM events").fetchone()
        if first is None or last is None:
            raise RuntimeError("history database contains no events")

        totals_row = db.execute(
            "SELECT "
            "sum(eventid='cowrie.session.connect'),"
            "sum(eventid IN ('cowrie.login.failed','cowrie.login.success'))," 
            "sum(eventid='cowrie.command.input'),"
            "sum(eventid='cowrie.session.file_download'),"
            "sum(eventid='cowrie.session.file_upload') "
            "FROM events WHERE ts>=? AND ts<=?",
            (cutoff, now),
        ).fetchone()
        public_sources = [
            (source, count)
            for source, count in db.execute(
                "SELECT src_ip,count(*) FROM events "
                "WHERE ts>=? AND ts<=? AND eventid='cowrie.session.connect' AND src_ip!='' "
                "GROUP BY src_ip ORDER BY count(*) DESC,src_ip",
                (cutoff, now),
            )
            if public_ip(source)
        ]
        countries = list(db.execute(
            "SELECT country,count(*) FROM events "
            "WHERE ts>=? AND ts<=? AND eventid='cowrie.session.connect' "
            "GROUP BY country ORDER BY count(*) DESC,country LIMIT 10",
            (cutoff, now),
        ))
        commands = collections.Counter(
            command_name(row[0])
            for row in db.execute(
                "SELECT command FROM events "
                "WHERE ts>=? AND ts<=? AND eventid='cowrie.command.input' AND command!=''",
                (cutoff, now),
            )
        )
        daily_rows = dict(db.execute(
            "SELECT strftime('%Y-%m-%d',ts,'unixepoch'),count(*) FROM events "
            "WHERE ts>=? AND ts<=? AND eventid='cowrie.session.connect' GROUP BY 1",
            (cutoff, now),
        ))

    end_date = dt.datetime.fromtimestamp(now, dt.timezone.utc).date()
    start_date = end_date - dt.timedelta(days=min(days, 30) - 1)
    daily = []
    cursor = start_date
    while cursor <= end_date:
        label = cursor.isoformat()
        daily.append({"date": label, "count": int(daily_rows.get(label, 0))})
        cursor += dt.timedelta(days=1)

    connections, logins, commands_total, downloads, uploads = (int(value or 0) for value in totals_row)
    return {
        "schema_version": 1,
        "generated_at": utc(now),
        "window_days": days,
        "coverage": {
            "first_observation": utc(first),
            "last_observation": utc(last),
            "range_complete": first <= cutoff,
        },
        "totals": {
            "connections": connections,
            "unique_public_ips": len(public_sources),
            "login_attempts": logins,
            "commands": commands_total,
            "downloads": downloads,
            "uploads": uploads,
        },
        "top_ips": ranking(public_sources),
        "top_countries": ranking(countries),
        "top_commands": ranking(commands.most_common(10)),
        "daily_connections": daily,
    }


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False, encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=False)
        handle.write("\n")
        temporary = Path(handle.name)
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def publish(repo: Path) -> None:
    git(repo, "pull", "--ff-only", "origin", "main")
    git(repo, "add", "--", "data/stats.json")
    if git(repo, "diff", "--cached", "--quiet", check=False).returncode == 0:
        print("aggregate snapshot unchanged")
        return
    git(repo, "commit", "-m", "Update daily aggregate statistics")
    git(repo, "push", "origin", "main")
    print("published daily aggregate snapshot")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--days", type=int, default=90, choices=range(1, 91), metavar="1-90")
    parser.add_argument("--export-only", action="store_true")
    args = parser.parse_args()

    if not (args.repo / ".git").is_dir() and not args.export_only:
        raise SystemExit("repo path is not a Git checkout")
    destination = args.repo / "data" / "stats.json"
    write_json(destination, build_snapshot(args.db, args.days))
    print(f"wrote {destination}")
    if not args.export_only:
        publish(args.repo)


if __name__ == "__main__":
    main()

