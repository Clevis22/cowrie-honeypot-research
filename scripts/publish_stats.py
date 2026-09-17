#!/usr/bin/env python3
"""Export safe Cowrie aggregates and optionally publish the changed JSON.

The recent snapshot contains fixed 24-hour, 7-day, 30-day, and 90-day windows so
the public page can offer a single timeframe picker. Aggregates only; no raw
events, passwords, messages, full command lines, URLs, or session identifiers.
"""

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
WINDOWS = (("24h", 24, 3600), ("7d", 7, DAY), ("30d", 30, DAY), ("90d", 90, DAY))
COMMAND_TOKEN = re.compile(r"^[A-Za-z0-9_.+-]{1,40}$")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
SEPARATORS = re.compile(r"&&|\|\||[;|&()\r\n]")
WRAPPERS = {"command", "env", "nohup", "sudo", "timeout"}
SHA256 = re.compile(r"[a-fA-F0-9]{64}\Z")
RANK_LIMIT = 10


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


def ranking(rows, limit: int = RANK_LIMIT):
    return [{"label": label, "count": int(count)} for label, count in rows[:limit]]


def columns(db: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in db.execute(f"PRAGMA table_info({table})")}


def build_window(db, now: float, seconds: int, count: int, has_shasum: bool) -> dict:
    start = int(now // seconds) * seconds - (count - 1) * seconds
    args = (start, now)
    totals = db.execute(
        "SELECT "
        "sum(eventid='cowrie.session.connect'),"
        "count(DISTINCT NULLIF(src_ip,'')),"
        "sum(eventid='cowrie.login.success'),"
        "sum(eventid='cowrie.login.failed'),"
        "sum(eventid='cowrie.command.input'),"
        "sum(eventid='cowrie.session.file_download'),"
        "sum(eventid='cowrie.session.file_upload'),"
        "sum(eventid='cowrie.session.file_download.failed') "
        "FROM events WHERE ts>=? AND ts<=?",
        args,
    ).fetchone()
    connections, unique_ips, ok, failed, commands, downloads, uploads, failed_downloads = (
        int(value or 0) for value in totals
    )

    def rank(field, where, limit=RANK_LIMIT):
        rows = db.execute(
            f"SELECT {field},count(*) FROM events WHERE ts>=? AND ts<=? AND {where} "
            f"GROUP BY {field} ORDER BY count(*) DESC,{field} LIMIT ?",
            args + (limit,),
        )
        return list(rows)

    public_sources = [
        (source, count)
        for source, count in db.execute(
            "SELECT src_ip,count(*) FROM events WHERE ts>=? AND ts<=? "
            "AND eventid='cowrie.session.connect' AND src_ip!='' "
            "GROUP BY src_ip ORDER BY count(*) DESC,src_ip",
            args,
        )
        if public_ip(source)
    ]
    top_commands = collections.Counter(
        command_name(row[0])
        for row in db.execute(
            "SELECT command FROM events WHERE ts>=? AND ts<=? "
            "AND eventid='cowrie.command.input' AND command!=''",
            args,
        )
    )
    top_hashes = []
    if has_shasum:
        top_hashes = [
            (digest.lower(), count)
            for digest, count in db.execute(
                "SELECT shasum,count(*) FROM events WHERE ts>=? AND ts<=? "
                "AND shasum IS NOT NULL AND shasum!='' GROUP BY shasum "
                "ORDER BY count(*) DESC,shasum LIMIT ?",
                args + (RANK_LIMIT,),
            )
            if SHA256.fullmatch(digest or "")
        ]
    buckets = [0] * count
    for index, total in db.execute(
        "SELECT CAST((ts-?)/? AS INTEGER),count(*) FROM events "
        "WHERE ts>=? AND ts<=? AND eventid='cowrie.session.connect' GROUP BY 1",
        (start, seconds, start, now),
    ):
        if 0 <= index < count:
            buckets[index] = int(total)
    return {
        "totals": {
            "connections": connections,
            "unique_public_ips": len(public_sources),
            "login_attempts": ok + failed,
            "logins_accepted": ok,
            "logins_rejected": failed,
            "commands": commands,
            "downloads": downloads,
            "uploads": uploads,
            "failed_downloads": failed_downloads,
        },
        "top_ips": ranking(public_sources),
        "top_countries": ranking(rank("country", "eventid='cowrie.session.connect'")),
        "top_commands": ranking(top_commands.most_common(RANK_LIMIT)),
        "top_usernames": ranking(rank(
            "username", "eventid IN ('cowrie.login.failed','cowrie.login.success') AND username!=''")),
        "top_hashes": ranking(top_hashes),
        "series": {"start": start, "bucket_seconds": seconds, "counts": buckets},
    }


def build_snapshot(db_path: Path, days: int, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    with connect_readonly(db_path) as db:
        first, last = db.execute("SELECT min(ts),max(ts) FROM events").fetchone()
        if first is None or last is None:
            raise RuntimeError("history database contains no events")
        present = columns(db, "events")
        has_shasum = "shasum" in present
        windows = {}
        for label, count, seconds in WINDOWS:
            if label == "90d" and days != 90:
                count = max(1, days)
            windows[label] = build_window(db, now, seconds, count, has_shasum)
    return {
        "schema_version": 2,
        "generated_at": utc(now),
        "coverage": {"first_observation": utc(first), "last_observation": utc(last)},
        "windows": windows,
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
