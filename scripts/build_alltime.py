#!/usr/bin/env python3
"""Build the all-time public aggregate from the private R2 log archive.

Runs in CI (see .github/workflows/alltime.yml). It lists the private bucket,
processes only archives that have not been folded in yet, and rewrites
``data/alltime.json``. The file is a bounded set of aggregates: raw logs,
passwords, login messages, URLs, and full command lines never appear.

State (which archives were processed, plus compact counters) lives in the same
file under ``_state`` so runs are incremental and idempotent.
"""

from __future__ import annotations

import argparse
import base64
import collections
import datetime as dt
import gzip
import hashlib
import ipaddress
import json
import math
import re
import shlex
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from geo_lookup import CountryLookup  # noqa: E402
from r2 import Client, Config  # noqa: E402

DAY = 86400
SHA256 = re.compile(r"[a-fA-F0-9]{64}\Z")
COMMAND_TOKEN = re.compile(r"^[A-Za-z0-9_.+-]{1,40}$")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
SEPARATORS = re.compile(r"&&|\|\||[;|&()\r\n]")
WRAPPERS = {"command", "env", "nohup", "sudo", "timeout"}
LOGIN_EVENTS = {"cowrie.login.failed", "cowrie.login.success"}
# Bounded dimension maps: exact top-N is impossible to keep for all time without
# unbounded storage, so maps are pruned to a generous cap and top lists are read
# from the retained head.
MAP_LIMIT = 800
MAP_KEEP = 400
PUBLISH_TOP = 15
DAILY_PUBLISH_LIMIT = 180


def utc(value: float) -> str:
    return dt.datetime.fromtimestamp(value, dt.timezone.utc).isoformat().replace("+00:00", "Z")


def timestamp(value):
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        return parsed.timestamp()
    except (ValueError, TypeError, AttributeError, OverflowError):
        return None


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


class HLL:
    """Small HyperLogLog so all-time unique counts stay bounded and private."""

    P = 12  # 4096 registers: ~16 KB of state per counter, ~1.6% error
    MASK = (1 << 64) - 1

    def __init__(self, registers: bytes | None = None):
        self.m = 1 << self.P
        self.registers = bytearray(registers) if registers and len(registers) == self.m else bytearray(self.m)

    def add(self, value: str) -> None:
        hashed = int.from_bytes(hashlib.blake2b(str(value).encode(), digest_size=8).digest(), "big")
        index = hashed >> (64 - self.P)
        remaining = (hashed << self.P) & self.MASK
        rank = 51 if remaining == 0 else (64 - remaining.bit_length() + 1)
        if rank > self.registers[index]:
            self.registers[index] = rank

    def estimate(self) -> int:
        m = self.m
        alpha = 0.7213 / (1 + 1.079 / m)
        estimate = alpha * m * m / sum(2.0 ** (-r) for r in self.registers)
        if estimate <= 2.5 * m:
            empty = self.registers.count(0)
            if empty:
                estimate = m * math.log(m / empty)
        return int(round(estimate))

    def to_b64(self) -> str:
        return base64.b64encode(bytes(self.registers)).decode()


class Aggregator:
    def __init__(self, state: dict, geo: CountryLookup, now: float):
        self.now = now
        self.geo = geo
        # Shared with the source iterator so a gzip copy of an archive already
        # seen in this run is skipped rather than double counted.
        self.objects: dict[str, dict] = state.setdefault("objects", {})
        self.daily: dict[str, dict] = {
            day: collections.Counter(counts) for day, counts in state.get("daily", {}).items()
        }
        self.hour = list(state.get("hour", [0] * 24))
        self.weekday = list(state.get("weekday", [0] * 7))
        self.totals = collections.Counter(state.get("totals", {}))
        self.maps = {name: collections.Counter(state.get("maps", {}).get(name, {}))
                     for name in ("ips", "countries", "commands", "usernames", "hashes")}
        hll = state.get("hll", {})
        self.unique_ips = HLL(base64.b64decode(hll["ips"]) if hll.get("ips") else None)
        self.unique_hashes = HLL(base64.b64decode(hll["hashes"]) if hll.get("hashes") else None)
        self.unique_users = HLL(base64.b64decode(hll["usernames"]) if hll.get("usernames") else None)
        self.first = state.get("first")
        self.last = state.get("last")

    def ingest(self, raw: bytes) -> None:
        try:
            value = json.loads(raw)
        except (ValueError, TypeError):
            return
        if not isinstance(value, dict):
            return
        ts = timestamp(value.get("timestamp"))
        if ts is None or ts > self.now + 60:
            return
        eventid = value.get("eventid")
        if not isinstance(eventid, str) or not eventid or len(eventid) > 80:
            return
        source = value.get("src_ip")
        source = str(source)[:64] if isinstance(source, (str, int, float)) else ""
        day = utc(ts)[:10]
        bucket = self.daily.setdefault(day, collections.Counter())
        bucket["events"] += 1
        self.first = ts if self.first is None else min(self.first, ts)
        self.last = ts if self.last is None else max(self.last, ts)

        if eventid == "cowrie.session.connect":
            self.totals["connections"] += 1
            bucket["connections"] += 1
            self.hour[int((ts % DAY) // 3600)] += 1
            self.weekday[dt.datetime.fromtimestamp(ts, dt.timezone.utc).weekday()] += 1
            if source:
                country = self.geo.lookup(source)
                self.maps["countries"][country] += 1
                if public_ip(source):
                    self.maps["ips"][source] += 1
                    self.unique_ips.add(source)
        elif eventid in LOGIN_EVENTS:
            key = "logins_ok" if eventid == "cowrie.login.success" else "logins_fail"
            self.totals[key] += 1
            bucket[key] += 1
            username = value.get("username")
            if isinstance(username, (str, int, float)) and str(username):
                self.maps["usernames"][str(username)[:80]] += 1
                self.unique_users.add(str(username)[:80])
        elif eventid == "cowrie.command.input":
            command = value.get("input")
            if isinstance(command, (str, int, float)) and str(command).strip():
                self.totals["commands"] += 1
                bucket["commands"] += 1
                self.maps["commands"][command_name(str(command).strip()[:512])] += 1
        elif eventid == "cowrie.session.file_download":
            self.totals["downloads"] += 1
            bucket["downloads"] += 1
            self._hash(value, "downloads")
        elif eventid == "cowrie.session.file_upload":
            self.totals["uploads"] += 1
            bucket["uploads"] += 1
            self._hash(value, "uploads")
        elif eventid == "cowrie.session.file_download.failed":
            self.totals["failed_downloads"] += 1
            bucket["failed"] += 1

    def _hash(self, value: dict, _kind: str) -> None:
        candidate = value.get("shasum")
        if isinstance(candidate, str) and SHA256.fullmatch(candidate):
            digest = candidate.lower()
            self.maps["hashes"][digest] += 1
            self.unique_hashes.add(digest)

    def prune(self) -> None:
        for name, counter in self.maps.items():
            if len(counter) > MAP_LIMIT:
                self.maps[name] = collections.Counter(dict(counter.most_common(MAP_KEEP)))

    def write(self, path: Path, generated_at: float) -> None:
        self.prune()
        days = sorted(self.daily)
        monthly = collections.Counter()
        for day in days:
            monthly[day[:7]] += self.daily[day]["connections"]
        published_days = days[-DAILY_PUBLISH_LIMIT:]
        first = self.first
        document = {
            "schema_version": 1,
            "generated_at": utc(generated_at),
            "coverage": {
                "first_observation": utc(first) if first else None,
                "last_observation": utc(self.last) if self.last else None,
                "days_observed": len(days),
            },
            "all_time": {
                "connections": self.totals["connections"],
                "unique_public_ips": self.unique_ips.estimate(),
                "unique_hashes": self.unique_hashes.estimate(),
                "unique_usernames": self.unique_users.estimate(),
                "login_attempts": self.totals["logins_ok"] + self.totals["logins_fail"],
                "logins_accepted": self.totals["logins_ok"],
                "logins_rejected": self.totals["logins_fail"],
                "commands": self.totals["commands"],
                "downloads": self.totals["downloads"],
                "uploads": self.totals["uploads"],
                "failed_downloads": self.totals["failed_downloads"],
            },
            "top": {name: [{"label": label, "count": int(count)}
                           for label, count in self.maps[name].most_common(PUBLISH_TOP)]
                    for name in ("ips", "countries", "commands", "usernames", "hashes")},
            "hour_of_day": list(self.hour),
            "weekday": list(self.weekday),
            "daily_connections": [{"date": day, "count": int(self.daily[day]["connections"])}
                                  for day in published_days],
            "monthly_connections": [{"month": month, "count": int(monthly[month])}
                                    for month in sorted(monthly)],
            "_state": {
                "objects": self.objects,
                "daily": {day: {k: int(v) for k, v in counts.items()} for day, counts in self.daily.items()},
                "hour": list(self.hour),
                "weekday": list(self.weekday),
                "totals": {k: int(v) for k, v in self.totals.items()},
                "maps": {name: dict(counter) for name, counter in self.maps.items()},
                "hll": {"ips": self.unique_ips.to_b64(), "hashes": self.unique_hashes.to_b64(),
                        "usernames": self.unique_users.to_b64()},
                "first": first,
                "last": self.last,
            },
        }
        document["_state"] = {k: v for k, v in document["_state"].items() if v is not None}
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(json.dumps(document, indent=2, sort_keys=False) + "\n", encoding="utf-8")
        temporary.replace(path)


OBJECT_PREFIX = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{16}-")


def logical_name(key: str) -> str:
    """Strip the R2 object prefix and any compression suffix.

    R2 keys look like ``raw/<sensor>/YYYY/MM/DD/<ts>-<digest16>-<filename>``;
    local files are just ``<filename>``. Collapsing both to the original Cowrie
    filename lets a plain and a gzip copy of one log dedupe to a single archive.
    """
    name = OBJECT_PREFIX.sub("", key.rsplit("/", 1)[-1])
    return name[:-3] if name.endswith(".gz") else name


def load_state(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("_state", {})
    except (OSError, ValueError):
        return {}


def iter_r2(prefix: str, state: dict):
    client = Client(Config.from_environment())
    known = state.get("objects", {})
    for item in client.list_objects(prefix):
        name = logical_name(item["key"])
        # A logical log is folded in once; a later gzip copy is the same data.
        if name in known:
            continue
        yield name, item, client.open(item["key"])


def iter_local(directory: Path, state: dict):
    known = state.get("objects", {})
    for path in sorted(directory.glob("cowrie.json.*")):
        name = logical_name(path.name)
        if name in known:
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        # Raw bytes; process() handles gzip transparently from the key suffix.
        yield name, {"key": str(path), "etag": digest, "size": path.stat().st_size}, open(path, "rb")


def process(name: str, item: dict, stream, aggregator: Aggregator) -> int:
    count = 0
    if item["key"].endswith(".gz"):
        stream = gzip.GzipFile(fileobj=stream)
    with stream:
        for raw in stream:
            count += 1
            aggregator.ingest(raw)
    aggregator.objects[name] = {"key": item["key"], "etag": item["etag"]}
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=Path("data/alltime.json"))
    parser.add_argument("--geo", type=Path, required=True)
    parser.add_argument("--prefix", default=None)
    parser.add_argument("--local-dir", type=Path, help="read log files from a directory instead of R2")
    parser.add_argument("--max-objects", type=int, default=0, help="process at most N new objects")
    args = parser.parse_args()

    now = time.time()
    state = load_state(args.state)
    geo = CountryLookup.from_csv(args.geo)
    aggregator = Aggregator(state, geo, now)
    processed = 0
    source = iter_local(args.local_dir, state) if args.local_dir else iter_r2(args.prefix, state)
    for name, item, stream in source:
        process(name, item, stream, aggregator)
        processed += 1
        print(f"processed {name} ({item['size']} bytes)")
        if args.max_objects and processed >= args.max_objects:
            break
    aggregator.write(args.state, now)
    print(f"wrote {args.state} after {processed} new archive(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
