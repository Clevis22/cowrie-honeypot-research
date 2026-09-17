#!/usr/bin/env python3
"""In-memory country lookup from a DB-IP Lite CSV, stdlib only.

The CSV is the free CC BY 4.0 DB-IP Lite country database; only the ranges for
that release are read, and no address is sent to any external service.
"""

from __future__ import annotations

import bisect
import gzip
import ipaddress
from pathlib import Path


class CountryLookup:
    def __init__(self, starts: list[int], ends: list[int], codes: list[str]):
        self.starts = starts
        self.ends = ends
        self.codes = codes
        self.available = bool(starts)

    @classmethod
    def from_csv(cls, path: str | Path) -> "CountryLookup":
        opener = gzip.open if str(path).endswith(".gz") else open
        starts: list[int] = []
        ends: list[int] = []
        codes: list[str] = []
        with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                parts = line.rstrip("\n").split(",")
                if len(parts) != 3:
                    continue
                start, end, code = (part.strip().strip('"') for part in parts)
                if not code or len(code) > 2:
                    continue
                try:
                    starts.append(int(ipaddress.ip_address(start)))
                    ends.append(int(ipaddress.ip_address(end)))
                except ValueError:
                    continue
                codes.append(code)
        order = sorted(range(len(starts)), key=starts.__getitem__)
        return cls([starts[i] for i in order], [ends[i] for i in order], [codes[i] for i in order])

    def lookup(self, value: str) -> str:
        if not value:
            return "ZZ"
        try:
            address = int(ipaddress.ip_address(value))
        except ValueError:
            return "ZZ"
        index = bisect.bisect_right(self.starts, address) - 1
        if index >= 0 and address <= self.ends[index]:
            return self.codes[index]
        return "ZZ"
