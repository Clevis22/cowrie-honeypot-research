import gzip
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.build_alltime import Aggregator, iter_local, logical_name, process


class FakeGeo:
    def lookup(self, value):
        return "US" if value.startswith("8.8.") else "ZZ"


def line(day, hour, eventid, src="8.8.8.8", **values):
    stamp = datetime(2026, 9, day, hour, 0, 0, tzinfo=timezone.utc).isoformat()
    record = {"timestamp": stamp, "eventid": eventid, "src_ip": src, "session": "s"}
    record.update(values)
    return json.dumps(record).encode() + b"\n"


class BuildAlltimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.logs = self.root / "logs"
        self.logs.mkdir()
        self.state = self.root / "alltime.json"

    def build(self):
        state = json.loads(self.state.read_text())["_state"] if self.state.is_file() else {}
        aggregator = Aggregator(state, FakeGeo(), datetime(2026, 9, 30, tzinfo=timezone.utc).timestamp())
        processed = 0
        for name, item, stream in iter_local(self.logs, state):
            process(name, item, stream, aggregator)
            processed += 1
        aggregator.write(self.state, datetime(2026, 9, 30, tzinfo=timezone.utc).timestamp())
        return processed

    def test_aggregates_dedupe_and_sanitization(self):
        (self.logs / "cowrie.json.2026-09-14").write_bytes(
            line(14, 3, "cowrie.session.connect", src="8.8.8.8")
            + line(14, 3, "cowrie.login.success", src="8.8.8.8", username="root", password="SECRET")
            + line(14, 4, "cowrie.login.failed", src="8.8.8.8", username="admin", password="SECRET")
            + line(14, 4, "cowrie.command.input", src="8.8.8.8", input="curl -fsSL https://example.test/?token=SECRET")
            + line(14, 5, "cowrie.session.file_download", src="8.8.8.8", shasum="a" * 64)
            + line(14, 5, "cowrie.session.file_upload", src="8.8.8.8", shasum="b" * 64)
        )
        (self.logs / "cowrie.json.2026-09-15").write_bytes(
            line(15, 23, "cowrie.session.connect", src="1.2.3.4")
            + line(15, 23, "cowrie.login.failed", src="1.2.3.4", username="root")
        )
        # A compressed copy of the same logical log must not double count.
        with gzip.open(self.logs / "cowrie.json.2026-09-14.gz", "wb") as handle:
            handle.write((self.logs / "cowrie.json.2026-09-14").read_bytes())
        self.assertEqual(self.build(), 2)
        self.assertEqual(self.build(), 0)  # idempotent

        document = json.loads(self.state.read_text())
        totals = document["all_time"]
        self.assertEqual(totals["connections"], 2)
        self.assertEqual(totals["logins_accepted"], 1)
        self.assertEqual(totals["logins_rejected"], 2)
        self.assertEqual(totals["commands"], 1)
        self.assertEqual(totals["downloads"], 1)
        self.assertEqual(totals["uploads"], 1)
        self.assertEqual(totals["unique_public_ips"], 2)
        self.assertEqual(totals["unique_hashes"], 2)
        self.assertEqual({row["label"] for row in document["top"]["hashes"]}, {"a" * 64, "b" * 64})
        self.assertEqual([row["label"] for row in document["top"]["commands"]], ["curl"])
        self.assertEqual({row["label"] for row in document["top"]["usernames"]}, {"root", "admin"})
        # private addresses never enter the public IP list
        self.assertNotIn("192.168.1.5", str(document["top"]["ips"]))
        # never publish secrets or full command lines
        encoded = json.dumps(document)
        self.assertNotIn("SECRET", encoded)
        self.assertNotIn("example.test", encoded)
        self.assertEqual(sum(document["hour_of_day"]), 2)
        self.assertEqual(sum(document["weekday"]), 2)
        self.assertEqual([row["count"] for row in document["monthly_connections"]], [2])

    def test_logical_name_dedupes_compression(self):
        self.assertEqual(
            logical_name("raw/s/2026/09/14/20260914T235800Z-a00a08b8ab1eb36b-cowrie.json.2026-09-14"),
            "cowrie.json.2026-09-14",
        )
        self.assertEqual(
            logical_name("raw/s/2026/09/14/20260914T235800Z-a00a08b8ab1eb36b-cowrie.json.2026-09-14.gz"),
            "cowrie.json.2026-09-14",
        )


if __name__ == "__main__":
    unittest.main()
