import datetime as dt
import sqlite3
import tempfile
import unittest
from pathlib import Path

from scripts.publish_stats import build_snapshot, command_name

DIGEST = "a" * 64


class PublishStatsTests(unittest.TestCase):
    def test_command_name_never_returns_arguments(self):
        self.assertEqual(command_name("curl -fsSL https://example.test/a?token=secret"), "curl")
        self.assertEqual(command_name("A=1 sudo -n /usr/bin/wget http://example.test/x"), "wget")
        self.assertEqual(command_name("busybox uname -a; echo secret"), "uname")
        self.assertEqual(command_name("'unterminated"), "other")

    def test_snapshot_contains_only_aggregates(self):
        now = dt.datetime(2026, 9, 16, 12, tzinfo=dt.timezone.utc).timestamp()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "history.sqlite"
            with sqlite3.connect(path) as db:
                db.execute(
                    "CREATE TABLE events (ts REAL,eventid TEXT,src_ip TEXT,country TEXT,"
                    "username TEXT,command TEXT,shasum TEXT)"
                )
                rows = [
                    (now - 20, "cowrie.session.connect", "8.8.8.8", "US", "", "", ""),
                    (now - 19, "cowrie.login.failed", "8.8.8.8", "US", "root", "", ""),
                    (now - 18, "cowrie.command.input", "8.8.8.8", "US", "", "curl https://example.test/?secret=yes", ""),
                    (now - 17, "cowrie.session.file_download", "8.8.8.8", "US", "", "", DIGEST),
                    (now - 16, "cowrie.session.file_download", "8.8.8.8", "US", "", "", "not-a-hash"),
                    (now - 15, "cowrie.session.connect", "192.168.1.5", "ZZ", "", "", ""),
                ]
                db.executemany("INSERT INTO events VALUES (?,?,?,?,?,?,?)", rows)
            value = build_snapshot(path, 90, now=now)
            self.assertEqual(set(value["windows"]), {"24h", "7d", "30d", "90d"})
            window = value["windows"]["90d"]
            self.assertEqual(window["totals"]["connections"], 2)
            self.assertEqual(window["totals"]["unique_public_ips"], 1)
            self.assertEqual(window["totals"]["logins_rejected"], 1)
            self.assertEqual(window["totals"]["downloads"], 2)
            self.assertEqual(window["top_commands"], [{"label": "curl", "count": 1}])
            self.assertEqual(window["top_hashes"], [{"label": DIGEST, "count": 1}])
            self.assertEqual(window["top_usernames"], [{"label": "root", "count": 1}])
            self.assertEqual(len(window["series"]["counts"]), 90)
            encoded = str(value)
            self.assertNotIn("secret", encoded)
            self.assertNotIn("192.168.1.5", encoded)
            self.assertNotIn("not-a-hash", encoded)

    def test_snapshot_without_shasum_column(self):
        now = dt.datetime(2026, 9, 16, 12, tzinfo=dt.timezone.utc).timestamp()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "history.sqlite"
            with sqlite3.connect(path) as db:
                db.execute("CREATE TABLE events (ts REAL,eventid TEXT,src_ip TEXT,country TEXT,username TEXT,command TEXT)")
                db.execute("INSERT INTO events VALUES (?,?,?,?,?,?)", (now - 5, "cowrie.session.connect", "8.8.8.8", "US", "", ""))
            value = build_snapshot(path, 90, now=now)
            self.assertEqual(value["windows"]["24h"]["top_hashes"], [])
            self.assertEqual(value["windows"]["24h"]["totals"]["connections"], 1)


if __name__ == "__main__":
    unittest.main()
