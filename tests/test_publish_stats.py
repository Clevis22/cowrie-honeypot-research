import datetime as dt
import sqlite3
import tempfile
import unittest
from pathlib import Path

from scripts.publish_stats import build_snapshot, command_name


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
                db.execute("CREATE TABLE events (ts REAL,eventid TEXT,src_ip TEXT,country TEXT,username TEXT,command TEXT)")
                rows = [
                    (now - 20, "cowrie.session.connect", "8.8.8.8", "US", "", ""),
                    (now - 19, "cowrie.login.failed", "8.8.8.8", "US", "root", ""),
                    (now - 18, "cowrie.command.input", "8.8.8.8", "US", "", "curl https://example.test/?secret=yes"),
                    (now - 17, "cowrie.session.file_download", "8.8.8.8", "US", "", ""),
                    (now - 16, "cowrie.session.connect", "192.168.1.5", "ZZ", "", ""),
                ]
                db.executemany("INSERT INTO events VALUES (?,?,?,?,?,?)", rows)
            value = build_snapshot(path, 90, now=now)
            encoded = str(value)
            self.assertEqual(value["totals"]["connections"], 2)
            self.assertEqual(value["totals"]["unique_public_ips"], 1)
            self.assertEqual(value["top_commands"], [{"label": "curl", "count": 1}])
            self.assertNotIn("secret", encoded)
            self.assertNotIn("192.168.1.5", encoded)


if __name__ == "__main__":
    unittest.main()

