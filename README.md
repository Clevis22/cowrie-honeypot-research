# Cowrie honeypot research telemetry

This repository publishes a small, static dashboard of aggregate activity from a research [Cowrie](https://github.com/cowrie/cowrie) SSH honeypot.

**Public dashboard:** https://clevis22.github.io/cowrie-honeypot-research/

The page is intentionally plain HTML, CSS, and JavaScript. It has no framework, analytics, external fonts, runtime API, or third-party client dependency.

## Setup

```text
Internet → Cowrie SSH sensor → local JSON logs
                              ├─ private live dashboard over Tailscale
                              ├─ hourly 90-day SQLite index
                              ├─ private raw-log archive in Cloudflare R2
                              ├─ captured-sample contribution to VirusTotal
                              ├─ AbuseIPDB reports for observed brute-force sources
                              └─ daily sanitized JSON → GitHub Pages
```

The Cowrie sensor runs separately from the public page. Its filesystem and banner are shaped like a small Linux web server so automated sessions can interact with a plausible environment. A private, dependency-free dashboard provides the detailed 24-hour feed, session replay, capture triage, and 7/30-day history. The public page receives only a daily aggregate generated from the local historical index.

Source countries are resolved locally with the DB-IP Lite country database. Raw logs are archived to a private R2 bucket. Captured files may be submitted to a VirusTotal collection for research, but neither sample content nor VirusTotal credentials are part of this repository.

## Public data boundary

`data/stats.json` (recent) holds four fixed windows — 24 hours, 7 days,
30 days, and 90 days. Each window contains:

- totals for connections, unique globally routable source IPs, login attempts
  split into accepted and rejected, commands, downloads, uploads, and failed
  downloads;
- the ten most active public source IPs, country codes, executable names,
  attempted usernames, and captured-file hashes; and
- hourly (24-hour window) or daily connection counts.

The public page shows one timeframe picker spanning these windows plus an
all-time option drawn from `data/alltime.json`.

`data/alltime.json` (all-time, built from the private raw archive) contains:

- all-time totals for connections, unique public IPs (approximate, via a HyperLogLog sketch), login attempts split into accepted and rejected, commands, downloads, uploads, failed downloads, unique captured files, and unique usernames;
- the most common public source IPs, country codes, executable names, attempted usernames, and captured-file SHA-256 hashes;
- connections by hour of day and by weekday, all-time;
- connections per day for the last 180 days and per month for all-time; and
- a compact internal `_state` block (which archives were folded in, counters, and the sketches) so the job is incremental.

Neither file contains raw Cowrie events, attempted passwords, login messages, complete command lines, command arguments, URLs, session identifiers, or captured file contents. The recent exporter reads the bounded SQLite index read-only; the all-time builder reads the private R2 archive read-only. Git history provides a daily record of published aggregates without becoming a log archive.

Exact public source IPs, attempted usernames, and captured-file hashes are included because this is security telemetry. They indicate observed network inputs, not proven identities or locations. VPNs, relays, scanners, and compromised machines may appear in the results. Hash lookups can reveal public reputation data for a sample; no sample is ever stored or served here.

## Daily publisher

[`scripts/publish_stats.py`](scripts/publish_stats.py) uses only the Python standard library. It:

1. reads the local history database in SQLite read-only mode;
2. aggregates fixed 24-hour, 7-day, 30-day, and 90-day windows;
3. discards private IPs and reduces commands to conservative executable labels;
4. atomically replaces `data/stats.json`; and
5. commits and pushes only that file when publishing is enabled.

The included systemd unit runs as an unprivileged `cowrie-stats` user. That user needs read access to the history database and a repository-scoped GitHub deploy key with write access. The timer runs once daily with a randomized delay.

Example one-time export without a Git push:

```sh
python3 scripts/publish_stats.py \
  --db /var/lib/cowrie-ui/history.sqlite \
  --repo "$PWD" \
  --days 90 \
  --export-only
```

Install the service and timer only after cloning this repository to `/opt/cowrie-public-stats/repo` and configuring the deploy key referenced by the unit:

```sh
sudo install -o root -g root -m 0644 deploy/cowrie-public-stats.service /etc/systemd/system/
sudo install -o root -g root -m 0644 deploy/cowrie-public-stats.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cowrie-public-stats.timer
```

## All-time aggregate (GitHub Actions)

Beyond the 90-day recent window, `data/alltime.json` is folded from the private
Cloudflare R2 archive by [`.github/workflows/alltime.yml`](.github/workflows/alltime.yml),
which runs daily and on demand. Only a bounded aggregate is committed; the raw
logs stay in the private bucket. The job is incremental: each run lists the
bucket and processes only archives that are not already recorded in the file's
`_state` block, so a plain and a gzip copy of one rotated log are counted once.

Required repository configuration (Settings → Secrets and variables → Actions):

- secrets `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `R2_BUCKET` — a read-only R2 token;
- optional variable `R2_PREFIX` (defaults to `raw`).

Country lookups use the free, token-free DB-IP Lite CSV, downloaded and cached
by month inside the workflow; no address is sent to any external service.

A local run against a directory of Cowrie logs (no R2 needed):

```sh
python3 scripts/build_alltime.py \
  --state data/alltime.json --geo /path/to/dbip-country-lite-YYYY-MM.csv.gz \
  --local-dir /path/to/logs
```

## Local preview and checks

```sh
python3 -m http.server 8000
python3 -m unittest discover -v
node --check app.js
```

Then open `http://127.0.0.1:8000/`.

## Research limitations

These measurements describe one sensor and should not be generalized to global attack prevalence. Country values are approximate source-IP geolocation, not attacker attribution. Counts can be affected by repeated automation from one address, network address translation, proxy infrastructure, and the sensor's uptime and retention window.

Operate honeypots only on infrastructure you control, isolate them from production systems, retain no more sensitive data than necessary, and follow applicable institutional, legal, and ethical requirements.

## License

Code in this repository is released under the MIT License. Published telemetry is provided for research and educational use without warranties.

