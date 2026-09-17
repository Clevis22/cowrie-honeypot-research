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
                              └─ daily sanitized JSON → GitHub Pages
```

The Cowrie sensor runs separately from the public page. Its filesystem and banner are shaped like a small Linux web server so automated sessions can interact with a plausible environment. A private, dependency-free dashboard provides the detailed 24-hour feed, session replay, capture triage, and 7/30-day history. The public page receives only a daily aggregate generated from the local historical index.

Source countries are resolved locally with the DB-IP Lite country database. Raw logs are archived to a private R2 bucket. Captured files may be submitted to a VirusTotal collection for research, but neither sample content nor VirusTotal credentials are part of this repository.

## Public data boundary

`data/stats.json` contains:

- totals for connections, unique globally routable source IPs, login attempts, commands, downloads, and uploads;
- the ten most active public source IPs and country codes;
- the ten most common executable names, such as `curl` or `wget`;
- daily connection counts for the latest 30 days; and
- generation and coverage timestamps.

It never contains raw Cowrie events, attempted passwords, usernames, full command lines, command arguments, URLs, session identifiers, captured file contents, hashes, or private/non-routable IP addresses. The exporter reads the bounded SQLite index read-only and writes one fixed-schema JSON file. Git history provides a daily record of published snapshots without becoming a log archive.

Exact public source IPs are included because this is security telemetry. They indicate observed network sources, not proven identities or locations. VPNs, relays, scanners, and compromised machines may appear in the results.

## Daily publisher

[`scripts/publish_stats.py`](scripts/publish_stats.py) uses only the Python standard library. It:

1. reads the local history database in SQLite read-only mode;
2. aggregates a rolling window of at most 90 days;
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

