# Advanced Internet Audit

This toolkit runs a network-engineer style internet test and writes a report.

## Install Optional Packages

```bash
python3 -m pip install -r requirements.txt
```

The script still runs without these packages, but `psutil` adds interface counters and `speedtest-cli` adds fuller download/upload testing.

## Run

```bash
python3 advanced_internet_audit.py
```

Outputs are written to `internet_audit_report/`:

- `internet_audit_report.md`
- `internet_audit_report.json`
- `internet_audit_capabilities.md`
- `internet_route_map.html`

## Live Route Map

```bash
python3 advanced_internet_audit.py --traceroute-target 8.8.8.8 --watch-interval 20 --watch-iterations 10
```

Open `internet_audit_report/internet_route_map.html` in a browser. It refreshes while the script updates traceroute snapshots.

## Useful Examples

```bash
python3 advanced_internet_audit.py --targets 1.1.1.1 8.8.8.8 google.com --ping-count 20
python3 advanced_internet_audit.py --traceroute-target openai.com --domains openai.com github.com cloudflare.com
python3 advanced_internet_audit.py --skip-speedtest --skip-mtu
```

Only test networks and targets you are allowed to test. Hop geolocation is approximate because ISP registration data often differs from physical router location.

## Interactive Web App

```bash
python3 internet_audit_web.py
```

Open the URL printed in the terminal. The web app provides:

- Background audit jobs with progress timeline
- Low-level controls for ICMP payload size, DNS record types, traceroute mode, probe counts, timeouts, workers, and custom targets
- Live route snapshots
- Route visualization with animated packet flow
- Latency, DNS, and HTTP/TLS charts
- Job history
- Download buttons for JSON, Markdown, capabilities, and HTML map reports
- PNG export for the route canvas

## Advanced Low-Level Examples

```bash
python3 advanced_internet_audit.py --ping-size 1200 --ping-count 20
python3 advanced_internet_audit.py --dns-qtypes A AAAA MX TXT NS --domains example.com cloudflare.com
python3 advanced_internet_audit.py --traceroute-target github.com --traceroute-mode tcp --traceroute-tcp-port 443
```

Some traceroute modes require operating-system support or elevated network permissions. If the OS blocks a mode, the report records the failure instead of crashing.
