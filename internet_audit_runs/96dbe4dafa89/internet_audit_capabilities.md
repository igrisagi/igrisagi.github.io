# Internet Audit Capabilities

- Public IP discovery and local machine/network identity
- Operating system, Python runtime, hostname, local IP, and default gateway detection
- Interface counters and interface status when psutil is installed
- ICMP latency, packet loss, minimum/average/maximum RTT, and jitter estimation
- TCP connection latency to common service ports
- DNS timing using the operating system resolver
- Direct UDP DNS resolver checks against 1.1.1.1, 8.8.8.8, and 9.9.9.9
- Low-level DNS record type checks for A, AAAA, CNAME, MX, TXT, NS, and PTR
- Custom ICMP ping payload size for packet-size and path sensitivity checks
- HTTP and HTTPS timing split into DNS, TCP connect, TLS handshake, TTFB, and total time
- Optional Ookla-style speed test when speedtest-cli is installed
- Fallback HTTP download throughput test when speedtest-cli is unavailable
- Traceroute or tracert hop discovery
- Traceroute probe mode selection where supported: UDP, ICMP, or TCP
- Public-hop geolocation for route visualization
- Interactive HTML world map with hop markers and route polyline
- Watch mode for repeated traceroute snapshots and auto-refreshing route map
- IPv4 path MTU probing where the local ping command supports do-not-fragment flags
- Automated findings with network-engineer style thresholds
- JSON report for machines and Markdown report for humans

Recommended optional packages: `speedtest-cli` for fuller speed tests and `psutil` for interface counters.