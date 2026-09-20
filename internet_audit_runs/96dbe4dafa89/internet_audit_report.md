# Advanced Internet Audit Report

Generated: `2026-09-19T08:30:12+00:00`

## Executive Findings

- High average latency to cloudflare.com: 250.8 ms.
- High jitter to cloudflare.com: 47.9 ms. Real-time voice/video/gaming may feel unstable.

## Identity

- Hostname: `e`
- Local IP: `192.168.1.36`
- Public IP: `120.56.153.212`
- Default gateway: `192.168.1.1` on `wlo1`
- Platform: `Linux-7.2.4-arch1-2-x86_64-with-glibc2.44`

## Speed

- Engine: `fallback-http-download`
- Download: `23.39 Mbps`
- Upload: `n/a`
- Ping: `n/a`

## Latency And Loss

| Target | Sent | Recv | Loss | Avg | P95 | Jitter |
| --- | --- | --- | --- | --- | --- | --- |
| 8.8.8.8 | 8 | 8 | 0.0% | 9.5 ms | 9.8 ms | 0.4 ms |
| 1.1.1.1 | 8 | 8 | 0.0% | 14.3 ms | 15.0 ms | 1.0 ms |
| google.com | 8 | 8 | 0.0% | 11.8 ms | 13.6 ms | 1.3 ms |
| cloudflare.com | 8 | 8 | 0.0% | 250.8 ms | 298.4 ms | 47.9 ms |

## TCP Connect

| Target | Success | Attempts | Avg Connect |
| --- | --- | --- | --- |
| github.com:443 | 3 | 3 | 63.8 ms |
| 1.1.1.1:53 | 3 | 3 | 353.3 ms |
| google.com:443 | 3 | 3 | 39.3 ms |
| cloudflare.com:443 | 3 | 3 | 643.3 ms |
| 8.8.8.8:53 | 3 | 3 | 13.5 ms |

## DNS

| Domain | Resolver | Type | OK | Time | Answers |
| --- | --- | --- | --- | --- | --- |
| openai.com | system | system | yes | 35.9 ms | 104.18.33.45, 172.64.154.211 |
| google.com | system | system | yes | 24.2 ms | 142.250.183.174, 2404:6800:4007:815::200e |
| github.com | system | system | yes | 21.6 ms | 20.207.73.82 |
| cloudflare.com | system | system | yes | 22.6 ms | 104.16.132.229, 104.16.133.229, 2606:4700::6810:84e5 |
| cloudflare.com | 1.1.1.1 | A | yes | 32.6 ms | 104.16.132.229, 104.16.133.229 |
| cloudflare.com | 1.1.1.1 | AAAA | yes | 35.2 ms | 2606:4700::6810:84e5, 2606:4700::6810:85e5 |
| cloudflare.com | 8.8.8.8 | A | yes | 57.9 ms | 104.16.132.229, 104.16.133.229 |
| cloudflare.com | 8.8.8.8 | AAAA | yes | 48.8 ms | 2606:4700::6810:84e5, 2606:4700::6810:85e5 |
| cloudflare.com | 9.9.9.9 | A | yes | 81.9 ms | 104.16.133.229, 104.16.132.229 |
| cloudflare.com | 9.9.9.9 | AAAA | yes | 159.9 ms | 2606:4700::6810:85e5, 2606:4700::6810:84e5 |
| google.com | 1.1.1.1 | A | yes | 15.6 ms | 142.250.205.142 |
| google.com | 1.1.1.1 | AAAA | yes | 13.4 ms | 2404:6800:4007:805::200e |
| google.com | 8.8.8.8 | A | yes | 39.1 ms | 142.251.223.238 |
| google.com | 8.8.8.8 | AAAA | yes | 135.9 ms | 2404:6800:4007:836::200e |
| google.com | 9.9.9.9 | A | yes | 82.5 ms | 142.250.197.238 |
| google.com | 9.9.9.9 | AAAA | yes | 121.7 ms | 2404:6800:4005:805::200e |
| github.com | 1.1.1.1 | A | yes | 14.5 ms | 20.207.73.82 |
| github.com | 1.1.1.1 | AAAA | yes | 16.6 ms |  |
| github.com | 8.8.8.8 | A | yes | 42.0 ms | 20.207.73.82 |
| github.com | 8.8.8.8 | AAAA | yes | 10.5 ms |  |
| github.com | 9.9.9.9 | A | yes | 119.6 ms | 20.205.243.166 |
| github.com | 9.9.9.9 | AAAA | yes | 96.2 ms |  |
| openai.com | 1.1.1.1 | A | yes | 15.4 ms | 172.64.154.211, 104.18.33.45 |
| openai.com | 1.1.1.1 | AAAA | yes | 15.5 ms |  |
| openai.com | 8.8.8.8 | A | yes | 11.6 ms | 104.18.33.45, 172.64.154.211 |
| openai.com | 8.8.8.8 | AAAA | yes | 14.3 ms |  |
| openai.com | 9.9.9.9 | A | yes | 98.9 ms | 172.64.154.211, 104.18.33.45 |
| openai.com | 9.9.9.9 | AAAA | yes | 96.3 ms |  |

## HTTP And TLS

| URL | Status | DNS | TCP | TLS | TTFB | Total |
| --- | --- | --- | --- | --- | --- | --- |
| https://www.google.com/generate_204 | 204 | 24.5 ms | 10.3 ms | 40.0 ms | 30.4 ms | 105.5 ms |
| https://github.com/ | 200 | 23.4 ms | 34.5 ms | 63.8 ms | 72.9 ms | 379.9 ms |
| https://www.cloudflare.com/cdn-cgi/trace | 200 | 27.4 ms | 212.7 ms | 228.6 ms | 623.9 ms | 1092.8 ms |

## Route

| Hop | IP | RTT | Approx Location | ISP/Org |
| --- | --- | --- | --- | --- |
| 1 | 192.168.1.1 | 4.1 ms | private_or_reserved | n/a |
| 1 | 192.168.1.1 | 9.5 ms | private_or_reserved | n/a |
| 2 | 192.168.1.1 | 2.3 ms | private_or_reserved | n/a |
| 2 | None | n/a | n/a | n/a |
| 3 | None | n/a | n/a | n/a |
| 4 | None | n/a | n/a | n/a |
| 5 | None | n/a | n/a | n/a |
| 6 | None | n/a | n/a | n/a |
| 7 | None | n/a | n/a | n/a |
| 8 | None | n/a | n/a | n/a |
| 9 | None | n/a | n/a | n/a |
| 10 | None | n/a | n/a | n/a |
| 11 | None | n/a | n/a | n/a |
| 12 | None | n/a | n/a | n/a |
| 13 | None | n/a | n/a | n/a |
| 14 | None | n/a | n/a | n/a |
| 15 | None | n/a | n/a | n/a |
| 16 | None | n/a | n/a | n/a |
| 17 | None | n/a | n/a | n/a |
| 18 | None | n/a | n/a | n/a |
| 19 | None | n/a | n/a | n/a |
| 20 | None | n/a | n/a | n/a |
| 21 | None | n/a | n/a | n/a |
| 22 | None | n/a | n/a | n/a |
| 23 | None | n/a | n/a | n/a |
| 24 | None | n/a | n/a | n/a |
| 25 | None | n/a | n/a | n/a |
| 26 | None | n/a | n/a | n/a |
| 27 | None | n/a | n/a | n/a |
| 28 | None | n/a | n/a | n/a |
| 29 | None | n/a | n/a | n/a |
| 30 | None | n/a | n/a | n/a |

Interactive route map: `internet_route_map.html`

## MTU

- Target: `1.1.1.1`
- Estimated IPv4 path MTU: `1492`

## Capabilities

See `internet_audit_capabilities.md` for the separate capabilities list.
