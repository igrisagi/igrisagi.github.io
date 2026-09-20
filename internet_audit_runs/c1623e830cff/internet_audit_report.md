# Advanced Internet Audit Report

Generated: `2026-09-19T08:22:33+00:00`

## Executive Findings

- High average latency to cloudflare.com: 243.4 ms.
- High jitter to cloudflare.com: 32.6 ms. Real-time voice/video/gaming may feel unstable.

## Identity

- Hostname: `e`
- Local IP: `192.168.1.36`
- Public IP: `120.56.153.212`
- Default gateway: `192.168.1.1` on `wlo1`
- Platform: `Linux-7.2.4-arch1-2-x86_64-with-glibc2.44`

## Speed

- Engine: `fallback-http-download`
- Download: `37.03 Mbps`
- Upload: `n/a`
- Ping: `n/a`

## Latency And Loss

| Target | Sent | Recv | Loss | Avg | P95 | Jitter |
| --- | --- | --- | --- | --- | --- | --- |
| 8.8.8.8 | 8 | 8 | 0.0% | 10.1 ms | 14.1 ms | 2.4 ms |
| 1.1.1.1 | 8 | 8 | 0.0% | 15.2 ms | 19.6 ms | 2.7 ms |
| google.com | 8 | 8 | 0.0% | 11.4 ms | 12.2 ms | 0.5 ms |
| cloudflare.com | 8 | 8 | 0.0% | 243.4 ms | 284.9 ms | 32.6 ms |

## TCP Connect

| Target | Success | Attempts | Avg Connect |
| --- | --- | --- | --- |
| google.com:443 | 3 | 3 | 44.7 ms |
| 1.1.1.1:53 | 3 | 3 | 14.1 ms |
| cloudflare.com:443 | 3 | 3 | 266.5 ms |
| github.com:443 | 3 | 3 | 68.0 ms |
| 8.8.8.8:53 | 3 | 3 | 113.1 ms |

## DNS

| Domain | Resolver | Type | OK | Time | Answers |
| --- | --- | --- | --- | --- | --- |
| openai.com | system | system | yes | 26.7 ms | 104.18.33.45, 172.64.154.211 |
| google.com | system | system | yes | 25.7 ms | 142.251.43.238, 2404:6800:4007:815::200e |
| github.com | system | system | yes | 26.1 ms | 20.207.73.82 |
| cloudflare.com | system | system | yes | 25.7 ms | 104.16.132.229, 104.16.133.229, 2606:4700::6810:84e5 |
| cloudflare.com | 1.1.1.1 | A | yes | 15.2 ms | 104.16.133.229, 104.16.132.229 |
| cloudflare.com | 1.1.1.1 | AAAA | yes | 15.7 ms | 2606:4700::6810:84e5, 2606:4700::6810:85e5 |
| cloudflare.com | 8.8.8.8 | A | yes | 48.7 ms | 104.16.132.229, 104.16.133.229 |
| cloudflare.com | 8.8.8.8 | AAAA | yes | 46.0 ms | 2606:4700::6810:84e5, 2606:4700::6810:85e5 |
| cloudflare.com | 9.9.9.9 | A | yes | 70.0 ms | 104.16.133.229, 104.16.132.229 |
| cloudflare.com | 9.9.9.9 | AAAA | yes | 63.6 ms | 2606:4700::6810:85e5, 2606:4700::6810:84e5 |
| google.com | 1.1.1.1 | A | yes | 16.3 ms | 142.250.67.46 |
| google.com | 1.1.1.1 | AAAA | yes | 14.5 ms | 2404:6800:4007:821::200e |
| google.com | 8.8.8.8 | A | yes | 13.5 ms | 142.250.206.14 |
| google.com | 8.8.8.8 | AAAA | yes | 12.4 ms | 2404:6800:4007:834::200e |
| google.com | 9.9.9.9 | A | yes | 88.6 ms | 142.250.197.46 |
| google.com | 9.9.9.9 | AAAA | yes | 80.5 ms | 2404:6800:4005:825::200e |
| github.com | 1.1.1.1 | A | yes | 13.0 ms | 20.207.73.82 |
| github.com | 1.1.1.1 | AAAA | yes | 14.7 ms |  |
| github.com | 8.8.8.8 | A | yes | 43.5 ms | 20.207.73.82 |
| github.com | 8.8.8.8 | AAAA | yes | 14.9 ms |  |
| github.com | 9.9.9.9 | A | yes | 74.0 ms | 20.205.243.166 |
| github.com | 9.9.9.9 | AAAA | yes | 70.1 ms |  |
| openai.com | 1.1.1.1 | A | yes | 14.9 ms | 104.18.33.45, 172.64.154.211 |
| openai.com | 1.1.1.1 | AAAA | yes | 16.2 ms |  |
| openai.com | 8.8.8.8 | A | yes | 15.5 ms | 172.64.154.211, 104.18.33.45 |
| openai.com | 8.8.8.8 | AAAA | yes | 14.5 ms |  |
| openai.com | 9.9.9.9 | A | yes | 78.3 ms | 172.64.154.211, 104.18.33.45 |
| openai.com | 9.9.9.9 | AAAA | yes | 73.5 ms |  |

## HTTP And TLS

| URL | Status | DNS | TCP | TLS | TTFB | Total |
| --- | --- | --- | --- | --- | --- | --- |
| https://www.google.com/generate_204 | 204 | 28.4 ms | 16.6 ms | 72.1 ms | 31.8 ms | 149.4 ms |
| https://www.cloudflare.com/cdn-cgi/trace | 200 | 29.2 ms | 206.0 ms | 219.5 ms | 456.4 ms | 911.4 ms |
| https://github.com/ | 200 | 28.7 ms | 47.7 ms | 77.2 ms | 96.2 ms | 498.3 ms |

## Route

| Hop | IP | RTT | Approx Location | ISP/Org |
| --- | --- | --- | --- | --- |
| 1 | 192.168.1.1 | 1.4 ms | private_or_reserved | n/a |
| 1 | 192.168.1.1 | 1.4 ms | private_or_reserved | n/a |
| 2 | 192.168.1.1 | 1.2 ms | private_or_reserved | n/a |
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
