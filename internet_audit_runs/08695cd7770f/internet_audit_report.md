# Advanced Internet Audit Report

Generated: `2026-09-19T08:10:15+00:00`

## Executive Findings

- HTTP test failed for http://127.0.0.1: [Errno 111] Connection refused

## Identity

- Hostname: `e`
- Local IP: `192.168.1.36`
- Public IP: `120.56.153.212`
- Default gateway: `192.168.1.1` on `wlo1`
- Platform: `Linux-7.2.4-arch1-2-x86_64-with-glibc2.44`

## Speed

- Engine: `n/a`
- Download: `n/a`
- Upload: `n/a`
- Ping: `n/a`

## Latency And Loss

| Target | Sent | Recv | Loss | Avg | P95 | Jitter |
| --- | --- | --- | --- | --- | --- | --- |
| 127.0.0.1 | 1 | 1 | 0.0% | 0.0 ms | 0.0 ms | n/a |

## TCP Connect

| Target | Success | Attempts | Avg Connect |
| --- | --- | --- | --- |
| 127.0.0.1:80 | 0 | 1 | n/a |

## DNS

| Domain | Resolver | Type | OK | Time | Answers |
| --- | --- | --- | --- | --- | --- |
| localhost | system | system | yes | 0.2 ms | 127.0.0.1, ::1 |
| localhost | 127.0.0.1 | A | no | 1001.1 ms |  |
| localhost | 127.0.0.1 | AAAA | no | 1000.6 ms |  |
| localhost | 127.0.0.1 | TXT | no | 1000.7 ms |  |

## HTTP And TLS

| URL | Status | DNS | TCP | TLS | TTFB | Total |
| --- | --- | --- | --- | --- | --- | --- |
| http://127.0.0.1 | n/a | 0.0 ms | n/a | n/a | n/a | 0.1 ms |

## Route

| Hop | IP | RTT | Approx Location | ISP/Org |
| --- | --- | --- | --- | --- |

Interactive route map: `internet_route_map.html`

## MTU

- Target: `None`
- Estimated IPv4 path MTU: `n/a`

## Capabilities

See `internet_audit_capabilities.md` for the separate capabilities list.
