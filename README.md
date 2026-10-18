# port-scanner-lite

[![CI](https://github.com/AJJudkins/port-scanner-lite/actions/workflows/ci.yml/badge.svg)](https://github.com/AJJudkins/port-scanner-lite/actions/workflows/ci.yml)

A small, readable TCP connect scanner written in Python with only the standard library. It defaults to **localhost**, maps ports to service names, and outputs a table, CSV, or JSON.

> **Authorized use only.** Scan only systems you own or have explicit written permission to test. By default this tool targets `127.0.0.1`; any other host requires the `--i-am-authorized` flag. Unauthorized scanning may be illegal.

## Problem
Quick checks of "what is listening on this machine?" are a daily admin task. This shows how a basic scanner works without heavy tools.

## How it works
```mermaid
flowchart LR
    A[CLI args: host, ports] --> B[parse_ports]
    B --> C[thread pool]
    C --> D[socket.create_connection per port]
    D --> E[open / closed + service name]
    E --> F[table / CSV / JSON]
```

## Setup
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install pytest
pytest
```

## Usage
```bash
python scanner.py                                  # localhost, ports 1-1024
python scanner.py --ports 22,80,443,8000-8100 --format json
python scanner.py --ports 1-1024 --format csv > results.csv
python scanner.py --host 192.0.2.5 --ports 22,80 --i-am-authorized   # only if permitted
```

## Sample output
```
127.0.0.1:22     open    ssh
127.0.0.1:631    open    ipp
```
(Results depend on what is running on your machine.)

## Limitations
- TCP connect scan only (no SYN/UDP scanning, no banner grabbing, no OS detection).
- Service names come from the OS services database and are guesses based on port number, not on what is actually running.

## What it demonstrates
Socket programming, concurrency with a thread pool, input validation, safe-by-default CLI design, and testing network code against local listeners.

## Hardening notes
- Non-local hosts need `--i-am-authorized`, and are capped at 1024 ports per run.
- Ports, `--timeout` (0-10 s) and `--workers` (1-200) are validated; invalid input exits with code 2 and a usage message instead of a traceback.
- Console script after `pip install -e .`: `port-scanner-lite --ports 22,80`.

## Security and testing status

- **Safety:** defaults to 127.0.0.1; scanning any other host requires `--i-am-authorized` and is limited to 1024 ports; TCP connect only, no payloads, bounded workers and timeouts. Only scan systems you own or have written permission to test.
- **Tested:** port parsing, validation, authorization gate and scanning against local listeners on 127.0.0.1.
- **Not tested:** scanning any remote host or network, IPv6 hosts beyond `::1`, behavior behind firewalls or rate limiters, and performance on large ranges.
- See [SECURITY.md](SECURITY.md).

## License
MIT
