# Security policy

## Scope and safety
defaults to 127.0.0.1; scanning any other host requires `--i-am-authorized` and is limited to 1024 ports; TCP connect only, no payloads, bounded workers and timeouts. Only scan systems you own or have written permission to test.

## What was and was not tested
**Tested (automated, in CI and locally):** port parsing, validation, authorization gate and scanning against local listeners on 127.0.0.1.

**Not tested:** scanning any remote host or network, IPv6 hosts beyond `::1`, behavior behind firewalls or rate limiters, and performance on large ranges.

## Reporting a problem
This is a small personal portfolio project, not a supported product. If you find a security issue, please open a GitHub issue **without** secrets, credentials or real system details, or use GitHub's "Report a vulnerability" button on the Security tab if it is enabled.
