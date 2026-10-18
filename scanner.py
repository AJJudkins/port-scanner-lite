"""Simple TCP connect scanner. Defaults to localhost. Authorized use only."""
import argparse
import csv
import io
import json
import socket
from concurrent.futures import ThreadPoolExecutor

LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")
MAX_WORKERS = 200
MAX_REMOTE_PORTS = 1024


def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def parse_ports(spec):
    """Parse '22,80,8000-8010' into a sorted list of unique ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            if lo < 1 or hi > 65535:
                raise ValueError(f"port out of range: {part}")
            if lo > hi:
                raise ValueError(f"bad range: {part}")
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
            if not 1 <= int(part) <= 65535:
                raise ValueError(f"port out of range: {part}")
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("ports must be in 1-65535")
    return sorted(ports)


def check_port(host, port, timeout=0.5):
    """Return True if a TCP connection succeeds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan(host, ports, timeout=0.5, workers=50, show_closed=False):
    with ThreadPoolExecutor(max_workers=workers) as ex:
        states = list(ex.map(lambda p: check_port(host, p, timeout), ports))
    rows = [{"host": host, "port": p, "state": "open" if s else "closed", "service": service_name(p)}
            for p, s in zip(ports, states)]
    return rows if show_closed else [r for r in rows if r["state"] == "open"]


def to_json(rows):
    return json.dumps(rows, indent=2)


def to_csv(rows):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=["host", "port", "state", "service"], lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue()


def to_table(rows):
    if not rows:
        return "No open ports found."
    return "\n".join(f"{r['host']}:{r['port']:<6} {r['state']:<7} {r['service']}" for r in rows)


def main(argv=None):  # returns None (exit 0) on success; argparse errors exit 2
    ap = argparse.ArgumentParser(description="Lightweight TCP port scanner (authorized use only).")
    ap.add_argument("--host", default="127.0.0.1", help="target host (default: 127.0.0.1)")
    ap.add_argument("--ports", default="1-1024", help="e.g. 22,80,8000-8100 (default: 1-1024)")
    ap.add_argument("--timeout", type=float, default=0.5, help="seconds per connection (0-10)")
    ap.add_argument("--workers", type=int, default=50, help="parallel connections (1-%d)" % MAX_WORKERS)
    ap.add_argument("--format", choices=["table", "csv", "json"], default="table")
    ap.add_argument("--show-closed", action="store_true")
    ap.add_argument("--i-am-authorized", action="store_true",
                    help="required to scan any host other than localhost")
    a = ap.parse_args(argv)
    if a.host not in LOCAL_HOSTS and not a.i_am_authorized:
        ap.error("scanning a non-local host requires --i-am-authorized (only scan systems you own or have permission to test)")
    if not 0 < a.timeout <= 10:
        ap.error("--timeout must be in (0, 10]")
    if not 1 <= a.workers <= MAX_WORKERS:
        ap.error(f"--workers must be 1-{MAX_WORKERS}")
    try:
        ports = parse_ports(a.ports)
    except ValueError as e:
        ap.error(f"invalid --ports: {e}")
    if a.host in LOCAL_HOSTS:
        pass
    elif len(ports) > MAX_REMOTE_PORTS:
        ap.error(f"at most {MAX_REMOTE_PORTS} ports per run for non-local hosts")
    rows = scan(a.host, ports, a.timeout, workers=a.workers, show_closed=a.show_closed)
    print({"table": to_table, "csv": to_csv, "json": to_json}[a.format](rows))


if __name__ == "__main__":
    main()
