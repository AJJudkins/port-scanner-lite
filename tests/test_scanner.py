import json, os, socket, sys
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import scanner


@pytest.fixture
def listener():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(5)
    yield s.getsockname()[1]
    s.close()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def test_parse_ports():
    assert scanner.parse_ports("80, 22,8000-8002,22") == [22, 80, 8000, 8001, 8002]


def test_parse_ports_invalid():
    with pytest.raises(ValueError):
        scanner.parse_ports("70000")


def test_detects_open_and_closed(listener):
    closed = free_port()
    rows = scanner.scan("127.0.0.1", [listener, closed], show_closed=True)
    state = {r["port"]: r["state"] for r in rows}
    assert state[listener] == "open" and state[closed] == "closed"


def test_service_name():
    assert scanner.service_name(22) == "ssh" or scanner.service_name(22) == "unknown"
    assert scanner.service_name(1) in ("tcpmux", "unknown")


def test_outputs(listener):
    rows = scanner.scan("127.0.0.1", [listener])
    assert json.loads(scanner.to_json(rows))[0]["port"] == listener
    assert scanner.to_csv(rows).splitlines()[0] == "host,port,state,service"


def test_remote_host_requires_flag():
    with pytest.raises(SystemExit):
        scanner.main(["--host", "192.0.2.1", "--ports", "80"])


import pytest


def test_bad_ports_exit_cleanly():
    import scanner
    for spec in ("abc", "0", "70000", "10-5", "1-99999"):
        with pytest.raises(SystemExit) as e:
            scanner.main(["--ports", spec])
        assert e.value.code == 2


def test_remote_requires_authorization_and_port_cap():
    import scanner
    with pytest.raises(SystemExit):
        scanner.main(["--host", "192.0.2.1", "--ports", "80"])
    with pytest.raises(SystemExit):
        scanner.main(["--host", "192.0.2.1", "--ports", "1-2000", "--i-am-authorized"])


def test_workers_and_timeout_bounds():
    import scanner
    for args in (["--workers", "0"], ["--workers", "9999"], ["--timeout", "0"], ["--timeout", "99"]):
        with pytest.raises(SystemExit):
            scanner.main(args)
