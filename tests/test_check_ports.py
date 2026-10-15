import socket

from siteward.checks import ports


def test_open_port_is_reported_and_closed_is_not(server, ctx_for, monkeypatch):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    open_port = listener.getsockname()[1]
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()
    monkeypatch.setattr(ports, "PORTS", {open_port: ("TestDB", "high"), closed_port: ("Nothing", "high")})
    try:
        found = ports.run(ctx_for(server, ports=True))
    finally:
        listener.close()
    assert [(f.id, f.severity) for f in found] == [("ports.open", "high")]
    assert f"{open_port}/tcp" in found[0].evidence and "TestDB" in found[0].evidence


def test_check_is_opt_in():
    assert ports.OPT_IN == "ports"
    assert 22 in ports.PORTS and 3306 in ports.PORTS and 3389 in ports.PORTS
