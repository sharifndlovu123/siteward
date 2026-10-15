import socket
from concurrent.futures import ThreadPoolExecutor

from siteward.core.models import Finding

ID = "ports.common"
CATEGORY = "Network"
OPT_IN = "ports"
TIMEOUT = 1.5

# port -> (service, severity if reachable from the internet)
PORTS = {
    21: ("FTP", "high"), 22: ("SSH", "info"), 23: ("Telnet", "high"), 25: ("SMTP", "low"), 53: ("DNS", "info"),
    110: ("POP3", "low"), 135: ("MS RPC", "high"), 139: ("NetBIOS", "high"), 143: ("IMAP", "low"),
    445: ("SMB", "high"), 1433: ("MS SQL", "high"), 1521: ("Oracle DB", "high"), 3306: ("MySQL", "high"),
    3389: ("RDP", "high"), 5432: ("PostgreSQL", "high"), 5900: ("VNC", "high"), 6379: ("Redis", "high"),
    8080: ("HTTP alt", "info"), 9200: ("Elasticsearch", "high"), 11211: ("Memcached", "high"),
    27017: ("MongoDB", "high"),
}


def _is_open(ip, port):
    try:
        with socket.create_connection((ip, port), TIMEOUT):
            return True
    except OSError:
        return False


def run(ctx):
    ip = ctx.target.ips[0]  # an address netguard already approved
    ports = sorted(PORTS)
    with ThreadPoolExecutor(max_workers=8) as pool:
        states = list(pool.map(lambda p: _is_open(ip, p), ports))
    out = []
    for port, is_open in zip(ports, states):
        if is_open:
            name, severity = PORTS[port]
            out.append(Finding("ports.open", f"{name} port {port} is reachable", CATEGORY, severity,
                               f"{port}/tcp open ({name})",
                               "Close the port or restrict it with a firewall to trusted addresses."))
    return out
