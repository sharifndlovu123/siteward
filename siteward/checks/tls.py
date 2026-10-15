import socket
import ssl
import time

from siteward.core.models import Finding, Skip

ID = "tls.certificate"
CATEGORY = "TLS"
OPT_IN = None
TIMEOUT = 8.0


def _assess_cert(cert: dict, now: float) -> list:
    days = (ssl.cert_time_to_seconds(cert["notAfter"]) - now) / 86400
    if days < 0:
        return [Finding("tls.cert-expired", "TLS certificate has expired", CATEGORY, "high",
                        f"notAfter: {cert['notAfter']}", "Renew the certificate immediately.")]
    if days < 30:
        severity = "high" if days < 14 else "medium"
        return [Finding("tls.cert-expiring", f"TLS certificate expires in {int(days)} days", CATEGORY, severity,
                        f"notAfter: {cert['notAfter']}", "Renew the certificate and enable auto-renewal.")]
    return []


def _fetch_cert(ip, host, port):
    """Connect to the netguard-validated IP; the hostname is used only for SNI and verification."""
    context = ssl.create_default_context()
    with socket.create_connection((ip, port), TIMEOUT) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(), tls.version()


def _accepts_legacy(ip, host, port):
    """Return the negotiated version if TLS 1.0/1.1 is accepted, False if refused, None if we cannot test."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Certificate verification is deliberately off HERE ONLY: this is a protocol-support probe that
    # sends no data and trusts nothing it receives. The real certificate check is _fetch_cert above.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.maximum_version = ssl.TLSVersion.TLSv1_1
        context.set_ciphers("ALL:@SECLEVEL=0")
    except (ssl.SSLError, ValueError):
        return None
    try:
        with socket.create_connection((ip, port), TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                return tls.version()
    except (ssl.SSLError, OSError):
        return False


def run(ctx):
    t = ctx.final  # where the site is really served (after redirects), with netguard-validated IPs
    if t.scheme != "https":
        raise Skip("target is not served over HTTPS")
    ip = t.ips[0]
    try:
        cert, version = _fetch_cert(ip, t.host, t.port)
    except ssl.SSLCertVerificationError as exc:
        return [Finding("tls.cert-invalid", "TLS certificate failed verification", CATEGORY, "high",
                        exc.verify_message or str(exc),
                        "Install a valid certificate from a trusted CA that matches the hostname.")]
    except ssl.SSLError as exc:
        return [Finding("tls.handshake-failed", "TLS handshake failed", CATEGORY, "high", str(exc),
                        "Check the server's TLS configuration.")]
    out = _assess_cert(cert, time.time())
    if version in ("TLSv1", "TLSv1.1"):
        out.append(Finding("tls.legacy-protocol", f"Negotiated legacy protocol {version}", CATEGORY, "high",
                           version, "Disable TLS 1.0/1.1; require TLS 1.2+."))
    elif _accepts_legacy(ip, t.host, t.port):
        out.append(Finding("tls.legacy-protocol", "Server accepts TLS 1.0/1.1", CATEGORY, "medium",
                           "A TLS 1.0/1.1 handshake succeeded", "Disable TLS 1.0/1.1; require TLS 1.2+."))
    return out
