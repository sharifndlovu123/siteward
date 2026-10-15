import ssl
from types import SimpleNamespace as NS

import pytest

from webscan.checks import tls
from webscan.core.models import Skip


def at(text):
    return ssl.cert_time_to_seconds(text)


NOW = at("Jun  1 00:00:00 2029 GMT")


def test_healthy_cert_has_no_findings():
    assert tls._assess_cert({"notAfter": "Jan  1 00:00:00 2030 GMT"}, NOW) == []


def test_expiring_soon_is_high():
    found = tls._assess_cert({"notAfter": "Jun 10 00:00:00 2029 GMT"}, NOW)
    assert [(f.id, f.severity) for f in found] == [("tls.cert-expiring", "high")]


def test_expiring_within_30_days_is_medium():
    found = tls._assess_cert({"notAfter": "Jun 25 00:00:00 2029 GMT"}, NOW)
    assert [(f.id, f.severity) for f in found] == [("tls.cert-expiring", "medium")]


def test_expired_cert_is_high():
    found = tls._assess_cert({"notAfter": "May  1 00:00:00 2029 GMT"}, NOW)
    assert [(f.id, f.severity) for f in found] == [("tls.cert-expired", "high")]


def test_non_https_target_is_skipped():
    with pytest.raises(Skip):
        tls.run(NS(target=NS(scheme="http", host="x", port=80)))
