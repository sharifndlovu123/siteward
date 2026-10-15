# Security policy

Please report vulnerabilities in webscan privately to the maintainers (see the contact on the project page) rather than opening a public issue. Include steps to reproduce. We aim to acknowledge reports within a few days.

Areas of particular interest: bypasses of the target validation in `webscan/core/netguard.py` (SSRF), rate-limit bypasses, injection into generated reports, and anything that causes scan data to be persisted.
