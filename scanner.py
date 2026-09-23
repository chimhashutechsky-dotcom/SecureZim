import asyncio
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
import httpx

COMMON_PORTS = [80, 443, 22, 25, 53, 110, 143, 3306, 5432, 8080, 8443]
SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
]

async def tcp_check(host, port, timeout=3):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

def tls_expiry(host, timeout=3):
    context = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
    expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    return (expires - datetime.now(timezone.utc)).days

async def scan_target(target):
    target = target.strip()
    parsed = urlparse(target if "://" in target else "https://" + target)
    host = parsed.hostname or target
    findings = []

    try:
        ip = socket.gethostbyname(host)
    except Exception as exc:
        return [{
            "severity": "high",
            "title": "Target could not be resolved",
            "description": "The authorized target could not be resolved through DNS.",
            "evidence": str(exc),
            "remediation": "Verify the domain/DNS configuration."
        }]

    findings.append({
        "severity": "info",
        "title": "Target resolved",
        "description": "The target resolved successfully.",
        "evidence": f"{host} -> {ip}",
        "remediation": "No action required."
    })

    open_ports = []
    for port in COMMON_PORTS:
        if await tcp_check(host, port):
            open_ports.append(port)

    if open_ports:
        findings.append({
            "severity": "info",
            "title": "Reachable TCP services detected",
            "description": "Reachable TCP ports from the configured safe port list were detected.",
            "evidence": ", ".join(map(str, open_ports)),
            "remediation": "Confirm every exposed service is required and appropriately protected."
        })

    for scheme in ("https", "http"):
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=5, verify=True) as client:
                response = await client.get(f"{scheme}://{host}")
            if scheme == "https":
                present = {k.lower() for k in response.headers.keys()}
                missing = [h for h in SECURITY_HEADERS if h not in present]
                if missing:
                    findings.append({
                        "severity": "medium",
                        "title": "Missing recommended HTTP security headers",
                        "description": "Some commonly recommended browser security headers were not present.",
                        "evidence": ", ".join(missing),
                        "remediation": "Review and configure appropriate security headers."
                    })
                try:
                    days = tls_expiry(host)
                    if days < 0:
                        findings.append({
                            "severity": "critical",
                            "title": "TLS certificate appears expired",
                            "description": "The HTTPS certificate has passed its reported expiry date.",
                            "evidence": f"{days} days relative to current UTC date",
                            "remediation": "Renew and correctly deploy the TLS certificate."
                        })
                    elif days <= 30:
                        findings.append({
                            "severity": "high",
                            "title": "TLS certificate expires soon",
                            "description": "The HTTPS certificate is within 30 days of expiry.",
                            "evidence": f"{days} days remaining",
                            "remediation": "Renew the certificate before expiry."
                        })
                except Exception:
                    pass
            break
        except Exception:
            continue
    return findings

def calculate_score(findings):
    penalties = {"critical": 35, "high": 20, "medium": 8, "low": 3, "info": 0}
    return max(0, min(100, 100 - sum(penalties.get(x["severity"], 0) for x in findings)))
