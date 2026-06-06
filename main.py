from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
import dns.resolver
import ipaddress
import asyncio

app = FastAPI(title="DNSBL Intelligence Center")

# =========================
# FRONTEND
# =========================

@app.get("/")
async def root():
    return RedirectResponse(url="/static/index.html")

app.mount("/static", StaticFiles(directory="static", html=True), name="static")


# =========================
# DNS RESOLVER
# =========================

async def dns_lookup(name, record_type="A"):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    try:
        return await asyncio.to_thread(resolver.resolve, name, record_type)

    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return "NXDOMAIN"
    except dns.resolver.NoNameservers:
        return "ERROR"
    except dns.resolver.Timeout:
        return "ERROR"
    except Exception:
        return "ERROR"


# =========================
# DNSBL CHECKER
# =========================

async def check_dnsbl(ip, zone):
    reversed_ip = ".".join(reversed(ip.split(".")))
    query = f"{reversed_ip}.{zone}"

    result = await dns_lookup(query, "A")

    if result == "NXDOMAIN":
        return "NOT LISTED"
    if result == "ERROR":
        return "UNKNOWN"

    try:
        for r in result:
            txt = r.to_text()

            if txt.startswith("127.0.0."):
                return "LISTED"
            if txt.startswith("127.255.255."):
                return "UNKNOWN"

        return "NOT LISTED"

    except:
        return "UNKNOWN"


# =========================
# SPAMHAUS ZONES (REAL MODEL)
# =========================

DNSBLS = {
    "CSS": "css.spamhaus.org",
    "SBL": "sbl.spamhaus.org",
    "XBL": "xbl.spamhaus.org",
    "PBL": "pbl.spamhaus.org",
    "AuthBL": "authbl.spamhaus.org"
}


# =========================
# SINGLE IP API
# =========================

@app.get("/api/ip/{ip}")
async def check_ip(ip: str):

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP Address")

    results = []

    for name, zone in DNSBLS.items():
        status = await check_dnsbl(ip, zone)
        results.append({
            "blacklist": name,
            "status": status
        })

    # overall logic
    if any(r["status"] == "LISTED" for r in results):
        overall = "LISTED"
    elif all(r["status"] == "NOT LISTED" for r in results):
        overall = "CLEAN"
    else:
        overall = "UNKNOWN"

    return {
        "ip": ip,
        "overall": overall,
        "results": results
    }


# =========================
# BULK CIDR API
# =========================

@app.get("/api/bulk")
async def bulk_check(cidr: str):

    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except:
        raise HTTPException(status_code=400, detail="Invalid CIDR Format")

    if network.num_addresses > 256:
        raise HTTPException(status_code=400, detail="Max allowed is /24")

    output = []

    for ip in network.hosts():

        ip = str(ip)

        results = []

        for name, zone in DNSBLS.items():
            status = await check_dnsbl(ip, zone)
            results.append({
                "blacklist": name,
                "status": status
            })

        if any(r["status"] == "LISTED" for r in results):
            overall = "LISTED"
        elif all(r["status"] == "NOT LISTED" for r in results):
            overall = "CLEAN"
        else:
            overall = "UNKNOWN"

        output.append({
            "ip": ip,
            "overall": overall,
            "results": results
        })

    return {
        "cidr": cidr,
        "total": len(output),
        "results": output
    }
