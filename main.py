from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
import dns.resolver
import ipaddress
import asyncio

app = FastAPI(title="DNSBL Intelligence Center")

# ==================================================
# FRONTEND
# ==================================================

@app.get("/")
async def root():
    return RedirectResponse(url="/static/index.html")

app.mount(
    "/static",
    StaticFiles(directory="static", html=True),
    name="static"
)

# ==================================================
# DNS HELPER
# ==================================================

async def dns_lookup(name, record_type):

    resolver = dns.resolver.Resolver()

    resolver.timeout = 3
    resolver.lifetime = 3

    try:
        return await asyncio.to_thread(
            resolver.resolve,
            name,
            record_type
        )

    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN"

    except Exception:
        return "ERROR"

# ==================================================
# SPF
# ==================================================

async def get_spf(domain):

    result = await dns_lookup(
        domain,
        "TXT"
    )

    if result in ["NXDOMAIN", "ERROR"]:
        return "NOT FOUND"

    try:

        for record in result:

            txt = "".join(
                s.decode() if isinstance(s, bytes)
                else str(s)
                for s in record.strings
            )

            if txt.lower().startswith("v=spf1"):
                return txt

    except:
        pass

    return "NOT FOUND"

# ==================================================
# DMARC
# ==================================================

async def get_dmarc(domain):

    result = await dns_lookup(
        f"_dmarc.{domain}",
        "TXT"
    )

    if result in ["NXDOMAIN", "ERROR"]:
        return "NOT FOUND"

    try:

        for record in result:

            txt = "".join(
                s.decode() if isinstance(s, bytes)
                else str(s)
                for s in record.strings
            )

            if txt.lower().startswith("v=dmarc1"):
                return txt

    except:
        pass

    return "NOT FOUND"

# ==================================================
# MX
# ==================================================

async def get_mx(domain):

    records = []

    result = await dns_lookup(
        domain,
        "MX"
    )

    if result in ["NXDOMAIN", "ERROR"]:
        return records

    try:

        for mx in result:

            records.append({
                "priority": mx.preference,
                "host": str(mx.exchange).rstrip(".")
            })

    except:
        pass

    records.sort(
        key=lambda x: x["priority"]
    )

    return records

# ==================================================
# DOMAIN API
# ==================================================

@app.get("/api/domain/{domain}")
async def check_domain(domain: str):

    spf_task = get_spf(domain)
    dmarc_task = get_dmarc(domain)
    mx_task = get_mx(domain)

    spf, dmarc, mx = await asyncio.gather(
        spf_task,
        dmarc_task,
        mx_task
    )

    return {
        "domain": domain,
        "spf": spf,
        "dmarc": dmarc,
        "mx": mx
    }

# ==================================================
# DNSBL ENGINE
# ==================================================

DNSBLS = {
    "Spamhaus": "zen.spamhaus.org",
    "Spamcop": "bl.spamcop.net",
    "Barracuda": "b.barracudacentral.org"
}

async def check_dnsbl(ip, zone):

    reversed_ip = ".".join(
        reversed(ip.split("."))
    )

    query = f"{reversed_ip}.{zone}"

    result = await dns_lookup(
        query,
        "A"
    )

    if result == "NXDOMAIN":
        return "CLEAN"

    if result == "ERROR":
        return "UNKNOWN"

    try:

        for r in result:

            returned = r.to_text()

            # DNSBL listings typically return 127.x.x.x
            if returned.startswith("127."):
                return "LISTED"

        return "CLEAN"

    except:
        return "UNKNOWN"

# ==================================================
# SINGLE IP API
# ==================================================

@app.get("/api/ip/{ip}")
async def check_ip(ip: str):

    try:
        ipaddress.ip_address(ip)

    except ValueError:

        raise HTTPException(
            status_code=400,
            detail="Invalid IP Address"
        )

    spamhaus = await check_dnsbl(
        ip,
        DNSBLS["Spamhaus"]
    )

    spamcop = await check_dnsbl(
        ip,
        DNSBLS["Spamcop"]
    )

    barracuda = await check_dnsbl(
        ip,
        DNSBLS["Barracuda"]
    )

    overall = "CLEAN"

    if (
        spamhaus == "LISTED"
        or spamcop == "LISTED"
        or barracuda == "LISTED"
    ):
        overall = "LISTED"

    return {
        "ip": ip,
        "spamhaus": spamhaus,
        "spamcop": spamcop,
        "barracuda": barracuda,
        "overall": overall
    }

# ==================================================
# BULK CIDR API
# ==================================================

@app.get("/api/bulk")
async def bulk_check(cidr: str):

    try:

        network = ipaddress.ip_network(
            cidr,
            strict=False
        )

    except:

        raise HTTPException(
            status_code=400,
            detail="Invalid CIDR Format"
        )

    if network.num_addresses > 256:

        raise HTTPException(
            status_code=400,
            detail="Maximum range allowed is /24"
        )

    results = []

    for ip in network.hosts():

        ip = str(ip)

        spamhaus = await check_dnsbl(
            ip,
            DNSBLS["Spamhaus"]
        )

        spamcop = await check_dnsbl(
            ip,
            DNSBLS["Spamcop"]
        )

        barracuda = await check_dnsbl(
            ip,
            DNSBLS["Barracuda"]
        )

        overall = "CLEAN"

        if (
            spamhaus == "LISTED"
            or spamcop == "LISTED"
            or barracuda == "LISTED"
        ):
            overall = "LISTED"

        results.append({
            "ip": ip,
            "spamhaus": spamhaus,
            "spamcop": spamcop,
            "barracuda": barracuda,
            "overall": overall
        })

    return {
        "cidr": cidr,
        "total": len(results),
        "results": results
    }
