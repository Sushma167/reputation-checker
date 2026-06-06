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

    except dns.resolver.NoAnswer:
        return "NXDOMAIN"

    except dns.resolver.NoNameservers:
        return "ERROR"

    except dns.resolver.Timeout:
        return "ERROR"

    except Exception:
        return "ERROR"

# ==================================================
# SPF
# ==================================================

async def get_spf(domain):

    result = await dns_lookup(domain, "TXT")

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

    except Exception:
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

    except Exception:
        pass

    return "NOT FOUND"

# ==================================================
# MX
# ==================================================

async def get_mx(domain):

    records = []

    result = await dns_lookup(domain, "MX")

    if result in ["NXDOMAIN", "ERROR"]:
        return records

    try:
        for mx in result:

            records.append({
                "priority": mx.preference,
                "host": str(mx.exchange).rstrip(".")
            })

    except Exception:
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

    spf, dmarc, mx = await asyncio.gather(
        get_spf(domain),
        get_dmarc(domain),
        get_mx(domain)
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

# ==================================================
# SPAMHAUS CSS / SBL / XBL / PBL / AUTHBL
# ==================================================

SPAMHAUS_ZEN = "zen.spamhaus.org"

async def check_spamhaus(ip):

    reversed_ip = ".".join(
        reversed(ip.split("."))
    )

    query = f"{reversed_ip}.{SPAMHAUS_ZEN}"

    result = await dns_lookup(
        query,
        "A"
    )

    response = {
        "css": "NOT LISTED",
        "sbl": "NOT LISTED",
        "xbl": "NOT LISTED",
        "pbl": "NOT LISTED",
        "authbl": "NOT LISTED"
    }

    if result in ["NXDOMAIN"]:
        return response

    if result in ["ERROR"]:
        return response

    try:

        for r in result:

            code = r.to_text()

            print(
                f"SPAMHAUS DEBUG | {ip} | {code}"
            )

            # CSS
            if code in [
                "127.0.0.3",
                "127.0.0.4",
                "127.0.0.5",
                "127.0.0.6",
                "127.0.0.7"
            ]:
                response["css"] = "LISTED"

            # SBL
            elif code == "127.0.0.2":
                response["sbl"] = "LISTED"

            # XBL
            elif code in [
                "127.0.0.9",
                "127.0.0.10",
                "127.0.0.11"
            ]:
                response["xbl"] = "LISTED"

            # PBL
            elif code in [
                "127.0.0.12",
                "127.0.0.13",
                "127.0.0.14"
            ]:
                response["pbl"] = "LISTED"

            # AuthBL
            elif code == "127.0.1.255":
                response["authbl"] = "LISTED"

        return response

    except Exception as e:

        print(
            f"SPAMHAUS ERROR: {e}"
        )

        return response

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

    spamhaus = await check_dnsbl(ip, DNSBLS["Spamhaus"])
    spamcop = await check_dnsbl(ip, DNSBLS["Spamcop"])
    barracuda = await check_dnsbl(ip, DNSBLS["Barracuda"])

    statuses = [spamhaus, spamcop, barracuda]

    if "LISTED" in statuses:
        overall = "LISTED"

    elif all(x == "CLEAN" for x in statuses):
        overall = "CLEAN"

    else:
        overall = "UNKNOWN"

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

for ip in network.hosts():

    ip = str(ip)

    spamhaus = await check_spamhaus(ip)

    results.append({
        "ip": ip,
        "css": spamhaus["css"],
        "sbl": spamhaus["sbl"],
        "xbl": spamhaus["xbl"],
        "pbl": spamhaus["pbl"],
        "authbl": spamhaus["authbl"]
    })

  return {
    "ip": ip,
    "results": [
        {"blacklist": "CSS", "status": spamhaus["css"]},
        {"blacklist": "SBL", "status": spamhaus["sbl"]},
        {"blacklist": "XBL", "status": spamhaus["xbl"]},
        {"blacklist": "PBL", "status": spamhaus["pbl"]},
        {"blacklist": "AuthBL", "status": spamhaus["authbl"]}
    ]
}
