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
# OTHER DNSBLs (Placeholder for future expansion)
# ==================================================

# Define common DNSBLs. This allows for easier management and expansion.
DNSBLS = {
    "Spamcop": "bl.spamcop.net",
    "Barracuda": "b.barracudacentral.org"
}

# Generic DNSBL checker. This function can be extended to handle different DNSBL return codes.
async def check_dnsbl(ip: str, dnsbl_zone: str):
    reversed_ip = ".".join(reversed(ip.split(".")))
    query = f"{reversed_ip}.{dnsbl_zone}"

    result = await dns_lookup(query, "A")

    if result in ["NXDOMAIN", "ERROR"]:
        return "CLEAN"
    else:
        # For simplicity, if any A record is returned, consider it listed.
        # Real DNSBLs often have specific A record values for different listing types.
        return "LISTED"

# ==================================================
# SINGLE IP API
# ==================================================

@app.get("/api/ip/{ip}")
async def check_single_ip(ip: str):

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid IP Address"
        )

    # Check Spamhaus (detailed)
    spamhaus_result = await check_spamhaus(ip)

    # Check other DNSBLs (simplified for now)
    spamcop_status = await check_dnsbl(ip, DNSBLS["Spamcop"])
    barracuda_status = await check_dnsbl(ip, DNSBLS["Barracuda"])

    # Aggregate statuses for overall status
    all_statuses = [
        spamhaus_result["css"],
        spamhaus_result["sbl"],
        spamhaus_result["xbl"],
        spamhaus_result["pbl"],
        spamhaus_result["authbl"],
        spamcop_status,
        barracuda_status
    ]

    overall_status = "CLEAN"
    if "LISTED" in all_statuses:
        overall_status = "LISTED"
    elif any(s == "ERROR" for s in all_statuses): # Consider DNS lookup errors as UNKNOWN for overall
        overall_status = "UNKNOWN"

    return {
        "ip": ip,
        "spamhaus": {
            "css": spamhaus_result["css"],
            "sbl": spamhaus_result["sbl"],
            "xbl": spamhaus_result["xbl"],
            "pbl": spamhaus_result["pbl"],
            "authbl": spamhaus_result["authbl"]
        },
        "spamcop": {"status": spamcop_status},
        "barracuda": {"status": barracuda_status},
        "overall_status": overall_status
    }

# ==================================================
# BULK CIDR API
# ==================================================

@app.get("/api/cidr/{cidr_block}")
async def check_bulk_cidr(cidr_block: str):
    try:
        network = ipaddress.ip_network(cidr_block, strict=False)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid CIDR block"
        )

    results = []
    # Limit the number of IPs to check in a bulk request to prevent abuse/long processing
    max_ips = 256 # For example, checking up to a /24 network

    ip_count = 0
    for ip_obj in network.hosts():
        if ip_count >= max_ips:
            print(f"Truncating CIDR check to {max_ips} IPs for {cidr_block}")
            break
        ip = str(ip_obj)

        spamhaus = await check_spamhaus(ip)
        spamcop = await check_dnsbl(ip, DNSBLS["Spamcop"])
        barracuda = await check_dnsbl(ip, DNSBLS["Barracuda"])

        # Determine overall status for this single IP in the CIDR block
        single_ip_statuses = [
            spamhaus["css"], spamhaus["sbl"], spamhaus["xbl"], spamhaus["pbl"], spamhaus["authbl"],
            spamcop, barracuda
        ]
        single_ip_overall = "CLEAN"
        if "LISTED" in single_ip_statuses:
            single_ip_overall = "LISTED"
        elif any(s == "ERROR" for s in single_ip_statuses):
            single_ip_overall = "UNKNOWN"


        results.append({
            "ip": ip,
            "spamhaus": {
                "css": spamhaus["css"],
                "sbl": spamhaus["sbl"],
                "xbl": spamhaus["xbl"],
                "pbl": spamhaus["pbl"],
                "authbl": spamhaus["authbl"]
            },
            "spamcop": {"status": spamcop},
            "barracuda": {"status": barracuda},
            "overall_status": single_ip_overall
        })
        ip_count += 1

    return {
        "cidr_block": cidr_block,
        "checked_ips_count": ip_count,
        "results": results
    }
