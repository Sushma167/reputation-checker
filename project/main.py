import asyncio
import ipaddress
import dns.resolver
from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI(title="Reputation Checker API")

# Mount static files for the frontend
app.mount("/static", StaticFiles(directory="static", html=True), name="static")

# --- DNS Helper Functions ---
async def async_dns_query(domain: str, record_type: str):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0
    try:
        return await asyncio.to_thread(resolver.resolve, domain, record_type)
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN"
    except Exception:
        return "ERROR"

async def get_txt_record(domain: str, prefix: str) -> str:
    result = await async_dns_query(domain, 'TXT')
    if result in ("NXDOMAIN", "ERROR"):
        return "Not Found"
    
    for rdata in result:
        txt = b"".join(rdata.strings).decode()
        if txt.startswith(prefix):
            return txt
    return "Not Found"

async def check_rbl(ip: str, rbl_domain: str) -> str:
    reversed_ip = '.'.join(reversed(ip.split('.')))
    query_url = f"{reversed_ip}.{rbl_domain}"
    
    result = await async_dns_query(query_url, 'A')
    
    if result == "NXDOMAIN":
        return "CLEAN"
    elif result == "ERROR":
        return "UNKNOWN"
    else:
        return "LISTED" # Successful A record resolution implies listed

# --- API Endpoints ---

@app.get("/api/domain/{domain}")
async def check_domain(domain: str):
    # Run DNS queries concurrently
    spf_task = get_txt_record(domain, "v=spf1")
    dmarc_task = get_txt_record(f"_dmarc.{domain}", "v=DMARC1")
    mx_task = async_dns_query(domain, 'MX')
    
    spf, dmarc, mx_records = await asyncio.gather(spf_task, dmarc_task, mx_task)
    
    mx_formatted = []
    if mx_records not in ("NXDOMAIN", "ERROR"):
        mx_formatted = [{"priority": mx.preference, "host": str(mx.exchange).rstrip('.')} for mx in mx_records]
        mx_formatted.sort(key=lambda x: x["priority"])

    return {
        "domain": domain,
        "spf": spf,
        "dmarc": dmarc,
        "mx": mx_formatted
    }

@app.get("/api/ip/{ip}")
async def check_ip(ip: str):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP Address")

    lists = {
        "spamhaus": "zen.spamhaus.org",
        "spamcop": "bl.spamcop.net",
        "barracuda": "b.barracudacentral.org"
    }
    
    tasks = [check_rbl(ip, rbl) for rbl in lists.values()]
    results = await asyncio.gather(*tasks)
    
    response_data = dict(zip(lists.keys(), results))
    response_data["ip"] = ip
    
    # Classification Engine
    listed_count = list(results).count("LISTED")
    response_data["status"] = "LISTED" if listed_count > 0 else "CLEAN"
    
    return response_data

@app.get("/api/bulk")
async def check_bulk(cidr: str = Query(..., description="CIDR format, e.g., 192.168.1.0/24")):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid CIDR Format")
        
    if network.num_addresses > 256:
        raise HTTPException(status_code=400, detail="CIDR too large. Max allowed is /24 (256 IPs).")
        
    ips = [str(ip) for ip in network.hosts()]
    if not ips: # Handle /32
        ips = [str(network.network_address)]

    # Process sequentially to avoid overwhelming DNS resolvers or hitting rate limits
    results = []
    for ip in ips:
        # A simple check against Spamhaus for bulk to keep it fast, 
        # but we can check all 3 if required. We check all 3 here:
        spamhaus = await check_rbl(ip, "zen.spamhaus.org")
        spamcop = await check_rbl(ip, "bl.spamcop.net")
        barracuda = await check_rbl(ip, "b.barracudacentral.org")
        
        status = "LISTED" if "LISTED" in [spamhaus, spamcop, barracuda] else "CLEAN"
        results.append({
            "ip": ip,
            "status": status,
            "spamhaus": spamhaus,
            "spamcop": spamcop,
            "barracuda": barracuda
        })
        
    return {"cidr": cidr, "total": len(results), "results": results}
