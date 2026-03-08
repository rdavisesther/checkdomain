import json
import re
from urllib.request import urlopen, Request
from urllib.parse import parse_qs

SELECTORS = [
    "default", "selector1", "selector2", "google", "microsoft",
    "dkim", "mail", "smtp", "k1", "k2", "s1", "s2"
]

def dns_google(name, rtype):
    url = f"https://dns.google/resolve?name={name}&type={rtype}"
    req = Request(url, headers={"User-Agent": "vercel-dns-check"})
    with urlopen(req, timeout=10) as r:
        data = json.loads(r.read().decode())
    answers = data.get("Answer", [])
    return [a.get("data", "") for a in answers]

def clean_txt(records):
    cleaned = []
    for r in records:
        cleaned.append(r.replace('" "', "").replace('"', ""))
    return cleaned

def ip_info(ip):
    req = Request(
        f"https://ipinfo.io/{ip}/json",
        headers={"User-Agent": "vercel-dns-check"}
    )
    with urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())

def handler(request):
    query = parse_qs(request.query_string.decode())
    domain = query.get("domain", [""])[0].strip()
    ip = query.get("ip", [""])[0].strip()

    if not domain:
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "Missing domain"})
        }

    result = {"domain": domain}

    try:
        result["a_record"] = dns_google(domain, "A")

        mx_raw = dns_google(domain, "MX")
        result["mx_records"] = mx_raw

        mx_hosts = []
        for m in mx_raw:
            parts = m.split()
            if parts:
                mx_hosts.append(parts[-1].rstrip("."))

        mx_ips = {}
        for host in sorted(set(mx_hosts)):
            mx_ips[host] = dns_google(host, "A")
        result["mx_ips"] = mx_ips

        txt_records = clean_txt(dns_google(domain, "TXT"))
        result["spf"] = [t for t in txt_records if "v=spf1" in t.lower()]

        dmarc = clean_txt(dns_google(f"_dmarc.{domain}", "TXT"))
        result["dmarc"] = dmarc

        dkim_found = {}
        for sel in SELECTORS:
            name = f"{sel}._domainkey.{domain}"
            records = clean_txt(dns_google(name, "TXT"))
            joined = " ".join(records)
            if re.search(r"v\s*=\s*DKIM1", joined, re.I):
                dkim_found[name] = records

        result["dkim"] = dkim_found or {"message": "No DKIM found with common selectors"}

        if ip:
            try:
                result["ip_info"] = ip_info(ip)
            except Exception as e:
                result["ip_info_error"] = str(e)

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(result, indent=2)
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": str(e)})
        }
