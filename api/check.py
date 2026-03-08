import json
import re
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from urllib.request import urlopen, Request

SELECTORS = [
    "default", "selector1", "selector2", "google", "microsoft",
    "dkim", "mail", "smtp", "k1", "k2", "s1", "s2"
]

def dns_google(name, rtype):
    url = f"https://dns.google/resolve?name={name}&type={rtype}"
    req = Request(url, headers={"User-Agent": "vercel-dns-check"})
    with urlopen(req, timeout=10) as response:
        payload = json.loads(response.read().decode("utf-8"))
    answers = payload.get("Answer", [])
    return [item.get("data", "") for item in answers if item.get("data")]

def clean_txt(records):
    cleaned = []
    for record in records:
        value = record.replace('" "', "")
        value = value.replace('"', "")
        cleaned.append(value)
    return cleaned

def ip_info(ip):
    req = Request(
        f"https://ipinfo.io/{ip}/json",
        headers={"User-Agent": "vercel-dns-check"}
    )
    with urlopen(req, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)

            domain = query.get("domain", [""])[0].strip()
            ip = query.get("ip", [""])[0].strip()

            if not domain:
                self.send_json(400, {"error": "Missing domain"})
                return

            result = {"domain": domain}

            result["a_record"] = dns_google(domain, "A")

            mx_raw = dns_google(domain, "MX")
            result["mx_records"] = mx_raw

            mx_hosts = []
            for item in mx_raw:
                parts = item.split()
                if parts:
                    mx_hosts.append(parts[-1].rstrip("."))

            mx_ips = {}
            for host in sorted(set(mx_hosts)):
                mx_ips[host] = {
                    "A": dns_google(host, "A"),
                    "AAAA": dns_google(host, "AAAA")
                }
            result["mx_ips"] = mx_ips

            txt_records = clean_txt(dns_google(domain, "TXT"))
            result["spf"] = [txt for txt in txt_records if "v=spf1" in txt.lower()]

            dmarc_records = clean_txt(dns_google(f"_dmarc.{domain}", "TXT"))
            result["dmarc"] = dmarc_records

            dkim_found = {}
            for selector in SELECTORS:
                name = f"{selector}._domainkey.{domain}"
                records = clean_txt(dns_google(name, "TXT"))
                joined = " ".join(records)
                if re.search(r"v\s*=\s*DKIM1", joined, re.IGNORECASE):
                    dkim_found[name] = records

            if dkim_found:
                result["dkim"] = dkim_found
            else:
                result["dkim"] = {
                    "message": "No DKIM found with common selectors. Check email header for real selector (s=)."
                }

            if ip:
                try:
                    result["ip_info"] = ip_info(ip)
                except Exception as exc:
                    result["ip_info_error"] = str(exc)

            self.send_json(200, result)

        except Exception as exc:
            self.send_json(500, {"error": str(exc)})

    def send_json(self, status_code, payload):
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
