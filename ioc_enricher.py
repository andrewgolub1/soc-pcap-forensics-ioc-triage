import os
import json
import base64
import requests
from datetime import datetime, timezone

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Indicators taken from pcap-dump
IOCS = {
    "ips": ["45.131.214.85"],
    "urls": ["http://45.131.214.85/fakeurl.htm"],
    "sha256_hashes": [
        "F0E200CACD273E3DD257057F27AEDA839A1F2F31482E0BB01EA8B1363A7AF245"
    ],
}

def parse_json_safely(resp: requests.Response) -> dict | None:
    if not resp.text or not resp.text.strip():
        return None
    try:
        return resp.json()
    except ValueError:
        return None

def check_abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY not set"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}

    resp = requests.get(url, headers=headers, params=params, timeout=15)
    payload = parse_json_safely(resp)
    if resp.status_code != 200 or not payload:
        return {"ip": ip, "error": f"HTTP {resp.status_code}: {resp.text} or empty response"}

    data = payload.get("data", {})
    return {
        "ip": ip,
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "country": data.get("countryCode"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "total_reports": data.get("totalReports"),
        "last_reported_at": data.get("lastReportedAt"),
    }


def check_vt_ip(ip: str) -> dict:
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not set"}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}

    resp = requests.get(url, headers=headers, timeout=15)
    payload = parse_json_safely(resp)
    if resp.status_code != 200 or not payload:
        return {"ip": ip, "error": f"HTTP {resp.status_code} or empty response"}

    attrs = payload.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "ip": ip,
        "as_owner": attrs.get("as_owner"),
        "country": attrs.get("country"),
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
    }

def check_vt_url(target_url: str) -> dict:
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not set"}

    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    url = f"https://www.totalvirus.com/api/v3/urls/{url_id}"
    headers={"x_apikey": VT_API_KEY}

    resp = requests.get(url, headers=headers, timeout=15)
    if resp.status_code == 404:
        return {"url": target_url, "status": "Not found in VirusTotal database"}
    
    payload = parse_json_safely(resp)
    if resp.status_code != 200 or not payload:
        return {
            "url": target_url,
            "status": f"No analysis body returned by VirusTotal (HTTP {resp.status_code})"
            }

    stats = (
        payload.get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
    )
    return {
        "url": target_url,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
    }

def check_vt_hash(sha256: str) -> dict:
    if not VT_API_KEY:
        return {"error": "VT_API_KEY is not set"}

    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": VT_API_KEY}

    resp = requests.get(url, headers=headers, timeout=15)
    if resp.status_code == 404:
        return {
            "sha256": sha256,
            "status": "Not found in VT (expeted for dynamic C2 HTTP response)",
        }
    payload = parse_json_safely(resp)
    if resp.status_code != 200 or not payload:
        return {
            "sha256": sha256,
            "status": f"No analysis body returned by VirusTotal (HTTP {resp.status_code})"
            }

    attrs = payload.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "sha256": sha256,
        "meaningful_name": attrs.get("meaningful_name"),
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
    }

def main():
    print("- SOC Tier-1 Automated IOC Enrichment -\n")
    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "abuseipdb_results": [],
        "virustotal_ip_results": [],
        "virustotal_url_results": [],
        "virustotal_hash_results": [],
    }

    for ip in IOCS["ips"]:
        print("- SOC Tier-1 Automated IOC Enrichment -\n")
        abuse_res = check_abuseipdb(ip)
        vt_ip_res = check_vt_ip(ip)
        report["abuseipdb_results"].append(abuse_res)
        report["virustotal_ip_results"].append(vt_ip_res)
        print("AbuseIPDB:", json.dumps(abuse_res, indent=2))
        print("VirusTotal IP:", json.dumps(vt_ip_res, indent=2))

    for u in IOCS["urls"]:
        print(f"\n[*] Checking URL {u} on VirusTotal...")
        vt_url_res = check_vt_url(u)
        report["virustotal_url_results"].append(vt_url_res)
        print("VirusTotal URL:", json.dumps(vt_url_res, indent=2))

    for h in IOCS["sha256_hashes"]:
        print(f"\n[*] Checking SHA-256 {h} on VirusTotal...")
        vt_hash_res = check_vt_hash(h)
        report["virustotal_hash_results"].append(vt_hash_res)
        print("VirusTotal Hash:", json.dumps(vt_hash_res, indent=2))

    with open("enrichment_output.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("\n[+] Enrichment complete! Results saved to enrichment_output.json")

if __name__ == "__main__":
    main()