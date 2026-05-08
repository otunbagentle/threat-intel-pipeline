import requests
import json
import time
from config import VT_API_KEY

def enrich_with_virustotal(ioc_value, ioc_type):
    headers = {"x-apikey": VT_API_KEY}
    
    if ioc_type in ["IPv4", "IPv6"]:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{ioc_value}"
    elif ioc_type == "URL":
        url = f"https://www.virustotal.com/api/v3/urls/{ioc_value}"
    else:
        return None
    
    try:
        response = requests.get(url, headers=headers)
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get(
            "last_analysis_stats", {}
        )
        enriched = {
            "malicious_votes": stats.get("malicious", 0),
            "suspicious_votes": stats.get("suspicious", 0),
            "harmless_votes": stats.get("harmless", 0),
            "vt_link": f"https://www.virustotal.com/gui/ip-address/{ioc_value}"
        }
        return enriched
    except Exception as e:
        print(f"[-] VT enrichment failed for {ioc_value}: {e}")
        return None

def enrich_all_iocs(ioc_file):
    with open(ioc_file, "r") as f:
        iocs = json.load(f)
    
    enriched_iocs = []
    
    for i, ioc in enumerate(iocs[:50]):
        print(f"[*] Enriching {i+1}/{min(50, len(iocs))}: {ioc['value']}")
        
        vt_data = enrich_with_virustotal(ioc["value"], ioc["type"])
        
        if vt_data:
            ioc.update(vt_data)
            if vt_data["malicious_votes"] >= 5:
                ioc["priority"] = "HIGH"
            elif vt_data["malicious_votes"] >= 2:
                ioc["priority"] = "MEDIUM"
            else:
                ioc["priority"] = "LOW"
        
        enriched_iocs.append(ioc)
        time.sleep(15)  # VT free tier rate limit
    
    with open("output/enriched_iocs.json", "w") as f:
        json.dump(enriched_iocs, f, indent=4)
    
    print(f"[+] Enrichment complete. {len(enriched_iocs)} IOCs processed.")
    return enriched_iocs

if __name__ == "__main__":
    enrich_all_iocs("output/raw_iocs.json")
