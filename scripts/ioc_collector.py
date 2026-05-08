import requests
import json
from config import OTX_API_KEY, ABUSEIPDB_KEY
from datetime import datetime

def get_otx_pulses():
    """Pull latest threat pulses from AlienVault OTX"""
    
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    
    iocs = []
    
    try:
        response = requests.get(url, headers=headers)
        data = response.json()
        
        for pulse in data.get("results", []):
            for indicator in pulse.get("indicators", []):
                ioc = {
                    "value": indicator["indicator"],
                    "type": indicator["type"],
                    "source": "AlienVault OTX",
                    "pulse_name": pulse["name"],
                    "timestamp": datetime.now().isoformat()
                }
                iocs.append(ioc)
                
        print(f"[+] Collected {len(iocs)} IOCs from OTX")
        return iocs
        
    except Exception as e:
        print(f"[-] Error collecting from OTX: {e}")
        return []

def get_abuse_ips():
    """Pull malicious IPs from AbuseIPDB"""
    
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {
        "Key": ABUSEIPDB_KEY,
        "Accept": "application/json"
    }
    params = {"confidenceMinimum": 90}
    
    iocs = []
    
    try:
        response = requests.get(url, headers=headers, params=params)
        data = response.json()
        
        for entry in data.get("data", [])[:100]:  # limit to 100
            ioc = {
                "value": entry["ipAddress"],
                "type": "IPv4",
                "source": "AbuseIPDB",
                "confidence": entry["abuseConfidenceScore"],
                "timestamp": datetime.now().isoformat()
            }
            iocs.append(ioc)
            
        print(f"[+] Collected {len(iocs)} IPs from AbuseIPDB")
        return iocs
        
    except Exception as e:
        print(f"[-] Error collecting from AbuseIPDB: {e}")
        return []

if __name__ == "__main__":
    all_iocs = get_otx_pulses() + get_abuse_ips()
    
    # Save to file
    with open("output/raw_iocs.json", "w") as f:
        json.dump(all_iocs, f, indent=4)
    
    print(f"[+] Total IOCs saved: {len(all_iocs)}")
