import subprocess
import schedule
import time
import requests
import json
from config import SPLUNK_URL, SPLUNK_TOKEN

def send_to_splunk(enriched_file):
    """Send enriched IOCs to Splunk HEC"""
    
    with open(enriched_file, "r") as f:
        iocs = json.load(f)
    
    headers = {
        "Authorization": f"Splunk {SPLUNK_TOKEN}",
        "Content-Type": "application/json"
    }
    
    success = 0
    for ioc in iocs:
        payload = {
            "event": ioc,
            "sourcetype": "threat_intel",
            "index": "main"
        }
        try:
            response = requests.post(
                f"{SPLUNK_URL}/services/collector/event",
                headers=headers,
                json=payload,
                verify=False
            )
            if response.status_code == 200:
                success += 1
        except Exception as e:
            print(f"[-] Failed to send {ioc['value']}: {e}")
    
    print(f"[+] Sent {success}/{len(iocs)} IOCs to Splunk")

def run_pipeline():
    print("[*] Starting Threat Intelligence Pipeline...")
    
    # Step 1: Collect IOCs
    subprocess.run(["python3", "scripts/ioc_collector.py"])
    
    # Step 2: Enrich IOCs
    subprocess.run(["python3", "scripts/enricher.py"])
    
    # Step 3: Generate report
    subprocess.run(["python3", "scripts/report_generator.py"])
    
    # Step 4: Send to Splunk
    print("[*] Sending IOCs to Splunk...")
    send_to_splunk("output/enriched_iocs.json")
    
    print("[+] Pipeline complete!")

# Run daily at 8AM
schedule.every().day.at("08:00").do(run_pipeline)

if __name__ == "__main__":
    run_pipeline()
    while True:
        schedule.run_pending()
        time.sleep(60)
