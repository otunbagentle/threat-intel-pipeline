# scripts/report_generator.py
import json
import pandas as pd
from datetime import datetime

def generate_report(enriched_file):
    """Generate a threat intelligence report"""
    
    with open(enriched_file, "r") as f:
        iocs = json.load(f)
    
    df = pd.DataFrame(iocs)
    
    # Summary statistics
    total = len(df)
    high = len(df[df.get("priority", "") == "HIGH"]) if "priority" in df else 0
    medium = len(df[df.get("priority", "") == "MEDIUM"]) if "priority" in df else 0
    
    report = f"""
====================================================
     THREAT INTELLIGENCE REPORT
     Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
====================================================

EXECUTIVE SUMMARY
-----------------
Total IOCs Analysed : {total}
HIGH Priority       : {high}
MEDIUM Priority     : {medium}
LOW Priority        : {total - high - medium}

IOC TYPE BREAKDOWN
------------------
{df['type'].value_counts().to_string() if 'type' in df else 'N/A'}

SOURCE BREAKDOWN
----------------
{df['source'].value_counts().to_string() if 'source' in df else 'N/A'}

TOP HIGH PRIORITY IOCs
----------------------
"""
    
    if "priority" in df.columns:
        high_iocs = df[df["priority"] == "HIGH"][
            ["value", "type", "source", "malicious_votes"]
        ].head(10)
        report += high_iocs.to_string(index=False)
    
    report += "\n\n===================================================="
    
    # Save report
    report_path = f"reports/threat_intel_report_{datetime.now().strftime('%Y%m%d')}.txt"
    with open(report_path, "w") as f:
        f.write(report)
    
    print(report)
    print(f"\n[+] Report saved to {report_path}")

if __name__ == "__main__":
    generate_report("output/enriched_iocs.json")
