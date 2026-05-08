import subprocess
import schedule
import time

def run_pipeline():
    print("[*] Starting Threat Intelligence Pipeline...")
    
    # Step 1: Collect IOCs
    subprocess.run(["python3", "scripts/ioc_collector.py"])
    
    # Step 2: Enrich IOCs
    subprocess.run(["python3", "scripts/enricher.py"])
    
    # Step 3: Generate report
    subprocess.run(["python3", "scripts/report_generator.py"])
    
    print("[+] Pipeline complete!")

# Run daily at 8AM
schedule.every().day.at("08:00").do(run_pipeline)

if __name__ == "__main__":
    run_pipeline()  # Run once immediately
    while True:
        schedule.run_pending()
        time.sleep(60)
