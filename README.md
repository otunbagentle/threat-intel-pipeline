# Threat Intelligence Pipeline

An automated pipeline that collects, enriches, and reports on 
Indicators of Compromise (IOCs) from open-source threat feeds.

## Features
- Collects IOCs from AlienVault OTX and AbuseIPDB
- Enriches IOCs using VirusTotal API
- Prioritises IOCs as HIGH, MEDIUM, or LOW
- Generates automated threat intelligence reports
- Runs daily on a schedule

## Setup
1. Clone the repo
2. Create virtual environment: `python3 -m venv venv`
3. Activate: `source venv/bin/activate`
4. Install packages: `pip3 install -r requirements.txt`
5. Rename `scripts/config.example.py` to `scripts/config.py`
6. Add your API keys to `scripts/config.py`
7. Run: `python3 scripts/pipeline.py`

## Tools Used
- Python 3
- AlienVault OTX
- AbuseIPDB
- VirusTotal
