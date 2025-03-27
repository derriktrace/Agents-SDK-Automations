EML Phishing Analysis Framework

A Python-based framework for analyzing `.eml` email files for phishing and malicious indicators. Integrates VirusTotal, URLScan.io, and deep header/body/link/attachment inspection. Ideal for SOC workflows, security researchers, or anyone doing email threat triage.

What It Does

Header Analysis
  Parses SPF, DKIM, DMARC, Received headers. Identifies spoofing, misalignment, and anomalies.

Body Analysis
  Extracts visible text, detects phishing keywords (e.g., “urgent”, “account suspended”), and flags suspicious greetings or short bodies.

Link Inspection
  Extracts and normalizes URLs. Resolves redirects. Sends to VirusTotal and URLScan.io. Flags mismatches between visible text and actual links.

Attachment Analysis
  Extracts, renames, and scans attachments:
    - Validates file types (vs extension)
    - Checks hash reputation on VirusTotal
    - Uploads to VT for full scans
    - Detects Office macros (via `olevba`)
    - Inspects ZIP archives (contents, encryption)

Final Verdicting Agent
  Uses a structured agent workflow (based on OpenAI’s agents framework) to generate a reasoned, final phishing verdict.

Requirements

Install dependencies:


pip install -r requirements.txt

Dependencies include:

requests, beautifulsoup4, oletools, python-magic, dkimpy, pyspf, dnspython, werkzeug, pydantic

Plus agents-framework if you use the agent orchestration

On macOS, you may need to install libmagic for python-magic to work:

brew install libmagic

Required API Keys

Set these environment variables:

export VT_API_KEY="your_virustotal_api_key"
export URLSCAN_API_KEY="your_urlscan_api_key"
export OPENAI_API_KEY="your_openai_api_key"  # only needed for agents framework

 Running the Script

Run from terminal:

python URLScan\ and\ VirusTotal\ Results\ -\ Need\ API\ keys\ V2.py

The script will prompt you for the path to an .eml file. It will then:

Validate and hash the file

Run header/body/link/attachment analysis

Perform lookups with VirusTotal and URLScan.io

Output a detailed, structured summary with a verdict

File Structure

.
├── URLScan and VirusTotal Results - Need API keys V2.py
├── attachments/            # Saved attachments (auto-created)
├── README.md
└── requirements.txt        # (optional, see below)

Notes

Built-in logging shows intermediate steps and debug info.
It will defang all URLs (e.g., http://example.com → hxxp://example[.]com) to prevent accidental clicks.You can adapt the agent tools for integration into SOC tools, SIEMs, or ticketing systems.
