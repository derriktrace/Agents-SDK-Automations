#!/usr/bin/env python3

# --- START OF CORRECTED SCRIPT ---

from __future__ import annotations
import os
import asyncio
import uuid
import subprocess
import hashlib
import email
import re
import base64
import json
import requests
import time
import ipaddress
from datetime import datetime
from email.message import Message
from typing import List, Dict, Tuple, Any, Optional
import urllib.parse
import zipfile
import mimetypes # For guessing extension from mime type

# Third-party libraries (ensure these are installed)
# Core: requests, pydantic, agents-framework
# Analysis: python-magic, dkimpy, pyspf, dnspython, beautifulsoup4, oletools, werkzeug, ipaddress
import magic  # python-magic
import dkim
import spf
import dns.resolver # Used instead of pydmarc
import dns.exception # Used instead of pydmarc
from bs4 import BeautifulSoup
from oletools import olevba # Part of oletools
from werkzeug.utils import secure_filename # For safe filenames

# --- Configuration & Constants ---

# Attempt to get API keys from environment variables
VT_API_KEY = os.environ.get("VT_API_KEY")
URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY") # Needed for the agents framework

# Validate essential API keys
if not VT_API_KEY:
    print("CRITICAL: VT_API_KEY environment variable not set. VirusTotal analysis will fail.")
    exit(1)
if not URLSCAN_API_KEY:
    print("CRITICAL: URLSCAN_API_KEY environment variable not set. urlscan.io analysis will fail.")
    exit(1)
if not OPENAI_API_KEY:
    print("CRITICAL: OPENAI_API_KEY environment variable not set. Agents framework will fail.")
    exit(1)


VT_BASE_URL = "https://www.virustotal.com/api/v3"
URLSCAN_BASE_URL = "https://urlscan.io/api/v1"
ATTACHMENT_DIR = "attachments"
URLSCAN_POLL_INTERVAL = 7  # Seconds
URLSCAN_MAX_POLLS = 15
REQUEST_TIMEOUT = 30  # Seconds for external HTTP requests

# --- Utility Functions ---

def defang_indicator(indicator: str) -> str:
    """Defangs IPs and domains to prevent accidental clicks."""
    if not indicator:
        return ""
    # Defang domains/hostnames
    indicator = indicator.replace(".", "[.]")
    # Defang http/https protocols
    indicator = indicator.replace("http://", "hxxp://")
    indicator = indicator.replace("https://", "hxxps://")
    return indicator

def safe_get(data: Optional[Dict], keys: List[str], default: Any = None) -> Any:
    """Safely get a nested key from a dictionary."""
    if data is None:
        return default
    temp = data
    for key in keys:
        if isinstance(temp, dict) and key in temp:
            temp = temp[key]
        else:
            return default
    return temp

# --- Analysis Helper Functions ---

def confirm_file_type(filepath: str) -> str:
    """Use python-magic to determine the actual file type, more reliable than 'file' command across OS."""
    try:
        mime_type = magic.from_file(filepath, mime=True)
        description = magic.from_file(filepath)
        return f"{description} (MIME: {mime_type})"
    except Exception as e:
        return f"Error determining file type: {str(e)}"

def calculate_hashes(filepath: str) -> tuple[str | None, str | None]:
    """Calculate MD5 and SHA256 hashes for the file."""
    try:
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
        return md5_hash.hexdigest(), sha256_hash.hexdigest()
    except Exception:
        return None, None

def parse_eml(filepath: str) -> Message | None:
    """Parse the EML file into an email.message.Message object."""
    try:
        with open(filepath, "rb") as f:
            msg = email.message_from_binary_file(f)
        return msg
    except Exception as e:
        print(f"Error parsing EML file {filepath}: {e}")
        return None

def extract_sender_ip_from_headers(msg: Message) -> Optional[str]:
    """
    Attempt to extract the originating external IP address from Received headers.
    Starts from the *last* Received header (closest to the recipient).
    NOTE: This regex is basic and might need refinement for specific header formats.
    """
    received_headers = msg.get_all("Received", [])
    # Regex to find IPs within brackets, often following 'from' or within parens
    ip_pattern = r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]' # More specific IP pattern

    for header_val in reversed(received_headers):
        matches = re.findall(ip_pattern, header_val)
        for ip_str in matches:
             # Check if it looks like an IP and isn't private/special
            try:
                ip = ipaddress.ip_address(ip_str)
                # More strict check: avoid private, loopback, link-local, multicast, reserved
                if not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved):
                    # Check if this IP is associated with 'from' or is the first one listed
                    # Simple check: Assume the first valid public IP found when reading bottom-up is the most likely candidate
                    print(f"DEBUG: Found potential sender IP: {ip_str} in header: {header_val[:100]}...") # Debug print
                    return str(ip) # Return the first valid public IP found
            except ValueError:
                continue # Not a valid IP address string

    print("Warning: Could not reliably determine originating external IP from Received headers.")
    return None

def analyze_headers(msg: Message) -> dict:
    """
    Analyze headers using dkimpy, pyspf, dnspython (for DMARC), and check key headers.
    Requires extracting the sender IP first.
    """
    results = {
        "sender_ip_extracted": None,
        "spf": {"result": "neutral", "explanation": "Could not determine sender IP or From header"},
        "dkim": {"verified": False, "error": None, "results": None},
        "dmarc": {"result": "neutral", "policy": "none", "record": None, "error": None}, # Updated DMARC structure
        "authentication_results": msg.get("Authentication-Results", "Not found"),
        "return_path": msg.get("Return-Path", msg.get("Envelope-From")),
        "from": msg.get("From", "Not found"),
        "reply_to": msg.get("Reply-To", "Not set"),
        "subject": msg.get("Subject", "Not found"),
        "message_id": msg.get("Message-ID", "Not found"),
        "received_path_summary": [],
        "anomalies": []
    }

    sender_ip = extract_sender_ip_from_headers(msg)
    results["sender_ip_extracted"] = sender_ip

    sender_email = msg.get("From")
    sender_domain = None
    if sender_email:
        # Extract email address part if display name is present
        addr_part = email.utils.parseaddr(sender_email)[1]
        if '@' in addr_part:
             sender_domain = addr_part.split('@')[1]

    # SPF Check
    if sender_ip and sender_email:
        # Use the actual address part for SPF check
        spf_identity = email.utils.parseaddr(sender_email)[1]
        helo_domain = "unknown.local" # Default HELO, ideally parse from Received header too
        try:
            # Basic HELO extraction attempt (needs refinement for robustness)
            first_received = msg.get_all("Received", [])
            if first_received:
                # Look for HELO/EHLO in common formats
                helo_match = re.search(r'\((?:EHLO|HELO)\s+([\w\.\-]+)\)', first_received[0], re.IGNORECASE)
                if helo_match:
                    helo_domain = helo_match.group(1)
                else: # Fallback look for name before IP
                     helo_match = re.search(r'from\s+([\w\.\-]+)\s+\(', first_received[0], re.IGNORECASE)
                     if helo_match:
                          helo_domain = helo_match.group(1)

            print(f"DEBUG: Performing SPF check with IP={sender_ip}, Identity={spf_identity}, HELO={helo_domain}") # Debug print
            spf_res, spf_exp = spf.check2(sender_ip, spf_identity, helo_domain)
            results["spf"] = {"result": spf_res, "explanation": spf_exp}
        except Exception as e:
            results["spf"] = {"result": "temperror", "explanation": f"SPF check failed: {e}"}
    else:
         results["spf"]["explanation"] = "Missing sender IP or From address for SPF check."

    # DKIM Check
    try:
        raw_msg_bytes = msg.as_bytes()
        dkim_results = dkim.verify(raw_msg_bytes, include_results=True)
        results["dkim"]["verified"] = dkim_results['verified']
        results["dkim"]["results"] = dkim_results['results']
        if not dkim_results['verified'] and 'error' in dkim_results:
            results["dkim"]["error"] = str(dkim_results['error'])
    except dkim.DKIMException as e: # Catch specific DKIM errors
        results["dkim"]["verified"] = False
        results["dkim"]["error"] = f"DKIM verification failed: {e}"
    except Exception as e: # Catch other unexpected errors
        results["dkim"]["verified"] = False
        results["dkim"]["error"] = f"DKIM verification raised unexpected exception: {e}"

    # --- DMARC Check using dnspython ---
    if sender_domain:
        try:
            dmarc_domain = f"_dmarc.{sender_domain}"
            print(f"DEBUG: Querying DMARC for: {dmarc_domain}") # Debug print
            try:
                answers = dns.resolver.resolve(dmarc_domain, 'TXT')
                dmarc_record_string = None
                for rdata in answers:
                    full_record = "".join(s.decode('utf-8') for s in rdata.strings)
                    if full_record.strip().startswith("v=DMARC1"):
                        dmarc_record_string = full_record
                        break

                if not dmarc_record_string:
                    results["dmarc"]["error"] = "No DMARC record found"
                    results["dmarc"]["result"] = "none"
                else:
                    results["dmarc"]["record"] = dmarc_record_string
                    print(f"DEBUG: Found DMARC record: {dmarc_record_string}") # Debug print
                    policy_match = re.search(r'p=([^;]+)', dmarc_record_string)
                    policy = policy_match.group(1).strip().lower() if policy_match else 'none'
                    results["dmarc"]["policy"] = policy

                    # Simplified Alignment Checks (Placeholders - True alignment is complex)
                    spf_domain_aligned = False
                    dkim_domain_aligned = False

                    # Basic Relaxed SPF Alignment Assumption (INACCURATE - NEEDS MORE DATA FROM SPF CHECK)
                    # Proper check needs the domain SPF authenticated for. check2 doesn't easily provide this.
                    if results["spf"]["result"] == 'pass':
                         spf_domain_aligned = True # Assume aligned if SPF passed for sender domain context

                    # Basic Relaxed DKIM Alignment Check
                    if results["dkim"]["verified"]:
                         for dkim_res in results["dkim"].get("results", []):
                             if dkim_res.get('result') == 'pass':
                                 dkim_signing_domain = dkim_res.get('d')
                                 # Relaxed alignment: dkim_signing_domain must be same or subdomain of sender_domain
                                 if dkim_signing_domain and (dkim_signing_domain == sender_domain or dkim_signing_domain.endswith("." + sender_domain)):
                                     dkim_domain_aligned = True
                                     break # One aligned signature is enough

                    # Evaluate DMARC Result based on simplified alignment
                    if (spf_domain_aligned and results["spf"]["result"] == 'pass') or \
                       (dkim_domain_aligned and results["dkim"]["verified"]):
                        results["dmarc"]["result"] = "pass"
                    else:
                        # If policy is none, result is none regardless of alignment failure
                        # If policy is quarantine or reject, failure leads to 'fail' result
                        if policy == "none":
                             results["dmarc"]["result"] = "none" # Alignment failed, but policy=none
                        else:
                             results["dmarc"]["result"] = "fail" # Alignment failed, policy=quarantine/reject
                    print(f"DEBUG: DMARC Result: {results['dmarc']['result']} (Policy={policy}, SPF Align={spf_domain_aligned}, DKIM Align={dkim_domain_aligned})") # Debug print

            except dns.resolver.NXDOMAIN:
                results["dmarc"]["error"] = "DMARC domain does not exist (NXDOMAIN)"
                results["dmarc"]["result"] = "none"
            except dns.resolver.NoAnswer:
                results["dmarc"]["error"] = "No TXT record found for DMARC"
                results["dmarc"]["result"] = "none"
            except dns.exception.Timeout:
                 results["dmarc"]["error"] = "DNS query for DMARC timed out"
                 results["dmarc"]["result"] = "temperror"
            except Exception as e:
                results["dmarc"]["error"] = f"DMARC DNS lookup failed: {e}"
                results["dmarc"]["result"] = "temperror"

        except Exception as e:
            results["dmarc"] = {"result": "temperror", "policy": None, "record": None, "error": f"DMARC check logic failed: {e}"}
    else:
        results["dmarc"]["error"] = "Missing sender domain for DMARC check."
        results["dmarc"]["result"] = "none"
    # --- End of DMARC Check using dnspython ---


    # Basic Received Path Summary
    received_headers = msg.get_all("Received", [])
    for i, hdr in enumerate(received_headers):
         summary = f"Hop {len(received_headers)-i}: {hdr[:100]}..."
         results["received_path_summary"].append(summary)

    # Basic Anomalies
    if results["return_path"] and results["from"] != "Not found":
        from_addr = email.utils.parseaddr(results["from"])[1]
        # Handle cases where Return-Path is <> or < > for bounces
        if results["return_path"] not in ["<>", "< >"] and results["return_path"] != f"<{from_addr}>":
              results["anomalies"].append(f"Mismatch between From address ({from_addr}) and Return-Path ({results['return_path']})")

    if results["reply_to"] != "Not set" and results["reply_to"] != results["from"]:
         results["anomalies"].append(f"Reply-To ({results['reply_to']}) differs from From ({results['from']})")

    if results["spf"]["result"] not in ['pass', 'none', 'neutral']:
         results["anomalies"].append(f"SPF check resulted in {results['spf']['result']}")
    if not results["dkim"]["verified"]:
         results["anomalies"].append(f"DKIM verification failed or was not present. Error: {results['dkim']['error']}")

    # Updated DMARC anomaly check
    if results["dmarc"]["result"] == 'fail':
         results["anomalies"].append(f"DMARC check resulted in {results['dmarc']['result']} (Policy: {results['dmarc']['policy']})")
    elif results["dmarc"]["result"] not in ['pass', 'none']: # Catch temperror etc.
         results["anomalies"].append(f"DMARC check issue: {results['dmarc']['result']} (Error: {results['dmarc'].get('error', 'N/A')})")

    return results

def extract_urls_and_text(msg: Message) -> Dict[str, Any]:
    """Extract URLs and visible text from text/plain and text/html parts."""
    data = {"urls": [], "body_text": ""}
    body_texts = []

    for part in msg.walk():
        content_type = part.get_content_type()
        charset = part.get_content_charset() or 'utf-8'

        if content_type == "text/plain":
            try:
                text = part.get_payload(decode=True).decode(charset, errors='replace')
                body_texts.append(text)
                found_urls = re.findall(r'https?://[^\s<>"\']+', text)
                for url in found_urls:
                    data["urls"].append({"text": url, "href": url, "source": "text/plain"})
            except Exception as e:
                print(f"Error decoding text/plain part: {e}")
                continue

        elif content_type == "text/html":
            try:
                html = part.get_payload(decode=True).decode(charset, errors='replace')
                soup = BeautifulSoup(html, 'html.parser')
                plain_text = soup.get_text(separator=' ', strip=True)
                if plain_text:
                    body_texts.append(plain_text)
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href'].strip()
                    text = a_tag.get_text(strip=True)
                    # Ensure href is a valid http/https URL before adding
                    if href and href.lower().startswith(('http://', 'https://')):
                        data["urls"].append({"text": text or href, "href": href, "source": "text/html"})
            except Exception as e:
                print(f"Error parsing text/html part: {e}")
                continue

    data["body_text"] = "\n\n".join(body_texts)
    seen_hrefs = set()
    unique_urls = []
    for url_info in data["urls"]:
        href_normalized = url_info["href"]
        if href_normalized not in seen_hrefs:
            unique_urls.append(url_info)
            seen_hrefs.add(href_normalized)
    data["urls"] = unique_urls
    return data

def normalize_url(url: str) -> str:
    """Basic URL normalization."""
    try:
        parsed = urllib.parse.urlparse(url)
        netloc = parsed.netloc.split(':')[0]
        rebuilt = urllib.parse.urlunparse((
            parsed.scheme.lower(),
            netloc.lower(),
            parsed.path, '', '', ''
        ))
        # Remove trailing slash if path is just '/' or empty, unless it's just the domain
        if rebuilt.endswith('/') and urllib.parse.urlparse(rebuilt).path not in ['/']:
             rebuilt = rebuilt[:-1]
        return rebuilt
    except Exception:
        return url

async def check_redirects(url: str, session: requests.Session) -> Tuple[str, List[str], Optional[str]]:
    """Follow redirects and return the final URL and the redirect chain."""
    redirect_chain = []
    final_url = url
    error = None
    try:
        response = await asyncio.to_thread(
            session.get, url, allow_redirects=True, timeout=REQUEST_TIMEOUT, stream=True
        )
        # Consume content to close connection if necessary with stream=True
        response.raise_for_status() # Check for HTTP errors on the final URL
        for resp in response.history:
            redirect_chain.append(resp.url)
        final_url = response.url
        response.close() # Ensure closed
    except requests.exceptions.TooManyRedirects as e:
         error = f"Too many redirects: {e}"
         # Try to get the last URL before failure from exception args if possible
         if e.response and e.response.url: final_url = e.response.url
    except requests.exceptions.RequestException as e:
        error = f"Redirect check failed: {e}"
        # Attempt to get URL from request object if available
        if e.request and e.request.url: final_url = e.request.url
    except Exception as e:
        error = f"Unexpected error during redirect check: {e}"

    # Make sure the original URL is the start if no redirects occurred but request succeeded
    if not redirect_chain and not error and final_url == url:
        redirect_chain.insert(0, url) # Add original if successful and no hops
    elif redirect_chain and redirect_chain[0] != url:
         redirect_chain.insert(0, url) # Ensure original URL is always first

    # If an error occurred, the final_url might be the last successful one or the original
    # The logic above tries to capture the last known URL, otherwise it remains the input `url`

    return final_url, redirect_chain, error

# --- VirusTotal API Functions ---

def vt_url_id(url: str) -> str:
    """Convert URL to VirusTotal's required ID format."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

async def call_vt_api(endpoint: str, method: str = "GET", **kwargs) -> Tuple[Optional[Dict], Optional[str]]:
    """Generic helper to call VirusTotal API asynchronously."""
    headers = {"x-apikey": VT_API_KEY, "Accept": "application/json"}
    url = f"{VT_BASE_URL}/{endpoint}"
    try:
        async with asyncio.Semaphore(10):
            response = await asyncio.to_thread(
                requests.request, method, url, headers=headers, timeout=REQUEST_TIMEOUT, **kwargs
            )
        # Handle different success/error codes
        if response.status_code == 200:
            return response.json(), None
        elif response.status_code == 204: # No content (often for acknowledgements)
             return {}, None
        elif response.status_code == 404:
             return None, "Not found on VirusTotal."
        elif response.status_code == 429:
             # Attempt to parse retry-after header if present
             retry_after = response.headers.get("Retry-After")
             wait_msg = f" Wait {retry_after}s." if retry_after else ""
             return None, f"VirusTotal API rate limit exceeded.{wait_msg}"
        elif response.status_code == 401:
             return None, "VirusTotal API authentication failed (Invalid Key?)."
        else:
            # General error, include text if possible
            error_text = response.text[:200] if response.text else "(No Response Body)"
            return None, f"VirusTotal API Error: {response.status_code} {error_text}"
    except requests.exceptions.Timeout:
        return None, "VirusTotal API request timed out."
    except requests.exceptions.RequestException as e:
        return None, f"VirusTotal API request failed: {e}"
    except Exception as e:
        return None, f"Unexpected error calling VirusTotal API: {e}"

async def analyze_url_virustotal(url: str) -> Tuple[Optional[Dict], Optional[str]]:
    """Query VirusTotal for URL analysis report."""
    url_id = vt_url_id(url)
    return await call_vt_api(f"urls/{url_id}")

async def scan_file_virustotal(file_path: str, file_name: str) -> Tuple[Optional[Dict], Optional[str]]:
    """Upload a file to VirusTotal for scanning. Returns the analysis ID container."""
    endpoint = "files" # Use standard endpoint, handles large files via multipart
    try:
        with open(file_path, "rb") as f:
            files = {"file": (file_name, f)}
            # This POST request might block, run in thread
            data, error = await call_vt_api(endpoint, method="POST", files=files)
            # The response for POST /files contains an analysis object with an ID
            return data, error
    except FileNotFoundError:
        return None, f"File not found for upload: {file_path}"
    except Exception as e:
        return None, f"Exception during VT file upload preparation: {str(e)}"

async def get_vt_analysis_report(analysis_id: str) -> Tuple[Optional[Dict], Optional[str]]:
    """Get the report for a specific VT analysis ID (used after file upload)."""
    return await call_vt_api(f"analyses/{analysis_id}")

async def get_threat_intel_virustotal(file_hash: str) -> Tuple[Optional[Dict], Optional[str]]:
    """Query VirusTotal for file hash reputation."""
    return await call_vt_api(f"files/{file_hash}")

def summarize_vt_url_report(url: str, data: Optional[Dict], error: Optional[str]) -> str:
    """Summarize VirusTotal URL report."""
    if error:
        return f"VT URL Analysis Error ({defang_indicator(url)}): {error}"
    if not data or 'data' not in data or 'attributes' not in data['data']:
        # Handle cases where VT might return 200 OK but no data (rare)
        return f"VT URL Analysis ({defang_indicator(url)}): No data/attributes available in response."

    attrs = data['data']['attributes']
    stats = attrs.get('last_analysis_stats', {})
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    harmless = stats.get('harmless', 0)
    undetected = stats.get('undetected', 0)
    total = malicious + suspicious + harmless + undetected

    verdict = "Unknown"
    if malicious > 0: verdict = "Malicious"
    elif suspicious > 0: verdict = "Suspicious"
    elif total > 0 and harmless >= total * 0.9: verdict = "Likely Harmless" # High confidence for harmless
    elif total > 0: verdict = "Benign/Undetected" # Includes cases with only undetected/harmless below threshold

    categories = list(attrs.get('categories', {}).values())
    category_str = f" Categories: {', '.join(categories)}" if categories else ""
    results = attrs.get('last_analysis_results', {})
    malicious_engines = [engine for engine, result in results.items() if result.get('category') == 'malicious'][:3]
    engines_str = f" Detections: {', '.join(malicious_engines)}" if malicious_engines else ""

    summary = (f"VT URL ({defang_indicator(url)}): Verdict: {verdict} ({malicious} Malicious, {suspicious} Suspicious / {total} Total)."
               f"{category_str}{engines_str}.")
    return summary

def summarize_vt_file_report(file_hash: str, data: Optional[Dict], error: Optional[str], filename: Optional[str]="") -> str:
    """Summarize VirusTotal File report (from hash lookup or analysis report)."""
    fname_str = f" ({secure_filename(filename)})" if filename else ""
    if error:
        # Make error message more concise for context
        error_short = error.split('\n')[0] # Take first line of error
        return f"VT File Analysis Error{fname_str} (Hash: {file_hash[:10]}...): {error_short}"

    attrs = None
    # Handle both direct file report and analysis report structure
    if data and 'data' in data and 'attributes' in data['data']: # Standard file report
        attrs = data['data']['attributes']
    elif data and 'attributes' in data: # Analysis report structure might have attributes at top level
        attrs = data['attributes']
        # Analysis reports might lack 'last_analysis_stats', look for 'stats' instead
        if 'last_analysis_stats' not in attrs and 'stats' in data:
             attrs['last_analysis_stats'] = data['stats'] # Copy stats over if needed

    if not attrs:
         # Check if it was an analysis report that's still queued/in-progress
         meta_status = safe_get(data, ['meta', 'status']) or safe_get(data, ['data', 'attributes', 'status'])
         if meta_status and meta_status != 'completed':
              return f"VT File Analysis{fname_str} (Hash: {file_hash[:10]}...): Report status is '{meta_status}'."
         return f"VT File Analysis{fname_str} (Hash: {file_hash[:10]}...): No attributes data available."

    stats = attrs.get('last_analysis_stats', {})
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    harmless = stats.get('harmless', 0)
    undetected = stats.get('undetected', 0)
    total = malicious + suspicious + harmless + undetected

    verdict = "Unknown"
    # Adjust verdict logic slightly, higher threshold for malicious needed?
    if malicious > 3: verdict = "Malicious" # Be reasonably confident
    elif malicious > 0 or suspicious > 0: verdict = "Suspicious" # Any malicious/suspicious flags it
    elif total > 0 and harmless >= total * 0.95: verdict = "Likely Harmless" # Very high confidence needed
    elif total > 0: verdict = "Benign/Undetected"

    # Meaningful names
    names = attrs.get('meaningful_name', attrs.get('names', ["N/A"]))
    # Ensure names is a list before joining
    name_str = f" Names: {', '.join(names[:2])}" if isinstance(names, list) and names else ""

    # Detections
    results = attrs.get('last_analysis_results', {})
    malicious_engines = []
    if isinstance(results, dict): # Ensure results is a dict before iterating
        malicious_engines = [f"{engine}: {result.get('result', 'detected')}" for engine, result in results.items() if result.get('category') == 'malicious'][:3]
    engines_str = f" Detections: {'; '.join(malicious_engines)}" if malicious_engines else ""

    # File type info
    type_desc = attrs.get('type_description', 'N/A')
    type_tag = attrs.get('type_tag', 'N/A')
    type_str = f" Type: {type_desc} ({type_tag})"

    summary = (f"VT File{fname_str}: Verdict: {verdict} ({malicious} Malicious, {suspicious} Suspicious / {total} Total)."
               f"{name_str}.{type_str}.{engines_str}.")
    return summary

# --- URLScan.io API Functions ---

async def submit_url_to_urlscan(url: str, public: bool = False) -> Tuple[Optional[str], Optional[str]]:
    """Submits URL to urlscan.io and returns the UUID or error."""
    headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}
    data = {"url": url, "public": "on" if public else "off"}
    submit_endpoint = f"{URLSCAN_BASE_URL}/scan/"
    try:
        async with asyncio.Semaphore(5):
            response = await asyncio.to_thread(
                requests.post, submit_endpoint, headers=headers, json=data, timeout=REQUEST_TIMEOUT
            )
        if response.status_code == 200:
            result = response.json()
            scan_id = result.get("uuid")
            return scan_id, None if scan_id else f"urlscan submission successful but no UUID returned: {result}"
        else:
             error_detail = response.text[:200] if response.text else "(No Response Body)"
             if response.status_code == 429: return None, f"urlscan API rate limit exceeded. {error_detail}"
             elif response.status_code == 400: return None, f"urlscan Bad Request: {error_detail}"
             elif response.status_code == 401: return None, f"urlscan Authentication Failed. {error_detail}"
             # Handle specific urlscan errors like "Domain is private/local" (400)
             elif response.status_code == 400 and "private ip" in error_detail.lower():
                 return None, f"urlscan refused scan: Domain resolves to private/local IP."
             else: return None, f"urlscan submission error: {response.status_code}, {error_detail}"
    except requests.exceptions.Timeout: return None, "urlscan submission request timed out."
    except requests.exceptions.RequestException as e: return None, f"urlscan submission request failed: {e}"
    except Exception as e: return None, f"Unexpected error during urlscan submission: {e}"

async def get_urlscan_result(scan_id: str) -> Tuple[Optional[Dict], Optional[str]]:
    """Polls for urlscan.io results."""
    headers = {"API-Key": URLSCAN_API_KEY}
    result_endpoint = f"{URLSCAN_BASE_URL}/result/{scan_id}/"
    for attempt in range(URLSCAN_MAX_POLLS):
        try:
            async with asyncio.Semaphore(10):
                response = await asyncio.to_thread(requests.get, result_endpoint, headers=headers, timeout=REQUEST_TIMEOUT)

            if response.status_code == 200: return response.json(), None
            elif response.status_code == 404: # Not ready yet
                if attempt < URLSCAN_MAX_POLLS - 1: await asyncio.sleep(URLSCAN_POLL_INTERVAL); continue
                else: return None, "urlscan result not ready after multiple attempts."
            elif response.status_code == 429: return None, f"urlscan API rate limit exceeded while fetching results."
            else:
                error_text = response.text[:200] if response.text else "(No Response Body)"
                return None, f"Error fetching urlscan results: {response.status_code}, {error_text}"
        except requests.exceptions.Timeout:
            if attempt < URLSCAN_MAX_POLLS - 1: await asyncio.sleep(URLSCAN_POLL_INTERVAL); continue
            else: return None, "urlscan result fetching timed out after multiple attempts."
        except requests.exceptions.RequestException as e: return None, f"urlscan result fetching request failed: {e}"
        except Exception as e: return None, f"Unexpected error during urlscan result fetch: {e}"
    return None, "urlscan polling completed without success." # Should not be reached

def summarize_urlscan_report(url: str, data: Optional[Dict], error: Optional[str]) -> str:
    """Summarize urlscan.io report."""
    if error:
        return f"URLScan Analysis Error ({defang_indicator(url)}): {error}"
    if not data or 'verdicts' not in data or 'lists' not in data:
        # Check if scan failed within urlscan
        task_status = safe_get(data, ['task', 'status'])
        if task_status and task_status != 'done':
             return f"URLScan Analysis ({defang_indicator(url)}): Scan status is '{task_status}'. No results available."
        return f"URLScan Analysis ({defang_indicator(url)}): No verdict/lists data available in response."

    verdict = "Unknown"
    overall_verdict = safe_get(data, ['verdicts', 'overall'], {})
    # Consider urlscan's specific verdict too
    urlscan_verdict = safe_get(data, ['verdicts', 'urlscan'], {})

    if overall_verdict.get('malicious', False) or urlscan_verdict.get('malicious', False):
        verdict = "Malicious"
    elif overall_verdict.get('score', 0) > 50: # Use score as indicator for suspicious
        verdict = "Suspicious"
    else:
        verdict = "Likely Benign" # Default if not flagged

    # IPs and Domains contacted
    ips = data['lists'].get('ips', [])
    domains = data['lists'].get('domains', [])
    contact_str = f" Contacted {len(ips)} IPs and {len(domains)} unique domains."

    # Malicious flags
    malicious_flags = []
    if overall_verdict.get('malicious'): malicious_flags.append("Overall Malicious")
    if urlscan_verdict.get('malicious'): malicious_flags.append("URLScan Malicious")
    # Could add community verdict etc. if needed
    flags_str = f" Flags: {', '.join(malicious_flags)}." if malicious_flags else ""

    # Link to report
    report_link = safe_get(data, ['task', 'reportURL'], "#")

    summary = (f"URLScan ({defang_indicator(url)}): Verdict: {verdict}."
               f"{contact_str}{flags_str}"
               f" Report: {report_link}")
    return summary

# --- Attachment Specific Analysis ---

def analyze_macros_olevba(filepath: str) -> List[str]:
    """Use olevba to detect VBA macros and potential risks."""
    findings = []
    try:
        vba_parser = olevba.VBA_Parser(filepath)
        if vba_parser.detect_vba_macros():
            findings.append("VBA Macros Found.")
            results = vba_parser.analyze_macros()
            risk_found = False
            for kw_type, keyword, description in results:
                # Focus on higher-risk types
                if kw_type in ['AutoExec', 'Suspicious', 'IOC']:
                    findings.append(f"- {kw_type}: {keyword} ({description})")
                    risk_found = True
                # Option to include strings, but can be verbose
                # elif kw_type in ['Hex String', 'Base64 String']:
                #     findings.append(f"- {kw_type} Found: {keyword[:50]}...")
            if not risk_found:
                 findings.append("- Macros present, but no specific high-risk keywords detected by olevba.")
        else:
            findings.append("No VBA Macros Detected.")
        vba_parser.close()
    except Exception as e:
        findings.append(f"Error analyzing macros with olevba: {e}")
    return findings

def inspect_archive(filepath: str) -> List[str]:
    """Inspect contents of a ZIP archive."""
    findings = []
    try:
        with zipfile.ZipFile(filepath, 'r') as zipf:
            file_list = zipf.namelist()
            findings.append(f"Archive contains {len(file_list)} file(s):")
            # Limit file listing for brevity
            for i, filename in enumerate(file_list):
                findings.append(f"- {filename}")
                if i >= 9: findings.append("- ... (list truncated)"); break
            # Check for encryption using file flags
            info_list = zipf.infolist()
            is_encrypted = any(f.flag_bits & 0x1 for f in info_list)
            if is_encrypted: findings.append("Archive appears to be password protected.")
    except zipfile.BadZipFile: findings.append("Error: Bad or corrupted ZIP file.")
    except Exception as e: findings.append(f"Error inspecting archive: {e}")
    return findings

def extract_attachments(msg: Message, output_dir: str = ATTACHMENT_DIR) -> List[Dict[str, str]]:
    """Extract attachments, save them safely, and return their details."""
    attachments_info = []
    if not os.path.exists(output_dir):
        try: os.makedirs(output_dir)
        except OSError as e: print(f"Error creating attachment directory {output_dir}: {e}"); return []

    counter = 0
    for part in msg.walk():
        content_disposition = str(part.get("Content-Disposition", ""))
        is_attachment_header = "attachment" in content_disposition.lower()
        has_filename = bool(part.get_filename())

        # Consider a part an attachment if Content-Disposition is 'attachment'
        # OR if it's not multipart and has a filename (might be inline but worth scanning)
        # This logic might need refinement based on desired scope (scan inline images?)
        # Let's stick to explicit attachments or non-multipart with filename for now.
        if is_attachment_header or (not part.is_multipart() and has_filename):
        # *** CORRECTED LINE BELOW ***
        # if is_attachment_header: # Rely only on the Content-Disposition check

            original_filename = part.get_filename()
            payload = part.get_payload(decode=True)

            # Skip empty parts that might somehow match
            if not payload:
                continue

            if original_filename:
                # Sanitize filename
                safe_base_filename = secure_filename(original_filename)
                # Handle cases where filename might become empty after sanitization
                if not safe_base_filename:
                     safe_base_filename = f"unsafe_filename_{counter}"
                filename_root, filename_ext = os.path.splitext(safe_base_filename)
                # Ensure counter makes it unique even if root is empty
                saved_filename = f"{filename_root}_{counter}{filename_ext}" if filename_root else f"attachment_{counter}{filename_ext}"
                counter += 1
            else:
                # Generate placeholder name if no filename provided
                content_type = part.get_content_type() or "application/octet-stream"
                ext = mimetypes.guess_extension(content_type) or ".bin"
                saved_filename = f"attachment_{counter}{ext}"
                counter += 1
                original_filename = saved_filename # Use generated name as original for reporting

            file_path = os.path.join(output_dir, saved_filename)

            try:
                with open(file_path, "wb") as f:
                    f.write(payload)
                attachments_info.append({
                    "original_filename": original_filename,
                    "saved_path": file_path,
                    "content_type": part.get_content_type() # Store reported content type
                    })
            except OSError as e:
                 print(f"Error saving attachment {original_filename} to {file_path}: {e}")
                 # Optionally add error info to a list to report back?

    return attachments_info

# --- Phishing Analysis Agent Framework ---

from pydantic import BaseModel, Field

class PhishingAnalysisContext(BaseModel):
    eml_filename: Optional[str] = None
    file_type_confirmed: Optional[str] = None
    md5_hash: Optional[str] = None
    sha256_hash: Optional[str] = None
    eml_hash_vt_summary: Optional[str] = None
    header_analysis_summary: Optional[str] = None
    link_analysis_summary: Optional[str] = None
    attachment_analysis_summary: Optional[str] = None
    body_analysis_summary: Optional[str] = None
    final_assessment: Optional[str] = None

try:
    from agents import (
        Agent, HandoffOutputItem, ItemHelpers, MessageOutputItem, RunContextWrapper,
        Runner, TResponseInputItem, ToolCallItem, ToolCallOutputItem, function_tool, handoff, trace,
    )
    from agents.extensions.handoff_prompt import RECOMMENDED_PROMPT_PREFIX
except ImportError:
    print("\n" + "="*60 + "\nERROR: Failed to import 'agents'. Install 'agents-framework'.\n" + "="*60 + "\n"); exit(1)

# --- Tool Implementations with Enhanced Logic & Summarization ---

@function_tool(
    name_override="file_check_and_hash_tool",
    description_override="Confirm input file is an EML, calculate its hashes (MD5, SHA256), and get VT reputation for the EML hash."
)
async def file_check_and_hash_tool(context: RunContextWrapper[PhishingAnalysisContext], filename: str) -> str:
    """Confirms file type, calculates hashes, and checks EML hash on VirusTotal."""
    if not os.path.exists(filename): return f"Error: File not found at path: {filename}"
    context.context.eml_filename = filename
    file_type = confirm_file_type(filename)
    context.context.file_type_confirmed = file_type

    # Allow processing even if not strictly EML, but warn
    if not ("email" in file_type.lower() or "mime" in file_type.lower() or "rfc 822" in file_type.lower()):
        warning_msg = (f"File '{filename}' confirmed as '{file_type}'. Warning: Does not appear to be standard EML. Proceeding.")
    else:
         warning_msg = ""

    md5, sha256 = calculate_hashes(filename)
    if not md5 or not sha256: return f"Error calculating hashes for file: {filename}"
    context.context.md5_hash = md5
    context.context.sha256_hash = sha256

    vt_data, vt_error = await get_threat_intel_virustotal(sha256)
    vt_summary = summarize_vt_file_report(sha256, vt_data, vt_error, filename=os.path.basename(filename))
    context.context.eml_hash_vt_summary = vt_summary

    return (f"{warning_msg} File Type: {file_type}. MD5: {md5}, SHA256: {sha256}. "
            f"EML File Hash VT Check: {vt_summary}").strip()

@function_tool(
    name_override="analyze_eml_headers_tool",
    description_override="Parses the EML file and analyzes headers for SPF, DKIM, DMARC (using DNS), path anomalies, and spoofing indicators."
)
async def analyze_eml_headers_tool(context: RunContextWrapper[PhishingAnalysisContext], filename: str) -> str:
    """Parses EML and performs detailed header analysis including DNS based DMARC."""
    msg = parse_eml(filename)
    if not msg: return f"Error: Could not parse EML file '{filename}'."

    try:
        analysis_results = analyze_headers(msg)
        # Create a concise summary for the LLM context
        summary_lines = []
        summary_lines.append(f"Sender IP Found: {analysis_results.get('sender_ip_extracted', 'Not Determined')}")
        spf = analysis_results.get('spf', {})
        summary_lines.append(f"SPF: {spf.get('result', 'error')} ({spf.get('explanation', 'N/A')})")
        dkim = analysis_results.get('dkim', {})
        dkim_status = "Verified" if dkim.get('verified') else f"Failed/Missing (Error: {dkim.get('error', 'N/A')})"
        summary_lines.append(f"DKIM: {dkim_status}")

        # Updated DMARC summary generation using results from dnspython check
        dmarc = analysis_results.get('dmarc', {})
        dmarc_summary_str = f"DMARC: {dmarc.get('result', 'error')} (Policy: {dmarc.get('policy', 'N/A')}"
        if dmarc.get('error'):
             # Make error snippet more concise if long
             error_str = str(dmarc['error'])
             dmarc_summary_str += f", Error: {error_str[:60]}{'...' if len(error_str)>60 else ''}"
        elif dmarc.get('record'):
             dmarc_summary_str += f", Record: {dmarc['record'][:60]}{'...' if len(dmarc['record'])>60 else ''}"
        dmarc_summary_str += ")"
        summary_lines.append(dmarc_summary_str)

        auth_res = analysis_results.get('authentication_results', 'Not Found')
        # Truncate potentially very long auth results header
        if len(auth_res) > 150: auth_res = auth_res[:150] + "... (truncated)"
        summary_lines.append(f"Authentication-Results Header: {auth_res}")

        # List anomalies found
        if analysis_results.get('anomalies'):
            summary_lines.append("Anomalies Detected:")
            for anomaly in analysis_results['anomalies']: summary_lines.append(f"- {anomaly}")

        summary = "\n".join(summary_lines)
        context.context.header_analysis_summary = summary
        return f"Header analysis complete:\n{summary}"

    except Exception as e:
        import traceback; traceback.print_exc() # Print full traceback for debugging
        error_msg = f"Unexpected error during header analysis: {str(e)}"
        context.context.header_analysis_summary = error_msg
        return error_msg

@function_tool(
    name_override="analyze_eml_body_tool",
    description_override="Extracts text content from the EML body (text and HTML), and performs basic analysis for phishing keywords or suspicious patterns."
)
async def analyze_eml_body_tool(context: RunContextWrapper[PhishingAnalysisContext], filename: str) -> str:
    """Extracts and analyzes body text content."""
    msg = parse_eml(filename)
    if not msg: return f"Error: Could not parse EML file '{filename}' for body analysis."

    try:
        extracted_data = extract_urls_and_text(msg)
        body_text = extracted_data.get("body_text", "")
        if not body_text: context.context.body_analysis_summary = "No text body content found."; return "No text body content found."

        findings = []
        # Simple keyword checks (case-insensitive)
        urgency_keywords = ['urgent', 'important', 'action required', 'verify', 'validate', 'suspended', 'limited access', 'immediately', 'password', 'username']
        financial_keywords = ['invoice', 'payment', 'refund', 'bank', 'account', 'credit card', 'confirm details', 'unusual activity', 'statement']
        generic_greetings = ['dear customer', 'dear user', 'hello valued member', 'dear account holder'] # Add more common ones

        lower_body = body_text.lower()
        for keyword in urgency_keywords:
            if keyword in lower_body: findings.append(f"Urgency/Security keyword found: '{keyword}'")
        for keyword in financial_keywords:
             if keyword in lower_body: findings.append(f"Financial keyword found: '{keyword}'")
        # Check anywhere in the first few lines for generic greeting
        for greeting in generic_greetings:
             if greeting in lower_body[:100]: # Check near beginning
                 findings.append(f"Generic greeting found: '{greeting}'")
        # Basic check for short body
        if len(body_text.strip()) < 150: # Slightly longer threshold
             findings.append("Note: Email body content is relatively short.")

        # Summarize findings
        summary = "Body text analysis: No immediate high-risk keywords found (basic check)."
        if findings:
             # Limit number of findings reported to avoid excessive length
             summary = "Body text analysis findings:\n" + "\n".join([f"- {f}" for f in findings[:5]]) # Report top 5 findings
             if len(findings) > 5: summary += "\n- ... (additional findings truncated)"

        context.context.body_analysis_summary = summary
        return summary

    except Exception as e:
        error_msg = f"Unexpected error during body analysis: {str(e)}"
        context.context.body_analysis_summary = error_msg
        return error_msg

@function_tool(
    name_override="analyze_eml_links_tool",
    description_override="Extracts URLs from EML (text & HTML), checks redirects, analyzes with VirusTotal and URLScan.io, compares visible link text with actual href."
)
async def analyze_eml_links_tool(context: RunContextWrapper[PhishingAnalysisContext], filename: str) -> str:
    """Extracts, analyzes URLs using VT and URLScan, checks redirects and text/href mismatches."""
    msg = parse_eml(filename)
    if not msg: return f"Error: Could not parse EML file '{filename}' for link analysis."

    try:
        extracted_data = extract_urls_and_text(msg)
        urls_info = extracted_data.get("urls", [])
        if not urls_info: context.context.link_analysis_summary = "No URLs found in the email body."; return "No URLs found."

        link_summaries = []
        session = requests.Session() # Use a session for potential connection reuse
        unique_normalized_hrefs = set()
        urls_to_process = []

        # --- Link Pre-processing ---
        for url_data in urls_info:
            original_href = url_data['href']
            link_text = url_data['text']
            source_part = url_data['source']

            # Check for text/href mismatches (only for HTML links)
            if source_part == 'text/html' and link_text != original_href and original_href.startswith(('http', 'hxxp')):
                 try:
                     # Parse domains, handle potential errors
                     text_domain = urllib.parse.urlparse(link_text).netloc if link_text.startswith(('http', 'hxxp')) else None
                     href_domain = urllib.parse.urlparse(original_href).netloc

                     # Check if domains differ significantly (ignore www.)
                     if href_domain and text_domain and text_domain.replace('www.','').lower() != href_domain.replace('www.','').lower():
                          link_summaries.append(f"Mismatch Warning: Text '{link_text[:50]}...' points to different domain href '{defang_indicator(original_href[:70])}...'.")
                     elif not href_domain and text_domain: # Text looks like URL but href is not? Suspicious.
                          link_summaries.append(f"Mismatch Warning: Link text looks like URL '{link_text[:50]}...' but has non-URL/malformed href '{original_href[:70]}...'.")

                 except Exception as parse_err: # Handle potential URL parsing errors
                      print(f"DEBUG: Error parsing URL for mismatch check: {parse_err} (Text: {link_text}, Href: {original_href})")
                      # Still note potential mismatch if text doesn't match href literally
                      link_summaries.append(f"Mismatch Warning: Potential mismatch text '{link_text[:50]}...' vs href '{defang_indicator(original_href[:70])}...'.")

            # Normalize URL for analysis
            normalized_href = normalize_url(original_href)

            # Add to processing list if it's a valid HTTP/S URL and not already seen
            if normalized_href.startswith(('http://', 'https://')) and normalized_href not in unique_normalized_hrefs:
                unique_normalized_hrefs.add(normalized_href)
                urls_to_process.append({'original': original_href, 'normalized': normalized_href})

        # --- Concurrent URL Analysis ---
        async def process_single_url(url_info_dict):
            """Coroutine to handle analysis steps for one unique normalized URL."""
            # orig_url = url_info_dict['original'] # Original URL not used downstream currently
            norm_url = url_info_dict['normalized']
            url_results = [f"--- Analysis for URL: {defang_indicator(norm_url)} ---"]

            # 1. Check Redirects
            final_url, redirect_chain, redirect_error = await check_redirects(norm_url, session)
            if redirect_error:
                 url_results.append(f"Redirect Check Failed: {redirect_error}")
                 # Decide if analysis should stop or proceed with original URL on error
                 url_to_scan = norm_url # Use original normalized URL if redirect check fails
            elif len(redirect_chain) > 1:
                 defanged_chain = " -> ".join(map(defang_indicator, redirect_chain))
                 url_results.append(f"Redirect Chain: {defanged_chain}")
                 url_to_scan = final_url # Use the final destination URL after redirects
            else:
                 url_results.append("Redirect Check: No redirects detected.")
                 url_to_scan = norm_url # No redirects, use the original normalized URL

            # 2. VirusTotal Analysis (on the final or original URL)
            vt_data, vt_error = await analyze_url_virustotal(url_to_scan)
            vt_summary = summarize_vt_url_report(url_to_scan, vt_data, vt_error)
            url_results.append(vt_summary)

            # 3. URLScan.io Analysis (on the final or original URL)
            # Check if URLScan should be skipped (e.g., for internal/private IPs if detected, though submit handles this)
            submit_uuid, submit_error = await submit_url_to_urlscan(url_to_scan)
            if submit_error:
                urlscan_summary = f"URLScan Submit Error ({defang_indicator(url_to_scan)}): {submit_error}"
            elif submit_uuid:
                # Wait and poll for results
                urlscan_data, urlscan_error = await get_urlscan_result(submit_uuid)
                urlscan_summary = summarize_urlscan_report(url_to_scan, urlscan_data, urlscan_error)
            else:
                urlscan_summary = f"URLScan ({defang_indicator(url_to_scan)}): Submission failed silently (No UUID)."

            url_results.append(urlscan_summary)
            return "\n".join(url_results) # Combine results for this URL

        if urls_to_process:
            tasks = [process_single_url(url_dict) for url_dict in urls_to_process]
            url_analysis_results = await asyncio.gather(*tasks)
            link_summaries.extend(url_analysis_results)

        session.close() # Close the requests session

        # --- Final Summary Formatting ---
        if not link_summaries:
             final_summary = "Link analysis performed, but no conclusive results or significant findings from processed URLs."
        else:
             # Combine initial warnings (mismatches) and detailed analysis results
             final_summary = "Link Analysis Results:\n" + "\n\n".join(link_summaries)

        # Limit overall summary length if needed
        if len(final_summary) > 3000: # Example limit for LLM context
             final_summary = final_summary[:3000] + "... (Link summary truncated)"

        context.context.link_analysis_summary = final_summary
        return final_summary

    except Exception as e:
        import traceback; traceback.print_exc()
        error_msg = f"Unexpected error during link analysis: {str(e)}"
        context.context.link_analysis_summary = error_msg
        return error_msg


@function_tool(
    name_override="analyze_eml_attachments_tool",
    description_override="Extracts attachments, verifies file types, checks hashes on VirusTotal, scans files, inspects archives, and checks for Office macros."
)
async def analyze_eml_attachments_tool(context: RunContextWrapper[PhishingAnalysisContext], filename: str) -> str:
    """Extracts and analyzes email attachments."""
    msg = parse_eml(filename)
    if not msg: return f"Error: Could not parse EML file '{filename}' for attachment analysis."

    try:
        # *** CORRECTED FUNCTION CALL ***
        # Call extract_attachments, handle potential errors during extraction
        try:
            extracted_attachments = extract_attachments(msg, ATTACHMENT_DIR)
        except Exception as extraction_err:
             import traceback; traceback.print_exc()
             err_msg = f"Error during attachment extraction phase: {extraction_err}"
             context.context.attachment_analysis_summary = err_msg
             return err_msg

        if not extracted_attachments:
            context.context.attachment_analysis_summary = "No attachments found or extracted."
            return "No attachments found or extracted."

        # --- Concurrent Attachment Analysis ---
        async def process_single_attachment(att_info):
            """Coroutine to handle analysis steps for one attachment."""
            original_filename = att_info['original_filename']
            saved_path = att_info['saved_path']
            content_type = att_info.get('content_type', 'N/A') # Use .get for safety
            att_results = [f"--- Attachment: {secure_filename(original_filename)} ---"]

            # Basic info
            try:
                 file_size = os.path.getsize(saved_path)
                 att_results.append(f"Size: {file_size} bytes")
            except OSError:
                 att_results.append("Size: Error getting size")

            # 1. File Type Verification
            actual_file_type = confirm_file_type(saved_path)
            att_results.append(f"Reported Type: {content_type}, Actual Type: {actual_file_type}")
            _, ext = os.path.splitext(original_filename); ext = ext.lower()
            if ext and ext != ".eml": # Ignore eml within eml for mismatch typically
                mismatch = False
                # Basic mismatch checks (can be expanded)
                if ("executable" in actual_file_type.lower()) and ext not in ['.exe', '.dll', '.scr', '.msi', '.com', '.bat', '.cmd', '.ps1']: mismatch = True
                elif ("microsoft office" in actual_file_type.lower() or "word" in actual_file_type.lower() or "excel" in actual_file_type.lower() or "powerpoint" in actual_file_type.lower()) and ext not in ['.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm', '.ppt', '.pptx', '.pptm']: mismatch = True
                elif ("pdf" in actual_file_type.lower()) and ext not in ['.pdf']: mismatch = True
                elif ("zip" in actual_file_type.lower() or "archive" in actual_file_type.lower()) and ext not in ['.zip', '.rar', '.7z', '.iso', '.img', '.tar', '.gz', '.arj']: mismatch = True
                elif ("image" in actual_file_type.lower()) and ext not in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tif', '.tiff', '.webp', '.svg']: mismatch = True
                # Add more types as needed (scripts, etc.)
                if mismatch: att_results.append(f"Warning: File extension '{ext}' might mismatch actual type '{actual_file_type}'.")

            # 2. Calculate Hashes
            md5, sha256 = calculate_hashes(saved_path)
            if not sha256:
                 att_results.append("Error calculating attachment hash.")
                 # Cannot proceed with VT hash check or scan effectively without hash
                 return "\n".join(att_results)
            else:
                 att_results.append(f"SHA256: {sha256}")

            # 3. Check Hash Reputation on VirusTotal First
            vt_hash_data, vt_hash_error = await get_threat_intel_virustotal(sha256)
            vt_hash_summary = summarize_vt_file_report(sha256, vt_hash_data, vt_hash_error, filename=original_filename)
            att_results.append(f"VT Hash Check: {vt_hash_summary}")

            # Determine if full scan is necessary based on hash check
            needs_scan = True
            # If hash check resulted in definite error (not just 'Not found'), maybe skip scan
            if vt_hash_error and "Not found" not in vt_hash_error:
                 needs_scan = False
            # Add logic here based on vt_hash_data if desired (e.g., skip if already known good/bad and recent?)
            # Example: Skip scan if known good from hash check
            # if vt_hash_data and "Likely Harmless" in vt_hash_summary:
            #     needs_scan = False
            #     att_results.append("VT Scan skipped (Known good/harmless hash).")

            # 4. Upload and Scan File on VirusTotal (if needed)
            if needs_scan:
                scan_submission_data, scan_submit_error = await scan_file_virustotal(saved_path, original_filename)

                if scan_submit_error:
                    att_results.append(f"VT Scan Submission Error: {scan_submit_error}")
                elif scan_submission_data and 'data' in scan_submission_data and 'id' in scan_submission_data['data']:
                    analysis_id = scan_submission_data['data']['id']
                    att_results.append(f"VT Scan Submitted (ID: {analysis_id}). Waiting for results...")
                    # Poll for results (simple loop, could be more robust)
                    analysis_data, analysis_error = None, "Polling timeout/incomplete"
                    for poll_attempt in range(6): # Poll up to ~1.5 mins (6 * 15s)
                        await asyncio.sleep(15) # Wait between polls
                        analysis_data, analysis_error = await get_vt_analysis_report(analysis_id)
                        # Check for terminal states (completed, failed) or errors
                        status = safe_get(analysis_data, ['data', 'attributes', 'status'])
                        if status == 'completed': break
                        if analysis_error and "Not found" not in analysis_error: break # Permanent error
                        if poll_attempt == 5: analysis_error = "Polling timed out before completion." # Set timeout error

                    # Summarize the analysis report (might have different structure than file report)
                    vt_scan_summary = summarize_vt_file_report(sha256, analysis_data, analysis_error, filename=original_filename)
                    att_results.append(f"VT Scan Result: {vt_scan_summary}")
                else:
                    # Handle cases where submission might succeed (200 OK) but not return expected data
                    att_results.append(f"VT Scan Submission response invalid or missing analysis ID: {scan_submission_data}")
            # else: # Message moved above if skipping due to known good hash
            #     att_results.append("VT Scan skipped based on hash check result or previous error.")

            # 5. Specific File Type Analysis (run regardless of VT scan outcome)
            # Office Macro Analysis
            office_types = ["microsoft office", "word", "excel", "powerpoint"]
            office_ext = ['.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm', '.ppt', '.pptx', '.pptm']
            if any(t in actual_file_type.lower() for t in office_types) or ext in office_ext:
                macro_findings = await asyncio.to_thread(analyze_macros_olevba, saved_path)
                if macro_findings and not ("No VBA Macros Detected." in macro_findings and len(macro_findings) == 1):
                    att_results.append("Macro Analysis (olevba):")
                    att_results.extend([f"  {f}" for f in macro_findings]) # Indent findings

            # Archive Inspection (ZIP only for now)
            if "zip archive" in actual_file_type.lower() or ext == ".zip":
                archive_findings = await asyncio.to_thread(inspect_archive, saved_path)
                if archive_findings:
                    att_results.append("Archive Inspection (ZIP):")
                    att_results.extend([f"  {f}" for f in archive_findings]) # Indent findings
            # Add similar checks for .rar, .7z etc. if needed, requires external libraries like 'patool' + binaries

            return "\n".join(att_results)

        # --- Execute Tasks Concurrently ---
        tasks = [process_single_attachment(att) for att in extracted_attachments]
        attachment_analysis_results = await asyncio.gather(*tasks)

        # --- Final Summary Formatting ---
        if not attachment_analysis_results:
            final_summary = "Attachment analysis performed, but no conclusive results."
        else:
            # Join summaries for each attachment
            final_summary = "Attachment Analysis Results:\n\n" + "\n\n".join(attachment_analysis_results)

        # Limit overall summary length if needed
        if len(final_summary) > 3000: # Example limit
             final_summary = final_summary[:3000] + "... (Attachment summary truncated)"

        context.context.attachment_analysis_summary = final_summary
        return final_summary

    except Exception as e:
        import traceback; traceback.print_exc()
        error_msg = f"Unexpected error during attachment analysis orchestration: {str(e)}"
        context.context.attachment_analysis_summary = error_msg
        return error_msg


@function_tool(
    name_override="final_assessment_tool",
    description_override="Compiles all collected analysis summaries (EML hash, headers, body, links, attachments) and provides a final phishing assessment verdict and justification."
)
async def final_assessment_tool(context: RunContextWrapper[PhishingAnalysisContext], verdict: str, justification: str) -> str:
    """Stores the final assessment provided by the LLM based on summaries."""
    # Basic validation of verdict
    allowed_verdicts = ["Malicious", "Suspicious", "Likely Benign", "Benign", "Unknown", "Inconclusive"]
    if verdict not in allowed_verdicts:
        verdict = f"Unknown (Invalid verdict provided: {verdict})" # Default if invalid

    final_report = (
        f"--- FINAL ASSESSMENT ---\n\n"
        f"Verdict: {verdict}\n\n"
        f"Justification:\n{justification}\n\n"
        f"--- Supporting Evidence Summaries ---\n\n"
        f"EML Hash Check:\n{context.context.eml_hash_vt_summary or 'Not available/Not performed'}\n\n"
        f"Header Analysis:\n{context.context.header_analysis_summary or 'Not available/Not performed'}\n\n"
        f"Body Analysis:\n{context.context.body_analysis_summary or 'Not available/Not performed'}\n\n"
        f"Link Analysis:\n{context.context.link_analysis_summary or 'Not available/Not performed'}\n\n"
        f"Attachment Analysis:\n{context.context.attachment_analysis_summary or 'Not available/Not performed'}\n"
        f"--------------------------"
    )
    context.context.final_assessment = final_report
    # Return a confirmation message to the agent
    return f"Final assessment recorded successfully with verdict: {verdict}"

# --- Agent Definitions ---

initial_analysis_agent = Agent[PhishingAnalysisContext](
    name="Initial Analysis Agent",
    handoff_description="Agent for initial file validation, hashing, and EML hash reputation check.",
    instructions=f"""{RECOMMENDED_PROMPT_PREFIX}
    You are the Initial Analysis Agent. Your tasks are:
    1. Receive the EML filename.
    2. Verify the file exists and appears to be an EML file using `file_check_and_hash_tool`.
    3. This tool also calculates MD5/SHA256 hashes and gets the VirusTotal reputation for the EML file's hash.
    4. Review the tool's output (file type, hashes, VT summary for the EML itself). Note any warnings about file type.
    5. If successful (hashes calculated), hand off the filename and initial findings (hashes, VT summary) to the Detailed Analysis Agent.
    6. If the file is not found or hashing fails, report the error clearly and stop.""",
    tools=[file_check_and_hash_tool],
    handoffs=[]
)

detailed_analysis_agent = Agent[PhishingAnalysisContext](
    name="Detailed Analysis Agent",
    handoff_description="Agent for in-depth analysis of headers, body, links, and attachments.",
    instructions=f"""{RECOMMENDED_PROMPT_PREFIX}
    You are the Detailed Analysis Agent. You have received the EML filename and initial hash info. Your responsibilities are:
    1. Analyze the EML headers using `analyze_eml_headers_tool`. Review the summary for SPF/DKIM/DMARC results and anomalies. Note reliability issues if sender IP wasn't found.
    2. Analyze the EML body content using `analyze_eml_body_tool`. Review the summary for suspicious keywords or patterns.
    3. Analyze the links within the EML using `analyze_eml_links_tool`. Review the summary for malicious/suspicious verdicts from VT/URLScan, redirects, and text/href mismatches.
    4. Analyze the attachments using `analyze_eml_attachments_tool`. Review the summary for malicious/suspicious verdicts, risky file types, macros, or archive contents.
    5. Ensure all tools are called with the correct EML filename provided in the context. Call tools sequentially.
    6. Once all analyses are complete (or if a tool returns a critical error preventing further analysis), hand off all collected summary information (headers, body, links, attachments) to the Final Assessment Agent.""",
    tools=[analyze_eml_headers_tool, analyze_eml_body_tool, analyze_eml_links_tool, analyze_eml_attachments_tool],
    handoffs=[]
)

final_assessment_agent = Agent[PhishingAnalysisContext](
    name="Final Assessment Agent",
    handoff_description="Agent for compiling the final phishing report based on analysis summaries.",
    instructions=f"""{RECOMMENDED_PROMPT_PREFIX}
    You are the Final Assessment Agent. You have received summaries of the EML analysis (EML hash VT check, headers, body, links, attachments). Your job is to:
    1. Carefully review ALL provided analysis summaries. Synthesize the findings, noting both malicious/suspicious indicators and benign ones.
    2. Identify the most critical indicators. Consider the combination of factors (e.g., Auth failures + bad links are worse than just auth failures). Note if key checks (like sender IP for SPF) were unreliable.
    3. Determine a final verdict from: Malicious, Suspicious, Likely Benign, Benign, Unknown/Inconclusive.
    4. Write a clear, concise justification for your verdict, referencing specific findings from the summaries (e.g., "SPF failed (sender IP unknown), VT marked URL example[.]com as malicious (Score: 10/90), attachment contained suspicious macros"). Do not just list summaries.
    5. Use the `final_assessment_tool` by providing your `verdict` and `justification`. Be precise.""",
    tools=[final_assessment_tool],
    handoffs=[]
)

# Set the handoffs to form a linear chain
initial_analysis_agent.handoffs = [detailed_analysis_agent]
detailed_analysis_agent.handoffs = [final_assessment_agent]

# The SOC Triage Agent delegates directly to the Initial Analysis Agent
triage_agent = Agent[PhishingAnalysisContext](
    name="SOC Triage Agent",
    handoff_description="SOC Triage Agent that delegates EML analysis tasks.",
    instructions=f"""{RECOMMENDED_PROMPT_PREFIX}
    You are the SOC Triage Agent. Your primary role is to receive the initial request containing the path to an EML file.
    1. Identify the EML file path from the user input.
    2. Immediately hand off the request (specifically, the filename as a string) to the Initial Analysis Agent to begin the standard phishing analysis workflow.
    Do not perform any analysis yourself. Just initiate the handoff.""",
    tools=[], # No tools needed, just handoff
    handoffs=[initial_analysis_agent]
)

# --- Main Execution Loop ---

async def main():
    print("--- Phishing Analysis Agent ---")
    print("Ensure VT_API_KEY, URLSCAN_API_KEY, and OPENAI_API_KEY are set.")

    current_agent: Agent[PhishingAnalysisContext] = triage_agent
    input_items: list[TResponseInputItem] = []
    context = PhishingAnalysisContext()
    conversation_id = uuid.uuid4().hex[:16]

    # Get initial EML file path from user
    while True:
        user_input = input("Enter the full path to the EML file for analysis: ")
        # Basic check if path exists and is a file
        if os.path.isfile(user_input):
            break
        else:
            print(f"Error: File not found or is not a file at '{user_input}'. Please provide a valid path.")

    # Initial message to start the process - pass filename clearly
    input_items.append({"content": f"Analyze EML file: {user_input}", "role": "user"})

    # Run the agent chain within a tracing context
    with trace("Phishing Analysis Workflow", group_id=conversation_id):
        while True: # Loop until final assessment is done or an error stops the chain
            print(f"\n--- Running Agent: {current_agent.name} ---")
            try:
                # Run the current agent
                result = await Runner.run(current_agent, input_items, context=context)
            except Exception as e:
                 # Catch errors during agent execution (e.g., LLM call failure)
                 print(f"\n!!! Agent execution failed unexpectedly: {e} !!!")
                 import traceback; traceback.print_exc()
                 break # Stop the process on agent error

            last_item = result.new_items[-1] if result.new_items else None

            # Print Agent's reasoning and actions for observability
            for new_item in result.new_items:
                agent_name = new_item.agent.name
                if isinstance(new_item, MessageOutputItem):
                    # Clean up message formatting slightly for printing
                    content = ItemHelpers.text_message_output(new_item).strip()
                    # Avoid printing empty messages
                    if content: print(f"[{agent_name} - Thought/Msg]:\n{content}\n")
                elif isinstance(new_item, ToolCallItem):
                    # *** CORRECTED TOOLCALLITEM ACCESS ***
                    tool_name = new_item.tool_name
                    tool_args = new_item.tool_arguments
                    print(f"[{agent_name} - Action]: Calling tool '{tool_name}' with args: {tool_args}")
                elif isinstance(new_item, ToolCallOutputItem):
                    # Print tool output (important for debugging)
                    # Truncate long outputs for cleaner console
                    output_str = str(new_item.output)
                    if len(output_str) > 1000: output_str = output_str[:1000] + "... (output truncated)"
                    print(f"[{agent_name} - Tool Output]:\n{output_str}\n")
                elif isinstance(new_item, HandoffOutputItem):
                    print(f"[{new_item.source_agent.name} -> {new_item.target_agent.name}]: Handing off analysis.")
                    # Optionally print handoff message content if needed for debugging
                    # print(f"Handoff Message: {new_item.message}")
                else:
                    # Print type of any unexpected items
                    print(f"[{agent_name}]: Processing item type: {new_item.__class__.__name__}")

            # Update input items for the next agent in the chain
            input_items = result.to_input_list()
            current_agent = result.last_agent

            # Check for completion state (final assessment generated)
            if context.final_assessment:
                print("\n" + "="*30 + " Analysis Complete " + "="*30)
                print(context.final_assessment)
                break

            # Check if the process stalled or ended without assessment
            if not isinstance(last_item, (HandoffOutputItem, ToolCallItem)):
                 # If the last action wasn't a tool call (waiting for output) or a handoff,
                 # the agent might have finished its turn without planning further action.
                 if current_agent.name != final_assessment_agent.name:
                      # If not the final agent, it should have handed off or called a tool
                      print(f"\n!!! Warning: Agent {current_agent.name} finished without handing off or reaching final assessment. Process might be stalled. Check agent logic/prompts. !!!")
                 elif not context.final_assessment:
                      # Final agent finished but didn't produce assessment via the tool
                      print(f"\n!!! Error: Final Assessment Agent finished but failed to produce a final assessment report using the tool. Check agent logic/prompts. !!!")
                 break # Exit loop if process seems stalled or ended unexpectedly


if __name__ == "__main__":
    # Check for essential libraries on startup
    try:
        import magic; import dkim; import spf; import dns.resolver
        import bs4; import oletools; import werkzeug; import agents
        import ipaddress; import requests; import pydantic
    except ImportError as e:
         print(f"\nERROR: Missing required library: {e.name}. Please install all dependencies:")
         # Provide pip command, adjust based on OS needs for python-magic
         print("pip install python-magic-bin dkimpy pyspf dnspython beautifulsoup4 oletools requests pydantic agents-framework werkzeug ipaddress")
         print("Note: On Linux, you might need 'pip install python-magic' and ensure 'libmagic1' is installed via package manager (apt/yum).")
         exit(1)

    # Run the main async function
    asyncio.run(main())

# --- END OF CORRECTED SCRIPT ---