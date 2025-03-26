#!/usr/bin/env python3

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

import dkim
import spf

# Set API keys (fakes for demonstration or testing)
os.environ["VT_API_KEY"] = "KEY HERE"
os.environ["OPENAI_API_KEY"] = "KEY HERE"
os.environ["URLSCAN_API_KEY"] = "KEY HERE"

VT_API_KEY = os.environ.get("VT_API_KEY")
if not VT_API_KEY:
    print("Please set the VT_API_KEY environment variable with your VirusTotal API key.")
    exit(1)

URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY")
if not URLSCAN_API_KEY:
    print("Please set the URLSCAN_API_KEY environment variable with your urlscan.io API key.")
    exit(1)

########################################
# Actual Analysis Helper Functions
########################################

def confirm_file_type(filepath: str) -> str:
    """Use the 'file' command to determine the file type."""
    try:
        output = subprocess.check_output(["file", "-b", filepath])
        return output.strip().decode("utf-8")
    except Exception as e:
        return f"Error determining file type: {str(e)}"

def calculate_hashes(filepath: str) -> tuple[str, str]:
    """Calculate MD5 and SHA256 hashes for the file."""
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            md5_hash.update(chunk)
            sha256_hash.update(chunk)
    return md5_hash.hexdigest(), sha256_hash.hexdigest()

def parse_eml(filepath: str) -> email.message.Message:
    """Parse the EML file into an email.message.Message object."""
    with open(filepath, "rb") as f:
        msg = email.message_from_binary_file(f)
    return msg

def analyze_headers(msg: email.message.Message) -> dict:
    """
    Analyze headers using dkimpy and pyspf.
    (Note: SPF check here uses dummy values for sender IP and HELO.)
    """
    raw_msg = msg.as_bytes()
    dkim_verified = dkim.verify(raw_msg)
    sender = msg.get("From", "example@example.com")
    dummy_ip = "8.8.8.8"      # Replace with actual sender IP if available
    dummy_helo = "mail.example.com"
    spf_result, spf_comment = spf.check2(dummy_ip, sender, dummy_helo)
    return {
        "dkim_verified": dkim_verified,
        "spf_result": spf_result,
        "spf_comment": spf_comment
    }

def extract_urls(msg: email.message.Message) -> list[str]:
    """Extract URLs from all text/plain parts of the email."""
    urls = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    text = part.get_payload(decode=True).decode(errors="ignore")
                    urls.extend(re.findall(r'https?://[^\s]+', text))
                except Exception:
                    continue
    else:
        try:
            text = msg.get_payload(decode=True).decode(errors="ignore")
            urls.extend(re.findall(r'https?://[^\s]+', text))
        except Exception:
            pass
    return list(set(urls))

def vt_url_id(url: str) -> str:
    """
    Convert the URL to a URL-safe base64 encoded string without padding,
    as required by the VirusTotal API.
    """
    encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return encoded

def analyze_url_virustotal(url: str) -> dict:
    """Query VirusTotal for URL analysis."""
    url_id = vt_url_id(url)
    headers = {"x-apikey": VT_API_KEY}
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    response = requests.get(vt_url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"Error analyzing URL (VirusTotal): {response.status_code} {response.text}"}

def analyze_url_with_urlscan(url: str, api_key: str = URLSCAN_API_KEY) -> dict:
    """
    Submits a URL to urlscan.io for scanning and returns the results once completed.
    """
    headers = {
        "API-Key": api_key,
        "Content-Type": "application/json",
    }

    submit_endpoint = "https://urlscan.io/api/v1/scan/"
    data = {
        "url": url,
        "public": "off",  # or "on" if you'd like it public
    }
    try:
        # Submit the URL for scanning
        submit_resp = requests.post(submit_endpoint, headers=headers, json=data)
        if submit_resp.status_code != 200:
            return {
                "error": f"urlscan submit error: {submit_resp.status_code}, {submit_resp.text}"
            }
        submit_result = submit_resp.json()
        scan_id = submit_result.get("uuid")
        if not scan_id:
            return {"error": f"No scan ID returned from urlscan: {submit_result}"}

        # Poll for results
        result_endpoint = f"https://urlscan.io/api/v1/result/{scan_id}/"
        for _ in range(10):  # Poll up to 10 times
            time.sleep(5)
            result_resp = requests.get(result_endpoint, headers=headers)
            if result_resp.status_code == 200:
                # Scan is complete
                return result_resp.json()
            elif result_resp.status_code == 404:
                # Not ready yet, continue polling
                continue
            else:
                return {
                    "error": f"Error fetching urlscan results: {result_resp.status_code}, {result_resp.text}"
                }

        # If not returned within the polling window
        return {"error": "urlscan result not ready after multiple attempts."}

    except Exception as e:
        return {"error": f"Exception during urlscan analysis: {str(e)}"}

def scan_file_virustotal(file_path: str) -> dict:
    """Upload a file to VirusTotal for scanning."""
    headers = {"x-apikey": VT_API_KEY}
    vt_file_url = "https://www.virustotal.com/api/v3/files"
    try:
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            response = requests.post(vt_file_url, headers=headers, files=files)
        if response.status_code in [200, 202]:
            return response.json()
        else:
            return {"error": f"Error scanning file (VirusTotal): {response.status_code} {response.text}"}
    except Exception as e:
        return {"error": f"Exception during file scan: {str(e)}"}

def get_threat_intel_virustotal(file_hash: str) -> dict:
    """Query VirusTotal for threat intelligence using a file hash."""
    headers = {"x-apikey": VT_API_KEY}
    vt_file_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    response = requests.get(vt_file_url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"Error fetching threat intel for hash (VirusTotal): {response.status_code} {response.text}"}

def extract_attachments(msg: email.message.Message, output_dir: str = "attachments") -> list[str]:
    """Extract attachments from the email and save them to an output directory."""
    attachments = []
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    for part in msg.walk():
        content_disposition = part.get("Content-Disposition", "")
        if "attachment" in content_disposition.lower():
            filename = part.get_filename() or "attachment.bin"
            file_path = os.path.join(output_dir, filename)
            with open(file_path, "wb") as f:
                f.write(part.get_payload(decode=True))
            attachments.append(file_path)
    return attachments

########################################
# Phishing Analysis Agent Framework
########################################

from pydantic import BaseModel

class PhishingAnalysisContext(BaseModel):
    filename: str | None = None
    file_type: str | None = None
    md5_hash: str | None = None
    sha256_hash: str | None = None
    header_analysis: str | None = None
    link_analysis: str | None = None
    attachment_analysis: str | None = None
    threat_intel: str | None = None
    final_assessment: str | None = None

from agents import (
    Agent,
    HandoffOutputItem,
    ItemHelpers,
    MessageOutputItem,
    RunContextWrapper,
    Runner,
    TResponseInputItem,
    ToolCallItem,
    ToolCallOutputItem,
    function_tool,
    handoff,
    trace,
)
from agents.extensions.handoff_prompt import RECOMMENDED_PROMPT_PREFIX

########################################
# Tool Implementations with Actual Code
########################################

@function_tool(
    name_override="calculate_hashes_tool",
    description_override="Confirm file type is EML and calculate MD5 and SHA256 hashes."
)
async def calculate_hashes_tool(context: RunContextWrapper[PhishingAnalysisContext], filename: str) -> str:
    context.context.filename = filename
    file_type = confirm_file_type(filename)
    context.context.file_type = file_type
    md5_hash, sha256_hash = calculate_hashes(filename)
    context.context.md5_hash = md5_hash
    context.context.sha256_hash = sha256_hash
    return (f"File '{filename}' confirmed as {file_type}. "
            f"MD5: {md5_hash}, SHA256: {sha256_hash}")

@function_tool(
    name_override="parse_eml_tool",
    description_override="Parse the EML file structure to extract headers, links, and attachments."
)
async def parse_eml_tool(context: RunContextWrapper[PhishingAnalysisContext], filename: str) -> str:
    try:
        msg = parse_eml(filename)
        headers = {k: str(v) for k, v in msg.items()}
        return f"Parsed EML headers:\n{json.dumps(headers, indent=2)}"
    except Exception as e:
        return f"Error parsing EML: {str(e)}"

@function_tool(
    name_override="analyze_headers_tool",
    description_override="Analyze email headers for spoofing, authentication, and anomalies."
)
async def analyze_headers_tool(context: RunContextWrapper[PhishingAnalysisContext], filename: str) -> str:
    try:
        msg = parse_eml(filename)
        analysis = analyze_headers(msg)
        result = json.dumps(analysis, indent=2)
        context.context.header_analysis = result
        return f"Header analysis result:\n{result}"
    except Exception as e:
        return f"Error analyzing headers: {str(e)}"

@function_tool(
    name_override="analyze_links_tool",
    description_override="Analyze URLs in the email for mismatches, lookalike domains, redirection, and threat intel."
)
async def analyze_links_tool(context: RunContextWrapper[PhishingAnalysisContext], filename: str) -> str:
    try:
        msg = parse_eml(filename)
        urls = extract_urls(msg)
        analysis_results = {}

        for url in urls:
            # 1) VirusTotal check
            vt_result = analyze_url_virustotal(url)

            # 2) urlscan.io check
            urlscan_result = analyze_url_with_urlscan(url)

            # Combine in one object
            combined = {
                "VirusTotal": vt_result,
                "urlscan": urlscan_result
            }
            analysis_results[url] = combined

        result = json.dumps(analysis_results, indent=2)
        context.context.link_analysis = result
        return f"Link analysis result:\n{result}"

    except Exception as e:
        return f"Error analyzing links: {str(e)}"

@function_tool(
    name_override="analyze_attachments_tool",
    description_override="Inspect attachments for anomalies, double extensions, macros, and suspicious content."
)
async def analyze_attachments_tool(context: RunContextWrapper[PhishingAnalysisContext], filename: str) -> str:
    try:
        msg = parse_eml(filename)
        attachments = extract_attachments(msg)
        analysis_results = {}
        for attachment in attachments:
            vt_result = scan_file_virustotal(attachment)
            analysis_results[attachment] = vt_result
        result = json.dumps(analysis_results, indent=2)
        context.context.attachment_analysis = result
        return f"Attachment analysis result:\n{result}"
    except Exception as e:
        return f"Error analyzing attachments: {str(e)}"

@function_tool(
    name_override="correlate_threat_intel_tool",
    description_override="Correlate email artifacts with threat intelligence sources."
)
async def correlate_threat_intel_tool(context: RunContextWrapper[PhishingAnalysisContext]) -> str:
    try:
        if not context.context.sha256_hash:
            return "SHA256 hash not available in context."
        vt_threat = get_threat_intel_virustotal(context.context.sha256_hash)
        result = json.dumps(vt_threat, indent=2)
        context.context.threat_intel = result
        return f"Threat intelligence result:\n{result}"
    except Exception as e:
        return f"Error correlating threat intelligence: {str(e)}"

@function_tool(
    name_override="final_assessment_tool",
    description_override="Compile all analysis results and provide a final phishing assessment."
)
async def final_assessment_tool(context: RunContextWrapper[PhishingAnalysisContext]) -> str:
    # Return the final assessment verbatim as requested or dynamically build one
    final_report = (
        'The analysis indicates that this email could be a phishing attempt. '
        'Here is a summary of the findings:\n\n'
        f'Header Analysis: {context.context.header_analysis}\n\n'
        f'Links Analysis: {context.context.link_analysis}\n\n'
        f'Attachment Analysis: {context.context.attachment_analysis}\n\n'
        f'Threat Intel: {context.context.threat_intel}\n\n'
        'Please review these details carefully to make a final decision.'
    )
    context.context.final_assessment = final_report
    return final_report

########################################
# Agent Definitions and Main Loop
########################################

# Create a linear handoff chain:
# SOC Triage -> Initial Analysis -> Detailed Analysis -> Final Assessment

from agents import (
    Agent,
)

initial_analysis_agent = Agent[PhishingAnalysisContext](
    name="Initial Analysis Agent",
    handoff_description="Agent for file verification and EML parsing.",
    instructions=f"""{RECOMMENDED_PROMPT_PREFIX}
    You are the Initial Analysis Agent. Your task is to:
    1. Confirm the file is an EML.
    2. Calculate MD5 and SHA256 hashes.
    3. Parse the EML structure.
    Hand off the results to the Detailed Analysis Agent when done.""",
    tools=[calculate_hashes_tool, parse_eml_tool],
    handoffs=[]  # Will be set explicitly
)

detailed_analysis_agent = Agent[PhishingAnalysisContext](
    name="Detailed Analysis Agent",
    handoff_description="Agent for in-depth header, link, and attachment analysis.",
    instructions=f"""{RECOMMENDED_PROMPT_PREFIX}
    You are the Detailed Analysis Agent. Your responsibilities include:
    1. Analyzing email headers for spoofing/authentication anomalies.
    2. Analyzing URLs and links for mismatches, redirection, and suspicious content.
    3. Inspecting attachments for malicious indicators.
    4. Correlating artifacts with threat intelligence sources.
    When your analysis is complete, hand off to the Final Assessment Agent.""",
    tools=[analyze_headers_tool, analyze_links_tool, analyze_attachments_tool, correlate_threat_intel_tool],
    handoffs=[]  # Will be set explicitly
)

final_assessment_agent = Agent[PhishingAnalysisContext](
    name="Final Assessment Agent",
    handoff_description="Agent for compiling the final phishing report.",
    instructions=f"""{RECOMMENDED_PROMPT_PREFIX}
    You are the Final Assessment Agent. Your job is to:
    1. Gather all analysis data.
    2. Produce a final assessment report on whether the email is phishing.
    Use the final assessment tool to generate your report.""",
    tools=[final_assessment_tool],
    handoffs=[]  # End of chain
)

# Set the handoffs to form a linear chain
initial_analysis_agent.handoffs = [detailed_analysis_agent]
detailed_analysis_agent.handoffs = [final_assessment_agent]

# The SOC Triage Agent delegates directly to the Initial Analysis Agent
triage_agent = Agent[PhishingAnalysisContext](
    name="SOC Triage Agent",
    handoff_description="SOC Triage Agent that delegates EML analysis tasks.",
    instructions=f"""{RECOMMENDED_PROMPT_PREFIX}
    You are the SOC Triage Agent. When an EML file is received, hand it off to the Initial Analysis Agent.
    If the analysis request deviates, transfer back for re-triage.""",
    handoffs=[initial_analysis_agent]
)

async def main():
    current_agent: Agent[PhishingAnalysisContext] = triage_agent
    input_items: list[TResponseInputItem] = []
    context = PhishingAnalysisContext()

    conversation_id = uuid.uuid4().hex[:16]

    while True:
        user_input = input("Enter the full path to your EML file: ")
        with trace("Phishing Analysis", group_id=conversation_id):
            input_items.append({"content": user_input, "role": "user"})
            result = await Runner.run(current_agent, input_items, context=context)

            for new_item in result.new_items:
                agent_name = new_item.agent.name
                if isinstance(new_item, MessageOutputItem):
                    print(f"{agent_name}: {ItemHelpers.text_message_output(new_item)}")
                elif isinstance(new_item, HandoffOutputItem):
                    print(f"Handed off from {new_item.source_agent.name} to {new_item.target_agent.name}")
                elif isinstance(new_item, ToolCallItem):
                    print(f"{agent_name}: Calling a tool")
                elif isinstance(new_item, ToolCallOutputItem):
                    print(f"{agent_name}: Tool call output: {new_item.output}")
                else:
                    print(f"{agent_name}: Skipping item: {new_item.__class__.__name__}")

            input_items = result.to_input_list()
            current_agent = result.last_agent

            if context.final_assessment:
                print("\nFinal Assessment Complete:")
                print(context.final_assessment)
                break

if __name__ == "__main__":
    asyncio.run(main())
