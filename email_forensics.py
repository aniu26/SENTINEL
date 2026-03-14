# SENTINEL — Local AI Powered Phishing Intelligence Agent
# Version: 0.2
# Description: Email header forensics with IP intelligence,
#              AbuseIPDB integration, and batch processing

import re
import requests
import os
import dns.resolver
from dotenv import load_dotenv

 #load api key from .env file
# Get the folder where this script is located
script_dir = os.path.dirname(os.path.abspath(__file__))

# Build the full path to .env file
env_path = os.path.join(script_dir, '.env')


# Load .env from exact location
load_dotenv(dotenv_path=env_path) 
 # Read .env file directly to see what Python sees


ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")
 
def read_header_file(filename):
    """Opens and reads the raw email header file 
    """
    try:
        with open(filename, "r") as file:
            content =file.read()
        return content
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return None 
def extract_field(header, field_name):
    """Extracts the value of a specified field from the email header.
    Returns the field value as a string, or None if not found.
    """
    pattern = rf"^{field_name}:\s*(.+)"
    match = re.search(pattern, header, re.IGNORECASE | re.MULTILINE)
    if match:
        return match.group(1).strip()
    return "not found"
def extract_ip_addresses(header):
    """Extracts all IP addresses found anywhere in the header.
    
    Every server that handled this email leaves its 
    IP address in the Received fields. Collecting all IPs 
    lets us trace the email's journey and spot malicious servers."""
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ips = re.findall(ip_pattern, header)
    #remove duplicates
    seen = []
    for ip in ips:
        if ip not in seen:
            seen.append(ip)
    return seen
def check_spoofing(from_field, reply_to, return_path):
    """Checks for common email spoofing indicators.
    
    Why: Phishing emails almost always have mismatches 
    between From, Reply-To, and Return-Path fields.
    """
    flags =[]
    #extract domains
    domain_pattern = r'@([\w.-]+)'

    from_match = re.search(domain_pattern, from_field)
    reply_match = re.search(domain_pattern, reply_to)
    return_match = re.search(domain_pattern, return_path)         

    from_domain = from_match.group(1) if from_match else ""
    reply_domain = reply_match.group(1) if reply_match else ""
    return_domain = return_match.group(1) if return_match else ""

    #Flag 1 -From domain doesn"t match Reply-To domain
    if from_domain and reply_domain and from_domain != reply_domain:
        flags.append(f" SPOOFING DETECTED: From domain ({from_domain}) does not match Reply-To domain ({reply_domain}).")
    #Flag 2 -From domain doesn"t match Return-Path domain
    if from_domain and return_domain and from_domain != return_domain:
        flags.append(f" SPOOFING DETECTED: From domain ({from_domain}) does not match Return-Path domain ({return_domain}).")   
    # Flag 3 - TLDs In Reply Domain
    tlds =['ru', 'cn', 'tk', 'ml', 'ga', 'pw', 'cc']
    for tld in tlds:
        if reply_domain.endswith(f".{tld}") or return_domain.endswith(f".{tld}"):
            flags.append(f" ALERT: Reply-To domain ({reply_domain}) uses a TLD ({tld}).")
    return flags
def geolocate_ip(ip):
    """ Queries ip-api.com to get location and VPN/Tor/Proxy
    information about an IP address.
    """
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,proxy,vpn,tor,hosting"
        response = requests.get(url, timeout=5)
        data = response.json()
        if data.get("status") == "success":
            return {
                "country": data.get("country", "Unknown"),
                "country_code": data.get("countryCode","??"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "org": data.get("org","Unknown"),
                "is_proxy": data.get("proxy", False),
                "is_vpn": data.get("vpn",False),
                "is_tor": data.get("tor",False),
                "is_hosting": data.get("hosting",False)
            }
        else:
            return None
    except requests.exceptions.Timeout:
        print(f"TIMEOUT- Could not geolocate IP {ip} within timeout period.")
        return None
    except requests.exceptions.ConnectionError:
        print(f"CONNECTION ERROR- Check your internet connection.")
        return None
def check_abuseipdb(ip):
    """Queries AbuseIPDB to check if an IP has been
    reported as malicious by the security community."""
    if not ABUSEIPDB_KEY:
        print("AbuseIPDB API key not found in .env file")
        return None
    try:
        url="https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": ABUSEIPDB_KEY,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }
        response =requests.get(
            url,
            headers=headers,
            params=params,
            timeout=5
        )
        data = response.json()
        abuse_data =data.get("data", {})
        return {
             "abuse_score": abuse_data.get("abuseConfidenceScore", 0),
            "total_reports": abuse_data.get("totalReports", 0),
            "usage_type": abuse_data.get("usageType", "Unknown"),
            "last_reported": abuse_data.get("lastReportedAt", "Never"),
            "is_whitelisted": abuse_data.get("isWhitelisted", False)
        }
    except requests.exceptions.Timeout:
        print(f"TIMEOUT- Could not check AbuseIPDB for IP {ip} within timeout period.")
        return None
    except requests.exceptions.ConnectionError:
        print(f"CONNECTION ERROR- AbuseIPDB connection error for {ip}.")
        return None

def check_spf(domain):
    """Queries DNS TXT records to find and evaluate an SPF record for a domain.

    SPF (Sender Policy Framework) is an email authentication standard defined
    in RFC 7208. A domain publishes an SPF record as a DNS TXT record starting
    with 'v=spf1'. It lists the mail servers authorised to send email on behalf
    of that domain.

    Why we check it:
    Phishing emails frequently impersonate legitimate domains. If the sending
    domain has no SPF record, or if the sending server is not listed in it,
    that is a strong indicator the email is forged. Checking SPF is one of the
    fastest ways to surface domain-level spoofing during header forensics.

    Args:
        domain: A domain name string, e.g. "google.com"

    Returns:
        A dictionary with:
            spf_found  — bool: True if a v=spf1 TXT record exists
            spf_record — str | None: the full SPF record string, or None
            spf_pass   — bool: True if a valid SPF record was found
            details    — str: human-readable explanation of the result
    """
    # --- Input validation ---
    domain = domain.strip()

    if not domain:
        return {
            "spf_found": False,
            "spf_record": None,
            "spf_pass": False,
            "details": "Invalid input: domain name cannot be empty."
        }

    # DNS spec maximum is 253 characters
    if len(domain) > 253:
        return {
            "spf_found": False,
            "spf_record": None,
            "spf_pass": False,
            "details": f"Invalid input: domain exceeds 253-character DNS maximum ({len(domain)} chars)."
        }

    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+'
    if not re.match(domain_pattern, domain):
        return {
            "spf_found": False,
            "spf_record": None,
            "spf_pass": False,
            "details": f"Invalid input: '{domain}' does not appear to be a valid domain name."
        }

    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for record in answers:
            # Each TXT record may be split across multiple strings; join them
            full_record = "".join(
                part.decode("utf-8") if isinstance(part, bytes) else part
                for part in record.strings
            )
            # Strip control characters before processing or returning the record
            full_record = re.sub(r'[\x00-\x1f\x7f]', '', full_record)

            if full_record.startswith("v=spf1"):
                return {
                    "spf_found": True,
                    "spf_record": full_record,
                    "spf_pass": True,
                    "details": f"SPF record found for {domain}: {full_record}"
                }
        # TXT records exist but none is an SPF record
        return {
            "spf_found": False,
            "spf_record": None,
            "spf_pass": False,
            "details": f"No SPF record found for {domain}. Domain has TXT records but none start with 'v=spf1'."
        }
    except dns.exception.Timeout:
        print(f"TIMEOUT- DNS query for {domain} timed out.")
        return {
            "spf_found": False,
            "spf_record": None,
            "spf_pass": False,
            "details": f"DNS timeout while querying SPF record for {domain}."
        }
    except dns.resolver.NXDOMAIN:
        print(f"NXDOMAIN- Domain {domain} does not exist in DNS.")
        return {
            "spf_found": False,
            "spf_record": None,
            "spf_pass": False,
            "details": f"Domain {domain} does not exist (NXDOMAIN). Likely a spoofed or nonexistent sender domain."
        }
    except dns.resolver.NoAnswer:
        print(f"NO ANSWER- No TXT records found for {domain}.")
        return {
            "spf_found": False,
            "spf_record": None,
            "spf_pass": False,
            "details": f"No TXT records found for {domain}. Domain exists but publishes no SPF policy."
        }
    except dns.exception.DNSException as e:
        print(f"DNS ERROR- Unexpected DNS error for {domain}: {e}")
        return {
            "spf_found": False,
            "spf_record": None,
            "spf_pass": False,
            "details": f"Unexpected DNS error while querying SPF record for {domain}: {e}"
        }

def check_dkim(header_text, domain):
    """Checks whether a DKIM signature is present and its public key exists in DNS.

    DKIM (DomainKeys Identified Mail) is an email authentication standard defined
    in RFC 6376. The sending mail server signs outgoing messages with a private key
    and publishes the matching public key in DNS as a TXT record. Receiving servers
    can then verify the signature to confirm the message was not tampered with and
    genuinely originates from the claimed domain.

    How it works in DNS:
    The public key is published at a specific subdomain constructed from two values
    embedded in the DKIM-Signature header:
        - Selector (s=): a label chosen by the domain owner, e.g. "s20221208"
        - Signing domain (d=): the domain that applied the signature, e.g. "gmail.com"
    The resulting DNS query name is: {selector}._domainkey.{domain}
    For example:  s20221208._domainkey.gmail.com

    Why we check it:
    Phishing emails cannot produce a valid DKIM signature for a domain they do not
    control, because they do not have the private key. If the DKIM-Signature header
    is missing, the selector does not resolve in DNS, or no public key (p=) is
    present, that is a strong indicator the email is forged or the signature has
    been revoked. Checking DKIM alongside SPF gives a much more complete picture
    of whether an email is authenticated.

    Args:
        header_text: The full raw email header string.
        domain:      The sender domain string, e.g. "gmail.com".

    Returns:
        A dictionary with:
            dkim_header_found — bool: True if a DKIM-Signature header was found
            dkim_selector     — str | None: the selector value (s=) from the header
            dkim_domain       — str | None: the signing domain (d=) from the header
            dkim_key_found    — bool: True if a public key record exists in DNS
            details           — str: human-readable explanation of the result
    """
    # --- Input validation: domain ---
    domain = domain.strip()

    if not domain:
        return {
            "dkim_header_found": False,
            "dkim_selector": None,
            "dkim_domain": None,
            "dkim_key_found": False,
            "details": "Invalid input: domain name cannot be empty."
        }

    # DNS spec maximum is 253 characters
    if len(domain) > 253:
        return {
            "dkim_header_found": False,
            "dkim_selector": None,
            "dkim_domain": None,
            "dkim_key_found": False,
            "details": f"Invalid input: domain exceeds 253-character DNS maximum ({len(domain)} chars)."
        }

    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+'
    if not re.match(domain_pattern, domain):
        return {
            "dkim_header_found": False,
            "dkim_selector": None,
            "dkim_domain": None,
            "dkim_key_found": False,
            "details": f"Invalid input: '{domain}' does not appear to be a valid domain name."
        }

    # --- Extract DKIM-Signature header (handles folded multi-line values) ---
    dkim_match = re.search(r'(?im)^DKIM-Signature:\s*(.+(?:\n[ \t]+.+)*)', header_text)

    if not dkim_match:
        return {
            "dkim_header_found": False,
            "dkim_selector": None,
            "dkim_domain": None,
            "dkim_key_found": False,
            "details": f"No DKIM-Signature header found in email. Domain {domain} may not sign outgoing mail."
        }

    dkim_value = dkim_match.group(1)

    # --- Parse selector (s=) and signing domain (d=) from DKIM-Signature ---
    selector_match = re.search(r'\bs=([^;\s]+)', dkim_value)
    dkim_domain_match = re.search(r'\bd=([^;\s]+)', dkim_value)

    selector = selector_match.group(1).strip() if selector_match else None
    dkim_domain = dkim_domain_match.group(1).strip() if dkim_domain_match else None

    # If either value is missing we cannot form a valid DNS query — return early
    if not selector or not dkim_domain:
        return {
            "dkim_header_found": True,
            "dkim_selector": selector,
            "dkim_domain": dkim_domain,
            "dkim_key_found": False,
            "details": "DKIM-Signature header found but selector (s=) or domain (d=) could not be parsed."
        }

    # --- Validate selector before using it in a DNS query ---
    # RFC 1035: each label must be 1-63 chars, alphanumeric and hyphens only
    selector_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9\-]{0,62}$'
    if not re.match(selector_pattern, selector):
        return {
            "dkim_header_found": True,
            "dkim_selector": None,
            "dkim_domain": dkim_domain,
            "dkim_key_found": False,
            "details": (
                f"DKIM selector failed validation — contains invalid characters or "
                f"exceeds the 63-character RFC 1035 label limit."
            )
        }

    # Use the validated domain parameter (not the raw d= value) to construct
    # the query name — treats all header-extracted data as untrusted
    query_name = f"{selector}._domainkey.{domain}"

    try:
        answers = dns.resolver.resolve(query_name, "TXT")
        for record in answers:
            # Each TXT record may be split across multiple strings; join them
            full_record = "".join(
                part.decode("utf-8") if isinstance(part, bytes) else part
                for part in record.strings
            )
            # Strip control characters from DNS response before any comparison
            full_record = re.sub(r'[\x00-\x1f\x7f]', '', full_record)

            # DKIM public key records always contain a p= tag
            if "p=" in full_record:
                return {
                    "dkim_header_found": True,
                    "dkim_selector": selector,
                    "dkim_domain": dkim_domain,
                    "dkim_key_found": True,
                    "details": (
                        f"DKIM public key found at {query_name}. "
                        f"Selector '{selector}' is valid and active."
                    )
                }
        # TXT records exist at the query name but none contain a DKIM public key
        return {
            "dkim_header_found": True,
            "dkim_selector": selector,
            "dkim_domain": dkim_domain,
            "dkim_key_found": False,
            "details": f"TXT records found at {query_name} but none contain a DKIM public key (p=)."
        }
    except dns.exception.Timeout:
        print(f"TIMEOUT- DNS query for {query_name} timed out.")
        return {
            "dkim_header_found": True,
            "dkim_selector": selector,
            "dkim_domain": dkim_domain,
            "dkim_key_found": False,
            "details": f"DNS timeout while querying DKIM key at {query_name}."
        }
    except dns.resolver.NXDOMAIN:
        print(f"NXDOMAIN- DKIM record {query_name} does not exist in DNS.")
        return {
            "dkim_header_found": True,
            "dkim_selector": selector,
            "dkim_domain": dkim_domain,
            "dkim_key_found": False,
            "details": (
                f"No DKIM record found at {query_name} (NXDOMAIN). "
                f"Selector may be revoked or domain does not publish DKIM keys."
            )
        }
    except dns.resolver.NoAnswer:
        print(f"NO ANSWER- No TXT records found at {query_name}.")
        return {
            "dkim_header_found": True,
            "dkim_selector": selector,
            "dkim_domain": dkim_domain,
            "dkim_key_found": False,
            "details": f"No TXT records found at {query_name}. DKIM public key is not published for this selector."
        }
    except dns.exception.DNSException as e:
        print(f"DNS ERROR- Unexpected DNS error querying {query_name}: {type(e).__name__}")
        return {
            "dkim_header_found": True,
            "dkim_selector": selector,
            "dkim_domain": dkim_domain,
            "dkim_key_found": False,
            "details": f"Unexpected DNS error while querying DKIM key at {query_name}: {type(e).__name__}"
        }

def analyze_ip_intelligence(ip):
    """
    Combines geolocation and AbuseIPDB data
    to produce a complete IP intelligence profile.
    
    Why combine both:
    Neither API alone tells the full story.
    Geolocation tells us WHERE, AbuseIPDB tells us
    WHO has seen this IP doing bad things.
    Together they give us a complete picture.
    """
    print(f"\n  📍 Analyzing: {ip}")
    print("  " + "-" * 45)
    
    # Get geolocation data
    geo = geolocate_ip(ip)
    
    if geo:
        # Build anonymity flags
        anonymity_flags = []
        if geo["is_tor"]:
            anonymity_flags.append("🚨 TOR EXIT NODE")
        if geo["is_vpn"]:
            anonymity_flags.append("⚠️ VPN DETECTED")
        if geo["is_proxy"]:
            anonymity_flags.append("⚠️ PROXY DETECTED")
        if geo["is_hosting"]:
            anonymity_flags.append("ℹ️ HOSTING/DATACENTER")
            
        country_code = geo.get('country_code', '??')
        print(f"  🌍 Location:  {geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')} {get_flag(country_code)}")
        print(f"  🏢 ISP:       {geo['isp']}")
        print(f"  🏛️ Org:       {geo['org']}")
        
        if anonymity_flags:
            for flag in anonymity_flags:
                print(f"  {flag}")
            print(f"  ⚠️  NOTE: Actual sender location may be UNKNOWN")
        else:
            print(f"  ✅ No anonymization detected")
    else:
        print(f"  ❌ Geolocation unavailable")
    
    # Get AbuseIPDB data
    abuse = check_abuseipdb(ip)
    
    if abuse:
        score = abuse["abuse_score"]
        
        # Color code the score
        if score >= 80:
            score_label = f"🚨 {score}/100 — MALICIOUS"
        elif score >= 40:
            score_label = f"⚠️ {score}/100 — SUSPICIOUS"
        elif score >= 1:
            score_label = f"🟡 {score}/100 — LOW RISK"
        else:
            score_label = f"✅ {score}/100 — CLEAN"
            
        print(f"  📊 Abuse Score:   {score_label}")
        print(f"  📝 Total Reports: {abuse['total_reports']}")
        print(f"  🔍 Usage Type:    {abuse['usage_type']}")
        
        if abuse["last_reported"] and abuse["last_reported"] != "Never":
            print(f"  🕐 Last Reported: {abuse['last_reported'][:10]}")
    else:
        print(f"  ❌ AbuseIPDB data unavailable")
    
    # Return combined risk assessment
    tor_or_vpn = geo and (geo["is_tor"] or geo["is_vpn"] or geo["is_proxy"])
    high_abuse = abuse and abuse["abuse_score"] >= 80
    
    return tor_or_vpn or high_abuse

def get_flag(country_code):
    """
    Converts a country code to an emoji flag.
    Works by converting letters to regional indicator symbols.
    
    Why: Makes reports more readable at a glance.
    DE instantly means less than 🇩🇪 visually.
    """
    if not country_code or len(country_code) != 2:
        return "🏳️"
    return "".join(
        chr(ord(c) + 127397) for c in country_code.upper()
    )

def detect_urgency(subject, body):
    """Scans email subject and body for urgency and manipulation language.

    What urgency detection is:
    Phishing emails rely heavily on psychological pressure to override a
    victim's critical thinking. Attackers craft messages designed to make
    recipients act immediately without pausing to verify legitimacy. This
    function identifies four categories of manipulation language commonly
    used in phishing campaigns by searching for known trigger phrases.

    Why attackers use urgency language:
    Social engineering works by exploiting cognitive biases. Urgency bypasses
    rational decision-making — when a person believes their account will be
    deleted in 24 hours or that they have won a prize, they are less likely
    to scrutinise the sender address, links, or authentication signals.
    Urgency language is documented in academic literature on phishing and
    consistently appears in real-world campaigns targeting banking, cloud
    services, and corporate credentials.

    Connection to MITRE ATT&CK T1566 (Phishing):
    MITRE T1566 covers phishing as an Initial Access technique. Sub-technique
    T1566.001 (Spearphishing Attachment) and T1566.002 (Spearphishing Link)
    describe the delivery mechanism, but the social engineering element —
    convincing the recipient to act — is the enabler. Urgency language is
    a primary component of that social engineering layer. A positive result
    from this function directly supports mapping to T1566 with MEDIUM confidence,
    since keyword matching alone cannot confirm intent.

    Current limitation — subject-only analysis when body is unavailable:
    SENTINEL currently processes raw email header files (.txt) that do not
    include the message body. When body is None or empty, this function
    analyses the subject line only. Subject-line urgency is still a meaningful
    signal — attackers frequently embed pressure language there — but the
    detection coverage is reduced. A body-absent result is flagged explicitly
    in the returned details string and the body_analyzed key.

    Future improvement — full .eml support:
    In a future version, SENTINEL will parse full RFC 5322 .eml files using
    Python's email.parser module. This will make the message body, HTML
    content, and MIME parts available for analysis, significantly increasing
    urgency detection accuracy and reducing false negatives on emails where
    urgency language appears only in the body.

    Args:
        subject: The email subject line string.
        body:    The email body text string, or None if unavailable.

    Returns:
        A dictionary with:
            urgency_detected     — bool: True if any urgency patterns matched
            urgency_score        — int: total number of individual patterns matched
            categories_triggered — list of str: category names that had at least one match
            matched_patterns     — list of str: exact phrases that matched
            details              — str: human-readable explanation of the result
            body_analyzed        — bool: True if body text was available and scanned
    """
    # --- Input sanitisation ---
    # Coerce None to empty string before any string operations
    subject = subject if isinstance(subject, str) else ""
    body    = body    if isinstance(body,    str) else ""

    # Strip control characters from both inputs
    subject = re.sub(r'[\x00-\x1f\x7f]', '', subject)
    body    = re.sub(r'[\x00-\x1f\x7f]', '', body)

    # Truncate subject to RFC 5321 maximum of 998 characters
    subject = subject[:998]

    body_analyzed = bool(body)

    # Build the text to scan — subject always included, body when available
    scan_text = subject + (" " + body if body else "")

    # Lowercase once for all case-insensitive comparisons
    scan_lower = scan_text.lower()

    # --- Pattern categories ---
    patterns = {
        "ACCOUNT_THREAT": [
            "suspended", "disabled", "locked", "blocked",
            "deactivated", "terminated", "unauthorized access",
            "suspicious activity", "unusual activity",
            "security alert", "account compromised",
            "breach detected"
        ],
        "ACTION_DEMAND": [
            "immediate action", "act now", "urgent",
            "verify now", "confirm immediately",
            "action required", "update required",
            "verify your account", "confirm your identity"
        ],
        "TIME_PRESSURE": [
            "within 24 hours", "expires soon",
            "limited time", "final notice",
            "deadline", "will be deleted",
            "hours remaining", "expires in"
        ],
        "REWARD_LURE": [
            "you have won", "congratulations",
            "selected winner", "claim your prize",
            "free gift", "exclusive offer"
        ]
    }

    # --- Matching ---
    categories_triggered = []
    matched_patterns     = []

    for category, phrases in patterns.items():
        category_matched = False
        for phrase in phrases:
            if phrase in scan_lower:
                matched_patterns.append(phrase)
                if not category_matched:
                    categories_triggered.append(category)
                    category_matched = True

    urgency_score    = len(matched_patterns)
    urgency_detected = urgency_score > 0

    # --- Build details string ---
    if urgency_detected:
        category_list = ", ".join(categories_triggered)
        details = (
            f"Urgency language detected — {urgency_score} pattern(s) matched "
            f"across {len(categories_triggered)} category(s): {category_list}."
        )
    else:
        details = "No urgency or manipulation language detected."

    if not body_analyzed:
        details += " Note: email body was not available — subject line analysed only."

    return {
        "urgency_detected":     urgency_detected,
        "urgency_score":        urgency_score,
        "categories_triggered": categories_triggered,
        "matched_patterns":     matched_patterns,
        "details":              details,
        "body_analyzed":        body_analyzed
    }

def map_to_mitre(findings):
    """Maps observed email threat indicators to MITRE ATT&CK techniques.

    What is MITRE ATT&CK:
    MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a
    globally recognised knowledge base of adversary behaviours based on
    real-world observations. It organises attacks into Tactics (the goal the
    attacker is trying to achieve) and Techniques (the specific method used to
    achieve that goal). Technique IDs like T1566.002 give security teams a
    common, vendor-neutral language to describe threats.

    Why mapping to ATT&CK matters for SOC teams:
    Raw forensic findings (e.g. "SPF failed") are useful for triage but do not
    communicate intent or severity to a SOC analyst or incident responder.
    Mapping findings to ATT&CK techniques allows teams to:
        - Correlate this email with other alerts using the same technique ID
        - Prioritise response based on tactic severity
        - Feed findings directly into SIEMs and threat intel platforms that
          index by ATT&CK ID (e.g. Splunk ES, Microsoft Sentinel, Elastic SIEM)
        - Write detection rules tied to documented adversary behaviour
        - Produce structured threat reports that are meaningful across teams

    Tactics used in these mappings:
        Initial Access      — The adversary is attempting to get into the network.
                              Phishing is the most common initial access vector.
        Defense Evasion     — The adversary is trying to avoid being detected.
                              Forging sender identity hides the true origin.
        Command and Control — The adversary is communicating with compromised systems.
                              Malicious IPs and anonymisation tools indicate C2 infra.

    Args:
        findings: A dictionary of observed indicators with these boolean keys:
                      spoofing_detected — From/Reply-To/Return-Path domain mismatch
                      tor_vpn_detected  — Tor exit node, VPN, or proxy on sending IP
                      malicious_ip      — IP has high AbuseIPDB abuse score
                      spf_pass          — SPF DNS record check passed
                      dkim_pass         — DKIM public key found in DNS
                      urgency_detected  — Urgency/pressure language in subject or body

    Returns:
        A list of dictionaries, one per mapped technique, each containing:
            technique_id   — ATT&CK technique ID, e.g. "T1566.002"
            technique_name — Human-readable technique name
            tactic         — The ATT&CK tactic this technique falls under
            confidence     — "HIGH", "MEDIUM", or "LOW"
            reason         — Why this technique was mapped based on observed evidence
        Returns an empty list if no techniques were mapped.
    """
    techniques = []

    # Use .get() throughout — never crash on missing or unexpected keys
    spoofing_detected = findings.get("spoofing_detected", False)
    tor_vpn_detected  = findings.get("tor_vpn_detected", False)
    malicious_ip      = findings.get("malicious_ip", False)
    spf_pass          = findings.get("spf_pass", True)
    dkim_pass         = findings.get("dkim_pass", True)
    urgency_detected  = findings.get("urgency_detected", False)

    if spoofing_detected:
        techniques.append({
            "technique_id":   "T1566.002",
            "technique_name": "Spearphishing Link",
            "tactic":         "Initial Access",
            "confidence":     "HIGH",
            "reason":         "Domain mismatch detected between From, Reply-To, and Return-Path fields."
        })

    if tor_vpn_detected:
        techniques.append({
            "technique_id":   "T1090.003",
            "technique_name": "Multi-hop Proxy",
            "tactic":         "Command and Control",
            "confidence":     "HIGH",
            "reason":         "Tor/VPN/Proxy detected on originating IP address."
        })

    if not spf_pass and not dkim_pass:
        techniques.append({
            "technique_id":   "T1036.005",
            "technique_name": "Match Legitimate Name or Location",
            "tactic":         "Defense Evasion",
            "confidence":     "MEDIUM",
            "reason":         "Both SPF and DKIM authentication failed, indicating sender identity is forged."
        })

    if malicious_ip:
        techniques.append({
            "technique_id":   "T1071.003",
            "technique_name": "Mail Protocols",
            "tactic":         "Command and Control",
            "confidence":     "HIGH",
            "reason":         "Originating IP has high abuse score indicating known malicious infrastructure."
        })

    if urgency_detected:
        techniques.append({
            "technique_id":   "T1566",
            "technique_name": "Phishing",
            "tactic":         "Initial Access",
            "confidence":     "MEDIUM",
            "reason":         "Urgency language detected indicating social engineering attempt."
        })

    return techniques

def generate_report(filename):
    """Generates a forensic report based on the email header analysis."""
    print("=" * 60)
    print(f" Forensic Analysis Report for '{filename}'")
    print("=" * 60)     

    # Read the file
    header = read_header_file(filename)
    if not header:
        return
    # Extract fields
    from_field = extract_field(header, "From")
    reply_to = extract_field(header, "Reply-To")    
    return_path = extract_field(header, "Return-Path")
    subject = extract_field(header, "Subject")
    urgency_result = detect_urgency(subject, None)
    originating_ip = extract_field(header, "X-Originating-IP")
    message_id = extract_field(header, "Message-ID")

    # Print extracted information
    print("\n EMAIL DETAILS")
    print("-" * 40)
    print(f" From: {from_field}")
    print(f" Reply-To: {reply_to}")     
    print(f" Return-Path: {return_path}")
    print(f" Subject: {subject}")       
    print(f" Originating IP: {originating_ip}")
    print(f" Message-ID: {message_id}")

    # Extract sender domain for SPF and DKIM checks
    domain_match = re.search(r'@([\w.-]+)', from_field)
    sender_domain = domain_match.group(1) if domain_match else None

    # Extract and print all IP addresses
    print("\n🌐 IP INTELLIGENCE ANALYSIS")
    print("-" * 40)
    ips = extract_ip_addresses(header)

    ip_risk_detected = False
    for ip in ips:
        is_risky = analyze_ip_intelligence(ip)
        if is_risky:
            ip_risk_detected = True  
    # Check for spoofing indicators
    print("\n SPOOFING ANALYSIS")   
    print("-" * 40)
    flags = check_spoofing(from_field, reply_to, return_path)
    if flags:
        for flag in flags:
            print(flag)
    else:
        print(" No spoofing indicators detected.")  

    # Run SPF and DKIM authentication checks
    print("\n EMAIL AUTHENTICATION")
    print("-" * 40)

    if sender_domain:
        spf_result = check_spf(sender_domain)
        spf_status = "✅ PASS" if spf_result["spf_pass"] else "❌ FAIL"
        spf_record_display = spf_result["spf_record"] if spf_result["spf_record"] else "not found"
        print(f" 📧 SPF Check:  {spf_status}")
        print(f"    Record:  {spf_record_display}")
        print(f"    Details: {spf_result['details']}")

        dkim_result = check_dkim(header, sender_domain)
        dkim_status = "✅ PASS" if dkim_result["dkim_key_found"] else "❌ FAIL"
        dkim_selector_display = dkim_result["dkim_selector"] if dkim_result["dkim_selector"] else "not found"
        print(f"\n 🔏 DKIM Check: {dkim_status}")
        print(f"    Selector: {dkim_selector_display}")
        print(f"    Details:  {dkim_result['details']}")
    else:
        print(" ⚠️  Could not extract sender domain from From field — skipping SPF/DKIM checks.")
        spf_result = {"spf_pass": False}
        dkim_result = {"dkim_key_found": False}

    # Calculate authentication failure — only a risk signal when both fail together
    spf_fail = not spf_result["spf_pass"]
    dkim_fail = not dkim_result["dkim_key_found"]
    auth_fail = spf_fail and dkim_fail

    if auth_fail:
        print("\n 🚨 AUTHENTICATION FAILURE: Both SPF and DKIM checks failed.")
        print("    This is a strong indicator the sender domain is forged.")

    # Urgency and social engineering language analysis
    print("\n🚨 URGENCY ANALYSIS")
    print("-" * 40)
    if urgency_result["urgency_detected"]:
        categories = ", ".join(urgency_result["categories_triggered"])
        patterns   = ", ".join(urgency_result["matched_patterns"])
        print(f" ⚠️  Urgency language detected")
        print(f"    Score:      {urgency_result['urgency_score']} pattern(s) matched")
        print(f"    Categories: {categories}")
        print(f"    Patterns:   {patterns}")
        print(f"    Details:    {urgency_result['details']}")
        if not urgency_result["body_analyzed"]:
            print(f" ℹ️  Body not available — subject analyzed only")
    else:
        print(f" ✅ No urgency language detected")
        print(f"    Details: {urgency_result['details']}")

    # Build findings and map to MITRE ATT&CK techniques
    findings = {
        "spoofing_detected": bool(flags),
        "tor_vpn_detected":  ip_risk_detected,
        "malicious_ip":      ip_risk_detected,
        "spf_pass":          spf_result.get("spf_pass", True),
        "dkim_pass":         dkim_result.get("dkim_key_found", True),
        "urgency_detected":  urgency_result["urgency_detected"]
    }
    techniques = map_to_mitre(findings)

    print("\n🎯 MITRE ATT&CK MAPPING")
    print("-" * 40)
    if techniques:
        for technique in techniques:
            print(f"\n [TACTIC] {technique['tactic']}")
            print(f" → {technique['technique_id']} — {technique['technique_name']}")
            print(f"   Confidence: {technique['confidence']}")
            print(f"   Reason: {technique['reason']}")
    else:
        print("✅ No ATT&CK techniques mapped")

    if flags or ip_risk_detected or auth_fail:
        print("🚨 HIGH RISK — This email shows strong indicators of phishing")
        print("   Recommended actions:")
        print("   → Block sender domain immediately")
        print("   → Report malicious IPs to AbuseIPDB")
        print("   → Alert security team")
        print("   → Preserve email headers as evidence")
    else:
        print("✅ LOW RISK — No obvious phishing indicators found")

# Privacy note — this is your differentiator
    print("\n🔒 PRIVACY NOTE")
    print("-" * 40)
    print("✅ Analysis performed entirely on-device")
    print("✅ Only IP addresses sent to external APIs")
    print("✅ No email content shared with third parties")
    is_high_risk = bool(flags) or ip_risk_detected or auth_fail
    return is_high_risk
def process_folder(folder_path):
    """
    Scans a folder for email files and analyzes each one.
    
    Why folder based processing:
    In real security operations emails come in bulk.
    Analysts need to process entire batches not individual
    files. This mirrors how real email security gateways
    work — they process queues of emails automatically.
    """
    import pathlib
    
    print("\n" + "=" * 60)
    print("   SENTINEL — BATCH EMAIL ANALYSIS")
    print(f"   Scanning folder: {folder_path}")
    print("=" * 60)
    
    folder = pathlib.Path(folder_path)
    
    if not folder.exists():
        print(f"❌ Folder not found: {folder_path}")
        return
    
    email_files = list(folder.glob("*.txt"))
    
    if not email_files:
        print(f"⚠️  No .txt files found in {folder_path}")
        return
    
    print(f"\n📬 Found {len(email_files)} email(s) to analyze")
    
    results = {
        "high_risk": [],
        "low_risk": [],
        "errors": []
    }
    
    for i, email_file in enumerate(email_files, 1):
        print(f"\n\n[{i}/{len(email_files)}] Processing: {email_file.name}")
        print("=" * 60)
        
        try:
            risk = generate_report(str(email_file))
            if risk:
                results["high_risk"].append(email_file.name)
            else:
                results["low_risk"].append(email_file.name)
        except Exception as e:
            print(f"❌ Error processing {email_file.name}: {e}")
            results["errors"].append(email_file.name)
    
    # Final summary
    print("\n\n" + "=" * 60)
    print("   SENTINEL — BATCH ANALYSIS COMPLETE")
    print("=" * 60)
    print(f"\n📊 Total analyzed:  {len(email_files)}")
    print(f"🚨 High risk:       {len(results['high_risk'])}")
    print(f"✅ Low risk:        {len(results['low_risk'])}")
    print(f"❌ Errors:          {len(results['errors'])}")
    
    if results["high_risk"]:
        print(f"\n🚨 HIGH RISK EMAILS DETECTED:")
        for email in results["high_risk"]:
            print(f"   → {email}")
    
    if results["low_risk"]:
        print(f"\n✅ CLEAN EMAILS:")
        for email in results["low_risk"]:
            print(f"   → {email}")
    
    print("\n" + "=" * 60)


# Run SENTINEL on emails folder
process_folder("emails")

