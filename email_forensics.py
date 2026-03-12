# SENTINEL — Local AI Powered Phishing Intelligence Agent
# Version: 0.2
# Description: Email header forensics with IP intelligence,
#              AbuseIPDB integration, and batch processing

import re 
import requests
import os
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
    pattern = rf"{field_name}:\s*(.+)"
    match = re.search(pattern, header, re.IGNORECASE)
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

    if flags or ip_risk_detected:
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
    is_high_risk = bool(flags) or ip_risk_detected
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

