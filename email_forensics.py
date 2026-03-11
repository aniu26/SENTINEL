#Phishing Email Header Forensics Tool
# Analyzes raw email headers for signs of spoofing and malicious activity

import re   
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
    print("\n IP ADDRESSES FOUND IN HEADER")
    print("-" * 40) 
    ips = extract_ip_addresses(header)
    for ip in ips:
        print(f" {ip}")     
    # Check for spoofing indicators
    print("\n SPOOFING ANALYSIS")   
    print("-" * 40)
    flags = check_spoofing(from_field, reply_to, return_path)
    if flags:
        for flag in flags:
            print(flag)
    else:
        print(" No spoofing indicators detected.")  

    if flags:
        print("HIGH RISK- This email shows indicators of Phishing")
        print("RECOMMENDATION- Block Sender, Do Not Click Links, Report to IT Security Team")
    else:
        print("LOW RISK- This email does not show common indicators of Phishing")
        print("RECOMMENDATION- Exercise Caution, Verify Sender if Uncertain")
    
generate_report("sample_email.txt")
