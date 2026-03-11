# IP Analyzer
# This script categorizes a list of IP addresses by type
def analyze_ip(ip):
    #Split the IP address into 4 parts
    parts = ip.split('.')
    #First check if the IP address is valid
    if len(parts) != 4:
        print(f"{ip} is not a valid IP address.")
        return
    #convert each part to an integer to compare
    first_octet = int(parts[0])
    #Private IP ranges--internal network IPs 10.x.x.x
    if first_octet == 10:
        return (f"{ip} is a Private IP address (Class A).")
    #Private IP ranges--internal network IPs 172.16.x.x to 172.31.x.x
    elif first_octet == 172 and 16 <= int(parts[1]) <= 31:
        return (f"{ip} is a Private IP address (Class B).")
    #Private IP ranges--internal network IPs 192.168.x.x
    elif first_octet == 192 and int(parts[1]) == 168:
        return (f"{ip} is a Private IP address (Class C).")
    #Loopback IP address
    elif first_octet == 127:
        return (f"{ip} is a Loopback IP address.")  
    #Public IP address
    else:
        return (f"{ip} is a Public IP address.")
#List of IP addresses to analyze
ip_addresses = input("Enter a list of IP addresses separated by commas: ").split(',')
#Analyze each IP address and print the result
for ip in ip_addresses:
    print(analyze_ip(ip))
    