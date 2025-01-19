import psutil
import os
import socket
import subprocess
import requests
import matplotlib.pyplot as plt
import seaborn as sns
import time

# Function to check for system configuration details like users, firewall status
def system_config_analysis():
    print("[*] Analyzing system configuration...")

    # Checking for active user accounts
    users = psutil.users()
    print(f"Active users: {users}")

    # Checking firewall status (platform dependent)
    if os.name == 'nt':
        # Windows Firewall check (example)
        firewall_status = subprocess.run("netsh advfirewall show allprofiles", shell=True, capture_output=True, text=True)
        firewall_status = "Enabled" if "State ON" in firewall_status.stdout else "Disabled"
    elif os.name == 'posix':
        # Linux iptables check (example)
        firewall_status = subprocess.run("sudo ufw status", shell=True, capture_output=True, text=True)
        firewall_status = "Enabled" if "active" in firewall_status.stdout else "Disabled"
    else:
        firewall_status = "Unknown"

    return {
        "users": len(users),
        "firewall": firewall_status,
    }

# Function to check for open ports
def open_ports_analysis():
    print("[*] Analyzing open ports...")
    open_ports = []
    for conn in psutil.net_connections(kind='inet'):
        open_ports.append(conn.laddr.port)

    return open_ports

# Function to check for known vulnerabilities using Vulners API
def vulnerability_analysis():
    print("[*] Checking for known vulnerabilities...")

    # Example query to Vulners API for vulnerabilities related to system packages
    url = "https://vulners.com/api/v3/search/lucene/?query=os:linux"
    response = requests.get(url)
    vulnerabilities = response.json() if response.status_code == 200 else {}

    # Parsing the results for known vulnerabilities
    vulnerability_info = []
    if 'data' in vulnerabilities:
        for item in vulnerabilities['data']['search']:
            vulnerability_info.append({
                'cve': item.get('cve', 'N/A'),
                'title': item.get('title', 'No title available'),
                'severity': item.get('cvss', 'N/A'),
                'link': item.get('link', 'No link available')
            })

    return vulnerability_info

# Function to check system security based on files and directories
def file_system_analysis():
    print("[*] Analyzing file system...")
    risky_files = []
    risky_dirs = []
    
    for root, dirs, files in os.walk('/'):
        for file in files:
            if file.endswith('.exe') or file.endswith('.bat'):
                risky_files.append(os.path.join(root, file))
        for dir in dirs:
            if dir == 'tmp' or dir == 'logs':
                risky_dirs.append(os.path.join(root, dir))
    
    return risky_files, risky_dirs

# Function to generate graphical analysis
def generate_graphical_report(security_data):
    print("[*] Generating graphical analysis...")

    # Data for plotting
    categories = ['Users', 'Firewall', 'Open Ports', 'Risky Files', 'Risky Directories']
    values = [security_data['users'], 1 if security_data['firewall'] == 'Enabled' else 0, len(security_data['open_ports']),
              len(security_data['risky_files']), len(security_data['risky_dirs'])]

    plt.figure(figsize=(10, 6))
    sns.barplot(x=categories, y=values, palette='viridis')
    plt.title('Security Posture of Device')
    plt.xlabel('Security Aspects')
    plt.ylabel('Risk Level')
    plt.tight_layout()
    plt.show()

# Main function to analyze the device's security
def analyze_security():
    start_time = time.time()
    
    # System Configuration Analysis
    system_config = system_config_analysis()

    # File System Analysis
    risky_files, risky_dirs = file_system_analysis()

    # Open Ports Analysis
    open_ports = open_ports_analysis()

    # Vulnerability Analysis
    vulnerabilities = vulnerability_analysis()

    # Compiling security data
    security_data = {
        'users': system_config['users'],
        'firewall': system_config['firewall'],
        'open_ports': open_ports,
        'risky_files': risky_files,
        'risky_dirs': risky_dirs,
        'vulnerabilities': vulnerabilities
    }

    # Print risky files and directories
    print("[*] Risky Files Found:")
    for file in risky_files:
        print(f"File: {file}")
    print("\n[*] Risky Directories Found:")
    for dir in risky_dirs:
        print(f"Directory: {dir}")
        
    # Print detailed security issues (Vulnerabilities, Risks)
    print("\n[*] Vulnerabilities and Risks Found:")
    print("===================================")
    for vulnerability in vulnerabilities:
        print(f"CVEs: {vulnerability['cve']}")
        print(f"Title: {vulnerability['title']}")
        print(f"Severity: {vulnerability['severity']}")
        print(f"More Info: {vulnerability['link']}\n")

    # Generate Graphical Report
    generate_graphical_report(security_data)

    print(f"[*] Security analysis completed in {time.time() - start_time:.2f} seconds.")

# Run the security analysis
if __name__ == "__main__":
    analyze_security()
