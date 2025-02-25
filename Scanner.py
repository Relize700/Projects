#!/usr/bin/python3

# Some parts of this code was modified and generated using ChatGPT. 

# Import section

import nmap
import os
import socket

# Main Menu section.

def main_menu():
    while True:
        print("Select an option:")
        print("1. Port Scanner")
        print("2. Find Vulnerability")
        print("3. Possible Exploits and Tools")
        choice = input("Enter your choice (1-3): ").strip()
        if choice in ["1", "2", "3"]:
            return choice
        else:
            print("Invalid choice. Please enter a valid option (1-3).")

# Port Scanner Section.

def port_scanner():
    target = input("Enter target IP or domain: ").strip()
    print("Select scan type:")
    print("1. Regular Scanning (TCP Connect, -T4)")
    print("2. Stealth Scanning (SYN Scan)")
    print("3. Lab Environment Scanning (TCP Connect, -T5)")
    scan_type = input("Enter your choice (1-3): ").strip()

# Port range selection.

    print("Select port range:")
    print("1. Common Ports (Top 1000)")
    print("2. First 10,000 Ports (1-10000)")
    print("3. Full Range (1-65535)")
    print("4. Custom Range (Specify range)")
    port_choice = input("Enter your choice (1-4): ").strip()
    
    if port_choice == "1":
        port_range = "--top-ports 1000"
    elif port_choice == "2":
        port_range = "-p 1-10000"
    elif port_choice == "3":
        port_range = "-p 1-65535"
    elif port_choice == "4":
        custom_range = input("Enter custom port range (e.g., 20-80,443,8080): ").strip()
        port_range = f"-p {custom_range}"
    else:
        print("Invalid choice. Defaulting to common ports.")
        port_range = "--top-ports 1000"

# Additional options.

    print("Do you want to include additional information?")
    print("1. Yes (For OS detection, version detection, script scanning, and traceroute)")
    print("2. No")
    extra_info = input("Enter your choice (1-2): ").strip()
    extra_flag = "-A" if extra_info == "1" else ""
    
    print("Do you want verbose output?")
    print("1. Yes (For verbose output)")
    print("2. No")
    verbose_option = input("Enter your choice (1-2): ").strip()
    verbose_flag = "-v" if verbose_option == "1" else ""
    
    scanner = nmap.PortScanner()

# Selecting speed of scanning for stealth mode.

    if scan_type == "1":
        scan_argument = f"-sT {port_range} -T4 {extra_flag} {verbose_flag}"
    elif scan_type == "2":
        print("How noisy would you like to be?")
        print("1. -T5 (Fastest scanning)")
        print("2. -T4")
        print("3. -T3")
        print("4. -T2")
        print("5. -T1 (Slowest scanning)")
        stealth_noise = input("Enter your choice (1-5): ").strip()
        stealth_timing = {"1": "-T5", "2": "-T4", "3": "-T3", "4": "-T2", "5": "-T1"}.get(stealth_noise, "-T3")
        scan_argument = f"-sS {port_range} {stealth_timing} {extra_flag} {verbose_flag}"
    elif scan_type == "3":
        scan_argument = f"-sT {port_range} -T5 {extra_flag} {verbose_flag}"
    else:
        print("Invalid choice. Defaulting to Regular Scanning.")
        scan_argument = f"-sT {port_range} -T4 {extra_flag} {verbose_flag}"
    
    print(f"Scanning {target} with {'Regular' if scan_type == '1' else 'Stealth' if scan_type == '2' else 'Lab'} scanning...")
    try:
        scanner.scan(target, arguments=scan_argument.strip())
    except Exception as e:
        print(f"An error occurred during scanning: {e}")
        return

# Showing scan results.

    scan_results = []
    scan_results.append("\nScan Results:")
    for host in scanner.all_hosts():
        scan_results.append(f"\nHost: {host} ({scanner[host].hostname()})")
        scan_results.append(f"State: {scanner[host].state()}")
        for proto in scanner[host].all_protocols():
            scan_results.append(f"\nProtocol: {proto}")
            ports = scanner[host][proto].keys()
            for port in sorted(ports):
                scan_results.append(f"Port: {port}\tState: {scanner[host][proto][port]['state']}")
        
        if extra_info == "1":
            scan_results.append("\nAdditional Information:")
            if 'osmatch' in scanner[host]:
                for os_match in scanner[host]['osmatch']:
                    scan_results.append(f"OS Match: {os_match['name']} (Accuracy: {os_match['accuracy']}%)")
            if 'tcp' in scanner[host]:
                for port in scanner[host]['tcp']:
                    scan_results.append(f"Port {port}: {scanner[host]['tcp'][port]['name']} {scanner[host]['tcp'][port]['version']}")
    
    print("\n".join(scan_results))

# Saving port scanning results.

    save_option = input("Do you want to save the scan results? (yes/no): ").strip().lower()
    if save_option == "yes":
        filename = f"scan_results_{target}.txt"
        try:
            with open(filename, "w") as file:
                file.write("\n".join(scan_results))
            print(f"Scan results saved as {filename}")
        except Exception as e:
            print(f"Error saving scan results: {e}")
            
# End of port scanner
#=====================================================================================
# Vulnerability Scanner.

# Request user for specific machine IP address.

def find_vulnerabilities():
    target = input("Enter target IP or domain to analyze vulnerabilities: ").strip()
    filename = f"scan_results_{target}.txt"

# Checking if file from port scanner is saved.
    
    if not os.path.exists(filename):
        print("Scan results file not found. Run a port scan first and save the results.")
        return

# Reading ports from port scanner file.
    
    open_ports = []
    with open(filename, "r") as file:
        for line in file:
            if line.strip().startswith("Port:"):
                parts = line.split()
                if len(parts) > 1:
                    open_ports.append(parts[1].strip())
    
    if not open_ports:
        print("No open ports found in the scan results.")
        return

    ports_str = ",".join(open_ports)
    print(f"Scanning {target} for vulnerabilities on open ports: {ports_str}...")

# Nmap vulnerability scanner.

    scanner = nmap.PortScanner()
    scan_argument = f"-sV -p {ports_str} --script vuln"
    try:
        scanner.scan(target, arguments=scan_argument.strip())
    except Exception as e:
        print(f"An error occurred during vulnerability scanning: {e}")
        return

# Printing results.

    vuln_results = []
    vuln_results.append("\nVulnerability Scan Results:")
    for host in scanner.all_hosts():
        vuln_results.append(f"\nHost: {host} ({scanner[host].hostname()})")
        for proto in scanner[host].all_protocols():
            vuln_results.append(f"\nProtocol: {proto}")
            ports = scanner[host][proto].keys()
            for port in sorted(ports):
                vuln_results.append(f"Port: {port}\tState: {scanner[host][proto][port]['state']}")
                if 'script' in scanner[host][proto][port]:
                    vuln_results.append("Vulnerabilities:")
                    for script, output in scanner[host][proto][port]['script'].items():
                        vuln_results.append(f"{script}: {output}")
    
    print("\n".join(vuln_results))
    
# Saving vulnerability results.

    save_vuln = input("Do you want to save the vulnerability scan results? (yes/no): ").strip().lower()
    if save_vuln == "yes":
        vuln_filename = f"vuln_results_{target}.txt"
        try:
            with open(vuln_filename, "w") as file:
                file.write("\n".join(vuln_results))
            print(f"Vulnerability scan results saved as {vuln_filename}")
        except Exception as e:
            print(f"Error saving vulnerability results: {e}")
            
# End of vulnerability scanner
#====================================================================================================
# Possible Exploits and Tools.

# Request user for specific machine IP address and check files from Port Scanner and Vulnerability Scanner.

def find_possible_exploits():
    target = input("Enter target IP or domain to analyze possible exploits: ").strip()
    scan_filename = f"scan_results_{target}.txt"
    vuln_filename = f"vuln_results_{target}.txt"

# Check which file is available, if not request to run Port Scanner and Vulnerability Scanner.
    
    if not os.path.exists(scan_filename) or not os.path.exists(vuln_filename):
        print("Required scan or vulnerability files not found. Run a port scan and vulnerability scan first.")
        return
    
    exploit_suggestions = []
    
# Read scanned ports from port scanner file. 
    scanned_ports = set()
    with open(scan_filename, "r") as scan_file:
        for line in scan_file:
            if "Port:" in line:
                parts = line.split()
                if len(parts) > 1:
                    port_number = parts[1].strip()
                    scanned_ports.add(port_number)
    
# Analyze vulnerabilities and assign them to the ports.

    port_vuln_map = {port: [] for port in scanned_ports}
    with open(vuln_filename, "r") as file:
        for line in file:
            line = line.strip()
            if any(keyword in line.lower() for keyword in ["cve-", "vuln", "exploit", "weak"]):
                for port in scanned_ports:
                    if f"Port {port}" in line:
                        port_vuln_map[port].append(line)
                        break
    
# Check for vulnerabilities found in vulnerability scanner.

    ports_with_vulns = []
    for port in scanned_ports:
        if port_vuln_map[port]:
            ports_with_vulns.append(port)
            exploit_suggestions.append(f"\nExploits for Port {port}:")
            exploit_suggestions.extend(port_vuln_map[port])
    
# Database suggested exploits and tools possible on specific ports if vulnerabilities are not found.
    
    if len(ports_with_vulns) < len(scanned_ports):
        show_suggestions = input("Do you want to see suggested exploits and tools for ports with no vulnerabilities? (yes/no): ").strip().lower()
        if show_suggestions == "yes":
            exploit_suggestions.append("\nSuggested Exploits and Tools:")
            port_service_map = {
            "20": ("FTP-Data", ["Used with FTP. No specific exploits suggested."]),
            "21": ("FTP", ["Brute Force: Hydra/Medusa", "Anonymous FTP: Nmap NSE", "Metasploit module: ftp_login"]),
            "22": ("SSH", ["Brute Force: Hydra/Medusa", "ssh-audit for weak ciphers", "Metasploit module: exploit/linux/ssh"]),
            "23": ("Telnet", ["Brute Force: Hydra", "Banner analysis for service info"]),
            "25": ("SMTP", ["SMTP Enumeration: smtp-user-enum", "Brute Force: Hydra/Medusa", "Nmap script: smtp-open-relay"]),
            "53": ("DNS", ["Zone Transfer: dig/nslookup", "DNS Enumeration: Fierce, dnsenum"]),
            "69": ("TFTP", ["TFTP Exploits: Check for misconfigurations, use tftp-hammer"]),
            "80": ("HTTP", ["Vulnerability Scanning: Nikto", "Directory Brute Force: Dirb/Gobuster", "Web Exploitation: SQLMap, Burp Suite"]),
            "88": ("Kerberos", ["Kerberoasting: Use Impacket's GetUserSPNs.py", "Brute Force: Hydra", "Ticket Exploitation: Rubeus"]),
            "110": ("POP3", ["Brute Force: Hydra", "POP3 Enumeration: Metasploit module: pop3_login"]),
            "119": ("NNTP", ["NNTP Exploits: Check for misconfigurations"]),
            "135": ("Microsoft RPC", ["RPC Enumeration: rpcclient", "Metasploit module: exploit/windows/dcerpc/ms03_026_dcom"]),
            "139": ("NetBIOS", ["SMB Enumeration: enum4linux", "Password Spraying: Hydra/Medusa"]),
            "143": ("IMAP", ["Brute Force: Hydra", "IMAP Enumeration: Nmap NSE"]),
            "161": ("SNMP", ["SNMP Enumeration: snmpwalk, snmp-check"]),
            "162": ("SNMPTRAP", ["SNMP Trap Analysis: snmptrapd"]),
            "389": ("LDAP", ["Anonymous Bind Testing: ldapsearch -x", "Brute Force: Hydra", "Enumeration: ldapenum"]),
            "443": ("HTTPS", ["SSL/TLS Testing: testssl.sh, SSLScan", "Web Exploitation: Burp Suite, SQLMap"]),
            "464": ("Kerberos Password Change", ["Password Spraying: Hydra", "Cracking extracted hashes: John the Ripper"]),
            "465": ("SMTPS", ["Brute Force: Hydra", "Check for SSL/TLS misconfigurations"]),
            "514": ("Syslog", ["Syslog analysis tools", "Check for misconfigurations"]),
            "515": ("Printer", ["Printer exploitation: Metasploit modules", "Banner grabbing"]),
            "520": ("RIP", ["Check for misconfigurations"]),
            "631": ("IPP", ["Printer/IPP enumeration and exploitation"]),
            "636": ("LDAPS", ["Certificate Analysis: openssl s_client -connect", "Brute Force: Hydra", "Enumeration: ldapsearch -x -ZZ"]),
            "749": ("Kerberos Admin", ["Kerberos administration: kadmin", "Check for default credentials or misconfigurations"]),
            "993": ("IMAPS", ["Brute Force: Hydra", "IMAP Enumeration: Nmap NSE"]),
            "995": ("POP3S", ["Brute Force: Hydra", "POP3S Enumeration: Nmap NSE"]),
            "1433": ("MSSQL", ["SQL Server Enumeration: nmap scripts", "Brute Force: Hydra"]),
            "3389": ("RDP", ["BlueKeep: Metasploit module cve_2019_0708_bluekeep", "Brute Force: Hydra"]),
            "3306": ("MySQL", ["Brute Force: Hydra", "Exploitation: SQLMap, Metasploit modules"]),
            "5432": ("PostgreSQL", ["Brute Force: Hydra", "Enumeration tools: pg_isready, Metasploit modules"]),
            "5900": ("VNC", ["Brute Force: Hydra", "Exploitation: Metasploit module vnc_login"]),
            "5985": ("WinRM", ["Brute Force: Evil-WinRM", "Weak Authentication: CrackMapExec"]),
            "8000": ("HTTP-Alt", ["Web Exploitation: SQLMap, Burp Suite", "Directory Enumeration: Dirb/Gobuster"]),
            "8080": ("HTTP-Alt", ["Vulnerability Scanning: Nikto", "Web Exploitation: SQLMap, Burp Suite"]),
            "8081": ("HTTP-Alt", ["Web Exploitation: Nikto, SQLMap, Burp Suite"]),
            "8443": ("HTTPS-Alt", ["SSL/TLS Testing: testssl.sh", "Web Exploitation: Burp Suite"]),
            "MITM6": ("Man-in-the-Middle", ["MITM6 for IPv6 spoofing", "NTLM relay attacks - Impacket’s ntlmrelayx.py", "SecretsDump for password dumping"]),
                "MITM6": ("Man-in-the-Middle", ["MITM6 for IPv6 spoofing", "NTLM relay attacks - Impacket’s ntlmrelayx.py", "SecretsDump for password dumping"])
            }

# Put suggested exploits from program database to ports found in port scanner.
            
            ports_with_suggestions = []
            ports_without_vulns = scanned_ports.difference(ports_with_vulns)
            
            for port in sorted(ports_without_vulns, key=lambda x: int(x)):
                if port in port_service_map:
                    service_name, suggestions = port_service_map[port]
                    if suggestions:
                        exploit_suggestions.append(f"\nFor Port {port} ({service_name}):")
                        for s in suggestions:
                            exploit_suggestions.append(f"  - {s}")
                    else:
                        exploit_suggestions.append(f"\nPort {port}: {service_name}")
                else:
# Trying to find out service name if port is not on the list in the program database.
                    try:
                        port_int = int(port)
                    except Exception:
                        port_int = None
                    if port_int is not None and 1 <= port_int <= 10000:
                        try:
                            service_name = socket.getservbyport(port_int)
                        except Exception:
                            service_name = "Unknown Service"
                    else:
                        service_name = "Unknown Service"
                    exploit_suggestions.append(f"\nPort {port}: {service_name}")
    
    exploit_suggestions.append("\nCheck for CVEs:")
    exploit_suggestions.append("- CVE Database: https://cve.mitre.org/")
    exploit_suggestions.append("- Exploit-DB: https://www.exploit-db.com/")
    
    print("\n".join(exploit_suggestions))

# Saving possible exploits.
   
    save_exploit = input("Do you want to save the exploit suggestions? (yes/no): ").strip().lower()
    if save_exploit == "yes":
        exploit_filename = f"exploits_{target}.txt"
        with open(exploit_filename, "w") as file:
            file.write("\n".join(exploit_suggestions))
        print(f"Exploit suggestions saved as {exploit_filename}")


# Main entry point.
if __name__ == "__main__":
    user_choice = main_menu()
    if user_choice == "1":
        port_scanner()
    elif user_choice == "2":
        find_vulnerabilities()
    elif user_choice == "3":
        find_possible_exploits()
