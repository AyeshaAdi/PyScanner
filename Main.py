import nmap
import socket
import ipaddress
import platform
import argparse
import subprocess
import sys
import time

# Define common ports for quick scanning if no specific ports are provided
DEFAULT_PORTS = "21,22,23,25,53,80,110,135,139,443,445,3389,8080,8443"

def check_nmap_installed():
    """
    Checks if nmap is installed on the system.
    Exits if nmap is not found.
    """
    try:
        # Try to run nmap --version to check if it's in the PATH
        subprocess.run(['nmap', '--version'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("[INFO] Nmap is installed and accessible.")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("\n[ERROR] Nmap is not installed or not found in your system's PATH.")
        print("Please install Nmap from https://nmap.org/download.html and try again.")
        print("On Debian/Ubuntu: sudo apt-get install nmap")
        print("On RedHat/CentOS: sudo yum install nmap")
        print("On macOS (using Homebrew): brew install nmap")
        print("On Windows: Download installer from nmap.org")
        sys.exit(1)

def get_local_network_details():
    """
    Attempts to get the local IP address and constructs a /24 network range.
    """
    try:
        # Get the hostname
        hostname = socket.gethostname()
        # Get the local IP address corresponding to the hostname
        local_ip = socket.gethostbyname(hostname)

        # Construct the /24 network range based on the local IP
        # Example: if local_ip is 192.168.1.100, network_range will be 192.168.1.0/24
        network_prefix = ".".join(local_ip.split('.')[:3])
        network_range = f"{network_prefix}.0/24"

        print(f"[INFO] Detected local IP: {local_ip}")
        print(f"[INFO] Using network range for scanning: {network_range}")
        return local_ip, network_range
    except socket.gaierror:
        print("[ERROR] Could not determine local IP address. Please ensure you are connected to a network.")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred while getting network details: {e}")
        sys.exit(1)

def perform_scan(target_network, target_ports, sudo_needed=False):
    """
    Performs host discovery and port scanning using nmap.PortScanner.
    Args:
        target_network (str): The network range to scan (e.g., "192.168.1.0/24").
        target_ports (str): The ports to scan (e.g., "21,22,80,443").
        sudo_needed (bool): True if sudo/administrator privileges are likely needed.
    Returns:
        dict: A dictionary containing scan results.
    """
    nm = nmap.PortScanner()
    scan_results = {}

    print(f"\n[PHASE 1/2] Starting host discovery (ping scan) on {target_network}...")
    print("This may take some time depending on the network size.")
    if sudo_needed:
        print("[WARNING] Sudo/Administrator privileges might be required for accurate results.")

    try:
        # -sn: Ping scan - just discovers hosts, doesn't port scan
        # -T4: Faster execution
        nm.scan(hosts=target_network, arguments='-sn -T4')
    except nmap.PortScannerError as e:
        print(f"[ERROR] Nmap PortScanner Error during host discovery: {e}")
        print("This often indicates permission issues. Try running the script with sudo/administrator privileges.")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred during host discovery: {e}")
        sys.exit(1)

    active_hosts = [host for host in nm.all_hosts() if nm[host].state() == 'up']
    print(f"[INFO] Found {len(active_hosts)} active hosts.")
    if not active_hosts:
        print("[INFO] No active hosts found. Exiting.")
        return scan_results

    print(f"\n[PHASE 2/2] Starting port and service scan on {len(active_hosts)} active hosts for ports: {target_ports}...")
    print("This will take longer.")

    for host_ip in active_hosts:
        print(f"  Scanning host: {host_ip} ({nm[host_ip].hostname() or 'N/A'})")
        try:
            # -sV: Service version detection
            # -O: OS detection (often requires root/admin)
            # -T4: Faster execution
            nm.scan(hosts=host_ip, ports=target_ports, arguments='-sV -O -T4')

            if host_ip in nm.all_hosts():
                host_info = nm[host_ip]
                host_data = {
                    'status': host_info.state(),
                    'hostname': host_info.hostname(),
                    'addresses': host_info.all_addresses(),
                    'os_matches': [],
                    'ports': {}
                }

                # OS Detection (if available)
                if 'osmatch' in host_info:
                    for osmatch in host_info['osmatch']:
                        host_data['os_matches'].append({
                            'name': osmatch['name'],
                            'accuracy': osmatch['accuracy']
                        })

                # Port details
                for proto in host_info.all_protocols():
                    lport = host_info[proto].keys()
                    for port in lport:
                        port_details = host_info[proto][port]
                        host_data['ports'][port] = {
                            'state': port_details['state'],
                            'service': port_details['name'],
                            'product': port_details.get('product', ''),
                            'version': port_details.get('version', '')
                        }
                scan_results[host_ip] = host_data
            else:
                print(f"  [WARNING] No scan data for {host_ip} after port scan.")

        except nmap.PortScannerError as e:
            print(f"  [ERROR] Nmap PortScanner Error for {host_ip}: {e}")
            print("  Consider running the script with sudo/administrator privileges if experiencing issues.")
        except Exception as e:
            print(f"  [ERROR] An unexpected error occurred while scanning {host_ip}: {e}")

    return scan_results

def display_results(results, local_ip):
    """
    Prints the scan results in a readable format.
    """
    print("\n" + "="*50)
    print("           NETWORK SCAN RESULTS           ")
    print("="*50)

    if not results:
        print("\nNo active hosts or open ports found based on the scan parameters.")
        return

    for ip, data in results.items():
        is_self = " (YOU)" if ip == local_ip else ""
        print(f"\nHost: {ip}{is_self}")
        print(f"  Hostname: {data['hostname'] or 'N/A'}")
        print(f"  Status: {data['status']}")
        print(f"  Addresses: {', '.join(data['addresses'])}")

        if data['os_matches']:
            print("  OS Guesses:")
            for os_match in data['os_matches']:
                print(f"    - Name: {os_match['name']}, Accuracy: {os_match['accuracy']}%")
        else:
            print("  OS Guesses: N/A")

        if data['ports']:
            print("  Open/Filtered Ports:")
            for port, p_data in data['ports'].items():
                service_info = f"({p_data['service']}"
                if p_data['product']:
                    service_info += f" - {p_data['product']}"
                if p_data['version']:
                    service_info += f" v{p_data['version']}"
                service_info += ")"
                print(f"    Port {port}/{p_data['state']}: {service_info}")
        else:
            print("  No open ports found on specified scan range.")
    print("\n" + "="*50)
    print("Scan finished.")
    print("="*50)


def main():
    parser = argparse.ArgumentParser(
        description="Advanced Wi-Fi Network Scanner Prototype. "
                    "Performs host discovery and port scanning on your connected network."
    )
    parser.add_argument(
        '--target',
        type=str,
        help="Target network range (e.g., '192.168.1.0/24'). "
             "If not provided, attempts to auto-detect from local IP."
    )
    parser.add_argument(
        '--ports',
        type=str,
        default=DEFAULT_PORTS,
        help=f"Ports to scan (comma-separated, e.g., '80,443,22'). "
             f"Default: {DEFAULT_PORTS}"
    )
    parser.add_argument(
        '--sudo',
        action='store_true',
        help="Indicate that the script is being run with sudo/administrator privileges. "
             "This can help nmap with certain scan types (e.g., OS detection, ARP scans)."
    )

    args = parser.parse_args()

    # Step 1: Check if nmap is installed
    check_nmap_installed()

    local_ip = None
    target_network = args.target

    # Step 2: Determine target network if not provided by user
    if not target_network:
        local_ip, target_network = get_local_network_details()
    else:
        # If target is provided, still try to get local IP for marking in results
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except socket.gaierror:
            local_ip = "Unknown"
        print(f"[INFO] Using user-specified target network: {target_network}")

    # Step 3: Inform about permissions
    os_name = platform.system()
    if os_name == "Linux" or os_name == "Darwin": # macOS is Darwin
        print("\n[IMPORTANT] On Linux/macOS, nmap often requires 'sudo' for full functionality (e.g., OS detection, ARP scans).")
        print("Please consider running this script with 'sudo python your_script_name.py'.")
    elif os_name == "Windows":
        print("\n[IMPORTANT] On Windows, nmap might require running your command prompt/PowerShell as 'Administrator' for full functionality.")
    else:
        print("\n[IMPORTANT] Depending on your OS, you might need elevated privileges (root/administrator) for comprehensive scans.")

    # Step 4: Perform the scan
    start_time = time.time()
    scan_results = perform_scan(target_network, args.ports, args.sudo)
    end_time = time.time()

    # Step 5: Display results
    display_results(scan_results, local_ip)

    print(f"\nTotal scan time: {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()
