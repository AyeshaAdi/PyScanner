Advanced Wi-Fi Network Scanner
This Python script is a prototype for an advanced Wi-Fi network scanner. It leverages the nmap tool and its python-nmap wrapper to perform host discovery and port scanning on your connected local network. The script provides details about active hosts, their open ports, running services, and attempts to identify their operating systems.

Features
Automatic Network Detection: Automatically identifies your local IP address and determines the /24 network range to scan.

Target Customization: Allows you to specify a custom target network range (e.g., 192.168.1.0/24).

Configurable Port Scanning: Scans a default set of common ports, or you can specify a custom list of ports.

Host Discovery: Identifies active hosts on the network using a ping scan.

Port & Service Detection: For active hosts, it scans for open ports and attempts to determine the service and its version running on those ports.

Operating System (OS) Detection: Tries to identify the operating system of the discovered hosts (requires elevated privileges for best results).

Clear Output: Presents scan results in a readable and organized format.

Prerequisites
Before running the script, you need to have the following installed:

Nmap: The network mapper tool.

Official Website: https://nmap.org/download.html

Debian/Ubuntu: sudo apt-get install nmap

RedHat/CentOS: sudo yum install nmap

macOS (with Homebrew): brew install nmap

Windows: Download the installer from the official Nmap website.

python-nmap: The Python wrapper for Nmap.

pip install python-nmap

Installation
Save the provided Python script (e.g., wifi_scanner.py) to your local machine.

Usage
Navigate to the directory where you saved the script in your terminal or command prompt.

Basic Usage (Auto-detect network, default ports)
python wifi_scanner.py

Running with Elevated Privileges (Recommended for full features like OS Detection)
For comprehensive scans, especially OS detection and ARP scans, nmap often requires elevated privileges.

Linux/macOS:

sudo python wifi_scanner.py --sudo

(You will be prompted for your system password.)

Windows:
Run your Command Prompt or PowerShell as an Administrator, then execute:

python wifi_scanner.py --sudo

Customizing Target Network
You can specify a target network range using the --target argument.

python wifi_scanner.py --target 192.168.1.0/24

Customizing Ports to Scan
You can specify a comma-separated list of ports using the --ports argument.

python wifi_scanner.py --ports 80,443,22,8080,3306

The default ports are: 21,22,23,25,53,80,110,135,139,443,445,3389,8080,8443

Combining Arguments
You can combine any of the arguments as needed:

sudo python wifi_scanner.py --target 192.168.1.0/24 --ports 21,22,80,443 --sudo

Important Notes
Permissions: Running the script with sudo (Linux/macOS) or as Administrator (Windows) is highly recommended to enable all nmap features, especially OS detection and low-level network scanning.

Network Connectivity: Ensure your machine is connected to a Wi-Fi network for the script to auto-detect your local IP and network range.

Scanning Time: The scan duration depends on the size of the network and the number of ports being scanned. Larger networks or more ports will take longer.

Ethical Use: Please ensure you have proper authorization before scanning any network that is not your own. Unauthorized network scanning can be illegal and unethical. This script is intended for educational purposes and for scanning networks you own or have explicit permission to scan.

Feel free to modify or extend this script based on your specific needs!
