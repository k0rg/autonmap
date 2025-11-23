import argparse
import concurrent.futures
import ipaddress
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

# --- CONFIGURATION ---
# Colors for terminal output
BLUE = '\033[94m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
ENDC = '\033[0m'

def print_msg(msg, level="info"):
    if level == "info": print(f"{BLUE}[*] {msg}{ENDC}")
    elif level == "success": print(f"{GREEN}[+] {msg}{ENDC}")
    elif level == "warn": print(f"{YELLOW}[!] {msg}{ENDC}")
    elif level == "error": print(f"{RED}[-] {msg}{ENDC}")

def check_dependencies():
    """Checks if required tools are installed."""
    if shutil.which("nmap") is None:
        print_msg("Error: 'nmap' is not installed or not in PATH.", "error")
        sys.exit(1)

def validate_ip(ip_str):
    """Validates if the string is a valid IP address."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def run_command(command, verbose=False):
    """Runs a command and streams output to the console."""
    if verbose:
        # Join the list for display purposes only
        cmd_str = " ".join(command)
        print(f"\n{YELLOW}Running: {cmd_str}{ENDC}")
    try:
        # shell=False is the secure way to run commands. 
        # It prevents shell injection attacks from user inputs like 'timing' or 'output'.
        if verbose:
            subprocess.check_call(command, shell=False)
        else:
            subprocess.check_call(command, shell=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        # Nmap might return non-zero if it fails or cancels, but we handle errors via file checks usually
        pass

def parse_open_ports(xml_file):
    """Parses Nmap XML to find open ports."""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        open_ports = []
        for host in root.findall('host'):
            ports = host.find('ports')
            if ports is not None:
                for port in ports.findall('port'):
                    state = port.find('state')
                    if state is not None and state.get('state') == 'open':
                        open_ports.append(port.get('portid'))
        return open_ports
    except Exception as e:
        print_msg(f"Could not parse XML ({xml_file}): {e}", "error")
        return []

def process_host(target_ip, output_base_dir, timing, skip_udp, udp_all, skip_vuln, verbose=False):
    """Main scanning logic for a single host."""
    
    # Create Directory for IP
    output_dir = os.path.join(output_base_dir, target_ip)
    os.makedirs(output_dir, exist_ok=True)
    
    print_msg(f"Starting Analysis for: {target_ip}", "success")

    # Define file paths (minus extensions)
    base_discovery = os.path.join(output_dir, "discovery")
    base_targeted  = os.path.join(output_dir, "targeted")
    base_vuln      = os.path.join(output_dir, "vuln")
    base_udp       = os.path.join(output_dir, "udp")

    # Split timing argument into list (e.g. "-T4 --min-rate 1000" -> ["-T4", "--min-rate", "1000"])
    timing_args = timing.split()

    # --- Step 1: TCP Discovery ---
    if not os.path.exists(f"{base_discovery}.xml"):
        print_msg(f"[{target_ip}] Step 1: Full TCP Discovery Scan")
        cmd = ["nmap", "-n", "-Pn", "-sS", "-p-"] + timing_args + [target_ip, "-oA", base_discovery]
        run_command(cmd, verbose)
    else:
        print_msg(f"[{target_ip}] Step 1: Skipped (Exists)")

    # Parse ports
    open_ports = parse_open_ports(f"{base_discovery}.xml")
    if not open_ports:
        print_msg(f"[{target_ip}] No open ports found. Aborting.", "warn")
        return
    
    port_list = ",".join(open_ports)
    print_msg(f"[{target_ip}] Open Ports: {port_list}", "success")

    # --- Step 2: Targeted Scan ---
    if not os.path.exists(f"{base_targeted}.xml"):
        print_msg(f"[{target_ip}] Step 2: Targeted Scan (-A)")
        cmd = ["nmap", "-n", "-Pn", "-sS", "-A", "-p", port_list] + timing_args + [target_ip, "-oA", base_targeted]
        run_command(cmd, verbose)
    else:
        print_msg(f"[{target_ip}] Step 2: Skipped (Exists)")

    # --- Step 3: Vuln Scan (Optional) ---
    if not skip_vuln:
        if not os.path.exists(f"{base_vuln}.xml"):
            print_msg(f"[{target_ip}] Step 3: Vulnerability Scan")
            cmd = ["nmap", "-n", "-Pn", "-sS", "--script", "vuln", "-p", port_list] + timing_args + [target_ip, "-oA", base_vuln]
            run_command(cmd, verbose)
        else:
            print_msg(f"[{target_ip}] Step 3: Skipped (Exists)")

    # --- Step 4: UDP Scan (Optional) ---
    if not skip_udp:
        if not os.path.exists(f"{base_udp}.xml"):
            run_udp = True
            use_all_ports = udp_all

            # Interactive Prompt Logic (Only in verbose/sequential mode and if no specific override set)
            if verbose and not udp_all:
                try:
                    choice = input(f"\n{YELLOW}[?] Run UDP scan on {target_ip}? (y/N): {ENDC}").lower()
                    if choice != 'y':
                        run_udp = False
                    else:
                        print(f"{YELLOW}    [1] Top 1,000 Ports (Standard - Fast){ENDC}")
                        print(f"{YELLOW}    [2] ALL 65,535 Ports (Comprehensive - Very Slow){ENDC}")
                        udp_type = input(f"{YELLOW}    Select Option [1/2]: {ENDC}").strip()
                        if udp_type == '2':
                            use_all_ports = True
                except EOFError:
                    run_udp = False

            if run_udp:
                if use_all_ports:
                    print_msg(f"[{target_ip}] Step 4: UDP Scan (ALL PORTS)")
                    cmd = ["nmap", "-n", "-Pn", "-sU", "-p-"] + timing_args + [target_ip, "-oA", base_udp]
                else:
                    print_msg(f"[{target_ip}] Step 4: UDP Scan (Top 1000)")
                    cmd = ["nmap", "-n", "-Pn", "-sU"] + timing_args + [target_ip, "-oA", base_udp]
                
                run_command(cmd, verbose)
            else:
                print_msg(f"[{target_ip}] Step 4: Skipped (User declined)")
        else:
            print_msg(f"[{target_ip}] Step 4: Skipped (Exists)")

    print_msg(f"[{target_ip}] Analysis Complete.", "success")

def main():
    parser = argparse.ArgumentParser(description="Automated Nmap Scanner")
    parser.add_argument("target", help="IP address or file containing list of IPs")
    parser.add_argument("-o", "--output", default=".", help="Base output directory")
    parser.add_argument("-t", "--threads", type=int, default=1, help="Number of concurrent hosts to scan (default: 1)")
    parser.add_argument("--timing", default="-T4", help="Nmap timing template (default: -T4)")
    parser.add_argument("--no-udp", action="store_true", help="Skip UDP scan")
    parser.add_argument("--udp-all", action="store_true", help="Run comprehensive UDP scan (all 65535 ports)")
    parser.add_argument("--no-vuln", action="store_true", help="Skip Vulnerability scan")
    
    args = parser.parse_args()

    # 1. Root Check
    if os.geteuid() != 0:
        print_msg("Root privileges required.", "error")
        sys.exit(1)

    # 2. Dependency Check
    check_dependencies()

    # 3. Target Parsing
    targets = []
    if os.path.isfile(args.target):
        with open(args.target, 'r') as f:
            for line in f:
                line = line.strip()
                if line and validate_ip(line):
                    targets.append(line)
                elif line:
                    print_msg(f"Skipping invalid IP in file: {line}", "warn")
    else:
        if validate_ip(args.target):
            targets.append(args.target)
        else:
            print_msg("Invalid target IP address.", "error")
            sys.exit(1)

    if not targets:
        print_msg("No valid targets found.", "error")
        sys.exit(1)

    print_msg(f"Loaded {len(targets)} targets. Output dir: {args.output}")
    
    # 4. Concurrent Execution
    # We use a ThreadPoolExecutor to run scans in parallel
    # If threads=1, we enable verbose output (showing nmap stdout)
    verbose_mode = (args.threads == 1)

    if verbose_mode:
        print_msg("Sequential scan detected. Verbose output enabled.", "info")
    else:
        print_msg(f"Concurrent scan detected ({args.threads} threads). Output suppressed to prevent interleaving.", "info")

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        try:
            for ip in targets:
                futures.append(
                    executor.submit(process_host, ip, args.output, args.timing, args.no_udp, args.udp_all, args.no_vuln, verbose_mode)
                )
            
            # Wait for all to complete
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print_msg(f"An error occurred during scanning: {e}", "error")
        except KeyboardInterrupt:
            print_msg("\nScan interrupted by user. Shutting down...", "warn")
            executor.shutdown(wait=False, cancel_futures=True)
            sys.exit(1)

if __name__ == "__main__":
    main()
