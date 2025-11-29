# AutoNmap

**AutoNmap** is a Python-based automation wrapper for Nmap, designed to streamline the enumeration phase of penetration testing. It is specifically tailored for OSCP-style labs and exams where efficient, methodical scanning is critical.

The script automates the "Discovery -> Targeted -> Vulnerability" scanning workflow, organizing results into structured directories and ensuring no data is overwritten during restart.

## Features

*   **Multi-Stage Scanning:** Automates the progression from full TCP discovery (`-p-`) to targeted service versioning (`-sV -sC`).
*   **Smart Resume:** Detects existing scan files for a target and skips completed steps, preventing redundant scanning.
*   **OSCP-Ready Output:** Saves all scans in Nmap's "Output All" format (`-oA`), generating `.nmap`, `.gnmap`, and `.xml` files for easy grepping and reporting.
*   **Structured Organization:** Automatically creates a directory for each target IP (e.g., `./10.10.11.50/`) to keep workspaces clean.
*   **Flexible Targets:** Accepts a single IP address or a newline-separated file of targets.
*   **Parallel Scanning:** Supports concurrent scanning of multiple targets to save time.
*   **Non-Interactive:** Fully automated with CLI flags, perfect for background execution.

## Prerequisites

*   **Python 3.x**
*   **Nmap** (Must be installed and in your system PATH)
*   **Root Privileges** (Required for OS detection `-O` and UDP scans `-sU`)

## Installation

Clone the repository to your local machine:
```sh
git clone https://github.com/YOUR_USERNAME/AutoNmap.git
cd AutoNmap
```
## Usage

The script requires `sudo` privileges to perform SYN scans, OS detection, and UDP scans.

### Basic Usage
```sh
# Scan a single target
sudo python3 autonmap.py 10.10.11.50
```


### Multiple Targets

Create a text file (e.g., `hosts.txt`) with one IP address per line:
```
192.168.1.10
192.168.1.15
192.168.1.22
```

Run the script passing the file as an argument:
```sh
sudo python3 autonmap.py hosts.txt
```

### Advanced Options
```sh
# Scan with 4 threads, skip UDP and Vuln scans
sudo python3 autonmap.py hosts.txt -t 4 --no-udp --no-vuln

# Custom output directory and aggressive timing
sudo python3 autonmap.py 10.10.11.50 -o ./results --timing "-T5"
```

| Flag | Description | Default |
|------|-------------|---------|
| `-t`, `--threads` | Number of concurrent hosts to scan (1=Verbose, >1=Silent) | 1 |
| `-o`, `--output` | Base directory for results | Current Dir |
| `--timing` | Nmap timing template | -T4 |
| `--no-udp` | Skip UDP scanning | False |
| `--udp-top100` | Run UDP scan on top 100 most popular ports (default when UDP enabled) | False |
| `--no-vuln` | Skip Vulnerability scanning | False |

## Workflow Details

1.  **Discovery Scan:**
    *   Command: `nmap -n -Pn -sS -p- -T4 <IP>`
    *   Purpose: Quickly identify all open ports on the target.
2.  **Targeted Scan:**
    *   Command: `nmap -n -Pn -sS -A -p <Open_Ports> -T4 <IP>`
    *   Purpose: Enumerates versions and OS details only on the ports found in Step 1.
3.  **Vulnerability Scan (Optional):**
    *   Command: `nmap ... --script vuln ...`
    *   Purpose: Checks for known CVEs on detected services with Nmap's built-in script scans.
4.  **UDP Scan (Optional):**
    *   Command: `nmap -n -Pn -sU --top-ports 100 -T4 <IP>`
    *   Purpose: Scans top 100 UDP ports.

## Output Structure

The script creates a folder for each IP address scanned. Inside, files are named by the scan stage:
```sh
./10.10.11.50/
├── discovery.nmap    # Output of full TCP port scan
├── discovery.xml
├── discovery.gnmap
├── targeted.nmap     # Output of -A scan on open ports
├── targeted.xml
├── targeted.gnmap
├── vuln.nmap         # Output of –script vuln (if selected)
└── udp.nmap          # Output of UDP scan (if selected)
```

## Disclaimer

This tool is for educational purposes and authorized penetration testing only. Do not use this tool on networks you do not have explicit permission to test.

## License

[MIT License](LICENSE)