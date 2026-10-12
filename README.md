# ScanIt — Python Network Scanner

A multithreaded Python network scanner for discovering reachable hosts, identifying open TCP ports, detecting common services, and performing basic operating system fingerprinting.

## Overview

ScanIt is a command-line network reconnaissance tool developed with Python's standard library. It combines host discovery, TCP port scanning, service identification, and optional operating system estimation into a single utility.

The tool can scan a specified IPv4 address, hostname, IP range, or CIDR network. When no target is supplied, it attempts to detect the local network and use it as the scan target.

The project was built to strengthen my understanding of Python programming, network communication, socket programming, concurrent execution, and practical network reconnaissance.

**Project type:** Network Reconnaissance / Python / Cybersecurity

## Features

- **Host discovery:** Identifies reachable hosts using ICMP ping and optional TCP probes.
- **TCP port scanning:** Checks specified TCP ports and reports those that accept connections.
- **Flexible target input:** Supports individual IPv4 addresses, hostnames, IP ranges, and CIDR notation.
- **Multithreading:** Uses `ThreadPoolExecutor` to perform host discovery and port scanning concurrently.
- **Service identification:** Uses Python's service-name database to associate common TCP ports with service names.
- **Banner grabbing:** Optionally retrieves basic service responses, including HTTP response headers where supported.
- **Operating system estimation:** Uses TTL values, service banners, and open-port information to make a best-effort OS guess.
- **Configurable scan parameters:** Supports custom port ranges, thread counts, connection timeouts, and maximum host limits.
- **JSON reporting:** Saves scan results to a structured JSON file for later analysis.
- **Cross-platform considerations:** Includes platform-specific handling for Windows, macOS, and Linux networking commands.
- **Input validation:** Validates target specifications, port ranges, and scan configuration values.

## Tools and Technologies

| Technology | Purpose |
|---|---|
| Python 3 | Main programming language |
| `socket` | TCP connections, host resolution, and service identification |
| `ipaddress` | IPv4 address and network manipulation |
| `subprocess` | Executes system commands such as `ping`, `ipconfig`, and `ip` |
| `concurrent.futures` | Concurrent host discovery and port scanning |
| `argparse` | Command-line argument parsing |
| `re` | Regular-expression matching for network command output and TTL values |
| `json` | Exporting scan results |
| `platform` | Operating system detection |
| `errno` | Interpreting connection error codes |
| `time` | Measuring scan duration |
| `math` | Calculating platform-appropriate ping timeout values |

All dependencies used by the application are from Python's standard library. No third-party Python packages are required.

## Requirements

- Python 3.9 or later recommended.
- Windows, Linux, or macOS.
- Network connectivity to the authorized targets.
- Permission to perform host discovery and TCP port scanning on the target systems.

Some host discovery functions depend on operating-system utilities such as `ping`, `ipconfig`, `ip`, or `ifconfig`. Availability and command-line options may vary by platform.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Femi49/scanit-network-scanner.git
```

### 2. Navigate to the project directory

```bash
cd scanit-network-scanner
```

### 3. Run the scanner


```bash
python scanit.py --help
```

On systems where Python 3 is invoked separately, use:

```bash
python3 scanit.py --help
```

The help menu displays the available command-line arguments and their default values.

## Usage

The scanner is controlled through command-line arguments.

### Scan a single host

```bash
python scanit.py 192.168.1.10
```

This targets the specified IPv4 address using the default port range.

### Scan a CIDR network

```bash
python scanit.py 192.168.1.0/24
```

This targets the usable host addresses in the specified IPv4 network, subject to the configured maximum-host limit.

### Scan an IP range

```bash
python scanit.py 192.168.1.1-20
```

The scanner also supports a full range:

```bash
python scanit.py 192.168.1.1-192.168.1.20
```

### Scan a hostname

```bash
python scanit.py example.com
```

The hostname is resolved to an IPv4 address before scanning. This example is illustrative; scan only hosts for which you have authorization.

### Scan selected ports

```bash
python scanit.py 192.168.1.10 -p 22,80,443
```

This checks TCP ports 22, 80, and 443.

### Scan a port range

```bash
python scanit.py 192.168.1.10 -p 1-1000
```

This checks TCP ports 1 through 1000.

### Skip host discovery

```bash
python scanit.py 192.168.1.10 -Pn
```

This treats the target as reachable and proceeds directly to port scanning. It is useful when ICMP and TCP-based discovery probes cannot establish whether a host is online.

### Adjust concurrency and timeout

```bash
python scanit.py 192.168.1.10 -p 1-1024 -t 50 --timeout 2
```

This uses up to 50 worker threads and a two-second connection timeout.

Increasing concurrency may improve performance, but it can also increase network traffic and resource usage.

### Enable operating system estimation

```bash
python scanit.py 192.168.1.10 -O
```

The scanner attempts to estimate the target's operating system using TTL information, service banners, and open-port indicators.

The result is a heuristic estimate, not definitive operating system identification.

### Enable service banner grabbing

```bash
python scanit.py 192.168.1.10 -p 80,443,8080 -b
```

The `-b` option enables basic banner collection for open ports. For HTTP-related ports, the scanner attempts to send an HTTP `HEAD` request and capture a short response.

Not all services return readable banners, and some services may not respond as expected.

### Save results to JSON

```bash
python scanit.py 192.168.1.10 -p 22,80,443 -O -b -o results.json
```

This saves the scan summary to `results.json`, including the target, number of ports scanned, host results, open-port information, elapsed time, and optional OS estimates.

### Set a maximum number of target hosts

```bash
python scanit.py 192.168.1.0/24 --max-hosts 512
```

The `--max-hosts` option controls the maximum target size accepted by the parser. Its default value is 1024.

This is a guardrail against unintentionally large scans, not a substitute for authorization or network scope controls.

## Command-Line Options

| Argument | Description | Default |
|---|---|---|
| `network` | IPv4 address, hostname, IP range, or CIDR network | Detected local network |
| `-p`, `--ports` | Ports or ranges to scan | `1-1024` |
| `-t`, `--threads` | Number of worker threads | `100` |
| `--timeout` | Per-connection timeout in seconds | `1.0` |
| `-Pn`, `--no-ping` | Skip host discovery and treat all targets as up | Disabled |
| `--no-tcp-fallback` | Disable TCP fallback during host discovery | Disabled |
| `-O`, `--os-detect` | Enable OS estimation | Disabled |
| `-b`, `--banners` | Enable service banner collection | Disabled |
| `--max-hosts` | Maximum number of target addresses accepted | `1024` |
| `-o`, `--output` | Save results to a JSON file | Not set |
| `-h`, `--help` | Display the help menu | N/A |

## How It Works

The scanning workflow consists of the following stages.

### 1. Target processing

The input is parsed to determine whether it represents an IPv4 address, hostname, address range, or CIDR network. Invalid targets and oversized networks are rejected.

### 2. Host discovery

Unless `-Pn` is specified, the scanner attempts to determine which hosts are reachable.

It first tries ICMP ping. When TCP fallback is enabled, it also probes common ports to identify hosts that may be online but do not respond to ping requests.

### 3. TCP port scanning

For each selected host, the scanner attempts TCP connections to the specified ports. Ports that successfully accept a connection are reported as open.

The scan runs concurrently using a thread pool to reduce the time spent waiting for individual network operations.

### 4. Service identification

For open ports, the scanner uses the local service-name database to retrieve a conventional TCP service name when available.

These names are indicators based on port assignments; they do not independently verify the actual application running on a port.

### 5. Banner collection

When enabled, the scanner attempts to retrieve a short service response. HTTP-related ports receive a basic `HEAD` request.

Banner information can provide additional clues about a service, but the scanner does not perform comprehensive application-layer fingerprinting.

### 6. Operating system estimation

When `-O` is enabled, the tool considers TTL values, service banners, and selected open ports to estimate the likely operating system.

Network routing, filtering, customized TTL values, and services shared across operating systems can affect the result.

### 7. Results and reporting

The scanner prints its findings to the terminal and can export structured results to JSON for documentation, further analysis, or use in other scripts.

## Example JSON Output

The following is an illustrative example of the report structure; actual values depend on the scan results and enabled options.

```json
{
  "target": "192.168.1.10",
  "ports_scanned": 3,
  "hosts": [
    {
      "ip": "192.168.1.10",
      "open_ports": [
        {
          "port": 22,
          "service": "ssh",
          "banner": ""
        },
        {
          "port": 80,
          "service": "http",
          "banner": "HTTP/1.1 200 OK"
        }
      ],
      "ttl": 64,
      "os_guess": "Linux / Unix / macOS / Android / iOS"
    }
  ],
  "elapsed_seconds": 1.52
}
```
## Limitations

ScanIt is intended for basic network reconnaissance and learning. It is not a replacement for a full-featured vulnerability scanner or an advanced network discovery platform.

Known limitations include:

- IPv4 targets only; IPv6 scanning is not supported.
- TCP port scanning only; UDP scanning is not implemented.
- OS detection is heuristic and may be inaccurate.
- Service names are based on conventional port assignments and may not identify the actual service.
- Banner collection is basic and may not work with every protocol.
- Host discovery may miss systems that block ICMP and the TCP fallback probes.
- Local network detection depends on the host's routing and interface configuration.
- Some platform-specific commands and output formats may not be available on every system.
- Scanning speed and accuracy depend on network conditions, firewall policies, timeouts, and concurrency.

## Future Improvements

Potential improvements for future versions include:

- More robust cross-platform network interface and subnet detection.
- CSV and HTML report exports.
- Improved service fingerprinting and protocol-aware banner collection.
- Better handling of scan progress, cancellation, and connection errors.
- Optional UDP scanning with appropriate response interpretation.
- Unit tests for IP parsing, port parsing, and result processing.
- Integration tests using a controlled local lab.
- A structured logging system with configurable verbosity.

## Responsible Use

This tool is intended for authorized network administration, cybersecurity education, and controlled security testing.

Only scan systems and networks that you own or have explicit permission to assess. Ensure that your scan scope complies with applicable laws, organizational policies, and engagement rules.

The author is not responsible for misuse of this tool.


## Author

**Your Name**

Cybersecurity | Network Security | Python

GitHub: `https://github.com/Femi49`

