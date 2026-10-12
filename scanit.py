import argparse
import errno
import ipaddress
import json
import math
import platform
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

BANNER = r"""
                      _ _
  ___  ___ __ _ _ __ (_) |_
 / __|/ __/ _` | '_ \| | __|
 \__ \ (_| (_| | | | | | |_
 |___/\___\__,_|_| |_|_|\__|

 Network scanner: host discovery + TCP port scan.
 Use responsibly and only with permission to scan the target.
"""

DEFAULT_PORTS = "1-1024"
DEFAULT_THREADS = 100
DEFAULT_TIMEOUT = 1.0
DEFAULT_MAX_HOSTS = 1024

# Ports probed over TCP when a host does not answer ping (ICMP may be blocked).
DISCOVERY_PORTS = (80, 443, 22, 445, 3389)
HTTP_PORTS = {80, 8000, 8008, 8080, 8888}

# "Connection refused" still proves a host is alive (it sent a TCP RST).
ALIVE_ERRNOS = {0, errno.ECONNREFUSED, 10061}  # 10061 = WSAECONNREFUSED on Windows


def print_banner():
    print(BANNER)


# --------------------------------------------------------------------------- #
# Local network detection
# --------------------------------------------------------------------------- #
def run_command(command, timeout=5):
    """Run a command and return its stdout, or '' if it fails or is missing."""
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
        return result.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def mask_to_cidr(mask):
    """
    Convert a subnet mask ('255.255.255.0' or hex '0xffffff00') to a prefix
    length. Returns None if the mask is invalid or non-contiguous.
    """
    try:
        mask = str(mask).strip()
        if mask.lower().startswith("0x"):
            mask = str(ipaddress.IPv4Address(int(mask, 16)))
        mask_int = int(ipaddress.IPv4Address(mask))
    except (ValueError, ipaddress.AddressValueError):
        return None

    bits = bin(mask_int).count("1")
    expected = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
    return bits if mask_int == expected else None


def get_local_ip():
    """Return the primary local IPv4 address (no packets are actually sent)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def get_prefix_for_ip(ip):
    """Look up the prefix length of the interface that owns `ip` (None if unknown)."""
    if platform.system().lower() == "windows":
        output = run_command(["ipconfig"])
        pairs = re.findall(
            r"IPv4[^:\n]*:\s*([\d.]+)[^\n]*\n\s*Subnet Mask[^:\n]*:\s*([\d.]+)", output
        )
        for addr, mask in pairs:
            if addr == ip:
                return mask_to_cidr(mask)
        return None

    # Linux (iproute2): "inet 192.168.1.5/24 ..."
    output = run_command(["ip", "-o", "-4", "addr", "show"])
    for addr, prefix in re.findall(r"inet\s+([\d.]+)/(\d+)", output):
        if addr == ip:
            return int(prefix)

    # macOS / BSD / older Linux (net-tools): "inet 192.168.1.5 netmask 0xffffff00"
    output = run_command(["ifconfig"])
    for addr, mask in re.findall(r"inet\s+([\d.]+)\s+netmask\s+(\S+)", output):
        if addr == ip:
            return mask_to_cidr(mask)
    return None


def detect_local_network():
    """Return the local network in CIDR form (e.g. '192.168.1.0/24'), or None."""
    ip = get_local_ip()
    if ip is None:
        return None
    prefix = get_prefix_for_ip(ip)
    if prefix is None or not 0 < prefix <= 32:
        prefix = 24  # sensible default when the mask cannot be detected
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


# --------------------------------------------------------------------------- #
# Target and port parsing
# --------------------------------------------------------------------------- #
def parse_network(arg, max_hosts=DEFAULT_MAX_HOSTS):
    """
    Turn a CIDR, IP range, single IP or hostname into a list of IPv4 strings.
    Raises ValueError with a helpful message on bad input or oversized targets.
    """
    if not arg or not arg.strip():
        raise ValueError("no target given")
    arg = arg.strip()

    if "/" in arg:
        network = ipaddress.ip_network(arg, strict=False)
        if network.version != 4:
            raise ValueError("only IPv4 is supported")
        count = max(network.num_addresses - 2, 1)
        if count > max_hosts:
            raise ValueError(
                f"{arg} contains {count} hosts (limit {max_hosts}); "
                "use a smaller network or raise --max-hosts"
            )
        return [str(ip) for ip in network.hosts()]

    if "-" in arg:
        start_text, end_text = arg.split("-", 1)
        start = ipaddress.ip_address(start_text.strip())
        end_text = end_text.strip()
        # Allow shorthand such as 192.168.1.1-10
        if "." not in end_text and start.version == 4:
            end_text = ".".join(str(start).split(".")[:3] + [end_text])
        end = ipaddress.ip_address(end_text)
        if start.version != 4 or end.version != 4:
            raise ValueError("only IPv4 is supported")
        if int(start) > int(end):
            raise ValueError("range start is greater than range end")
        count = int(end) - int(start) + 1
        if count > max_hosts:
            raise ValueError(
                f"range contains {count} hosts (limit {max_hosts}); "
                "use a smaller range or raise --max-hosts"
            )
        return [str(ipaddress.ip_address(v)) for v in range(int(start), int(end) + 1)]

    try:
        ip = ipaddress.ip_address(arg)
        if ip.version != 4:
            raise ValueError("only IPv4 is supported")
        return [str(ip)]
    except ValueError as exc:
        if "only IPv4" in str(exc):
            raise
    # Not an IP address: try to resolve it as a hostname.
    try:
        return [socket.gethostbyname(arg)]
    except socket.gaierror:
        raise ValueError(f"'{arg}' is not a valid IP, range, network or hostname")

def get_ttl(ip, timeout=DEFAULT_TIMEOUT):
    """Ping once and return the reply TTL, or None if there was no real reply."""
    system = platform.system().lower()
    if system == "windows":
        command = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    elif system == "darwin":
        command = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), ip]
    else:
        command = ["ping", "-c", "1", "-W", str(max(1, math.ceil(timeout))), ip]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True,
            timeout=timeout + 2, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"ttl[=:]\s*(\d+)", result.stdout, re.IGNORECASE)
    return int(match.group(1)) if match else None


def ping_host(ip, timeout=DEFAULT_TIMEOUT):
    return get_ttl(ip, timeout) is not None

LINUX_HINTS = ("ubuntu", "debian", "centos", "red hat", "fedora", "linux", "openssh", "vsftpd")
WINDOWS_HINTS = ("microsoft", "windows", "iis", "win32", "win64")
WINDOWS_ONLY_PORTS = {135, 3389, 5985}  # not 139/445: Linux Samba uses those too


def guess_os(ttl, open_ports=()):
    """Best-effort OS guess from TTL, banners and open ports."""
    ports = {p["port"] for p in open_ports}
    banners = " ".join(p.get("banner", "") for p in open_ports).lower()

    # 1. Banners are the strongest evidence
    if any(h in banners for h in WINDOWS_HINTS):
        return "Windows"
    if any(h in banners for h in LINUX_HINTS):
        return "Linux / Unix"

    # 2. TTL
    if ttl is not None:
        if ttl <= 64:
            guess = "Linux / Unix / macOS / Android / iOS"
        elif ttl <= 128:
            guess = "Windows"
        else:
            guess = "Network device / Solaris / older Unix"
        if ports & WINDOWS_ONLY_PORTS and ttl > 64:
            guess = "Windows"
        return guess

    # 3. No ping reply (ICMP blocked): fall back to ports only
    if ports & WINDOWS_ONLY_PORTS:
        return "Probably Windows"
    if 22 in ports:
        return "Probably Linux / Unix"
    return "Unknown"

def parse_ports(spec):
    """Parse '80,443,1000-1010' into a sorted list of unique port numbers."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            low_text, high_text = part.split("-", 1)
            low, high = int(low_text), int(high_text)
            if low > high:
                raise ValueError(f"invalid port range '{part}'")
            ports.update(range(low, high + 1))
        else:
            ports.add(int(part))
    if not ports:
        raise ValueError("no ports specified")
    if min(ports) < 1 or max(ports) > 65535:
        raise ValueError("ports must be between 1 and 65535")
    return sorted(ports)


# --------------------------------------------------------------------------- #
# Host discovery
# --------------------------------------------------------------------------- #
def ping_host(ip, timeout=DEFAULT_TIMEOUT):
    """Return True only if `ip` sends a genuine ICMP echo reply."""
    system = platform.system().lower()
    if system == "windows":
        command = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    elif system == "darwin":
        command = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), ip]
    else:
        command = ["ping", "-c", "1", "-W", str(max(1, math.ceil(timeout))), ip]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True,
            timeout=timeout + 2, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    # A real reply contains "TTL=" (Windows) or "ttl=" (Linux/macOS).
    # "Destination host unreachable" replies do not, even when the exit code is 0.
    return "TTL=" in result.stdout.upper()


def tcp_probe(ip, timeout=DEFAULT_TIMEOUT):
    """Return True only if a common port actually accepts a connection."""
    for port in DISCOVERY_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((ip, port)) == 0:
                return True
        except OSError:
            pass
        finally:
            sock.close()
    return False

def is_host_up(ip, timeout=DEFAULT_TIMEOUT, tcp_fallback=True):
    if ping_host(ip, timeout):
        return True
    return tcp_probe(ip, timeout) if tcp_fallback else False


def discover_hosts(ip_list, threads, timeout, tcp_fallback=True):
    """Return the sorted list of hosts that respond."""
    up_hosts = []
    executor = ThreadPoolExecutor(max_workers=max(1, min(threads, len(ip_list))))
    try:
        futures = {
            executor.submit(is_host_up, ip, timeout, tcp_fallback): ip for ip in ip_list
        }
        for future in as_completed(futures):
            ip = futures[future]
            if future.result():
                print(f"  [+] {ip} is up")
                up_hosts.append(ip)
    except KeyboardInterrupt:
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    executor.shutdown(wait=True)
    return sorted(up_hosts, key=lambda x: int(ipaddress.ip_address(x)))


# --------------------------------------------------------------------------- #
# Port scanning
# --------------------------------------------------------------------------- #
def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def read_banner(sock, port):
    """Best-effort one-line service banner."""
    try:
        if port in HTTP_PORTS:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = sock.recv(256)
    except OSError:
        return ""
    text = data.decode("utf-8", errors="replace").strip()
    return text.splitlines()[0][:100] if text else ""


def scan_port(ip, port, timeout=DEFAULT_TIMEOUT, grab_banner=False):
    """Return a result dict if the port is open, otherwise None."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((ip, port)) != 0:
            return None
        banner = read_banner(sock, port) if grab_banner else ""
        return {"port": port, "service": service_name(port), "banner": banner}
    except OSError:
        return None
    finally:
        sock.close()


def scan_ports(ip, ports, threads, timeout, grab_banner=False):
    """Scan all `ports` on `ip` concurrently; return open ports sorted."""
    open_ports = []
    executor = ThreadPoolExecutor(max_workers=max(1, min(threads, len(ports))))
    try:
        futures = [
            executor.submit(scan_port, ip, port, timeout, grab_banner) for port in ports
        ]
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    except KeyboardInterrupt:
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    executor.shutdown(wait=True)
    return sorted(open_ports, key=lambda r: r["port"])


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser():
    parser = argparse.ArgumentParser(
        prog="scanit",
        description="Scan a network for reachable hosts and open TCP ports.",
        epilog="Only scan systems you own or have permission to test.",
    )
    parser.add_argument(
        "network",
        nargs="?",
        help="CIDR (192.168.1.0/24), range (192.168.1.1-10), IP or hostname. "
        "Omit to scan the local network.",
    )
    parser.add_argument(
        "-p", "--ports", default=DEFAULT_PORTS,
        help=f"ports to scan, e.g. 22,80,443 or 1-1024 (default: {DEFAULT_PORTS})",
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=DEFAULT_THREADS,
        help=f"number of worker threads (default: {DEFAULT_THREADS})",
    )
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT,
        help=f"per-connection timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "-Pn", "--no-ping", action="store_true",
        help="skip host discovery and treat every host as up",
    )
    parser.add_argument(
        "--no-tcp-fallback", action="store_true",
        help="host discovery uses ICMP ping only (no TCP probe fallback)",
    )
    parser.add_argument(
        "-O", "--os-detect", action="store_true",
        help="try to guess the operating system of each host",
    )
    parser.add_argument(
        "-b", "--banners", action="store_true", help="grab service banners on open ports"
    )
    parser.add_argument(
        "--max-hosts", type=int, default=DEFAULT_MAX_HOSTS,
        help=f"refuse targets larger than this (default: {DEFAULT_MAX_HOSTS})",
    )
    parser.add_argument("-o", "--output", help="save results to a JSON file")
    return parser
   


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.threads < 1 or args.timeout <= 0 or args.max_hosts < 1:
        print("Error: --threads, --timeout and --max-hosts must be positive.")
        return 2

    print_banner()

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"Error: invalid ports: {exc}")
        return 2

    target = args.network
    if target is None:
        target = detect_local_network()
        if target is None:
            print("Error: could not detect the local network; please specify a target.")
            return 2
        print(f"No target given; using local network {target}")

    try:
        ip_list = parse_network(target, args.max_hosts)
    except ValueError as exc:
        print(f"Error: {exc}")
        return 2

    started = time.time()
    results = {"target": target, "ports_scanned": len(ports), "hosts": []}

    try:
        if args.no_ping:
            online_hosts = ip_list
            print(f"Skipping discovery; scanning {len(online_hosts)} host(s).")
        else:
            print(f"Discovering hosts in {target} ({len(ip_list)} addresses)...")
            online_hosts = discover_hosts(
                ip_list, args.threads, args.timeout, not args.no_tcp_fallback
            )
            print(f"Online hosts: {len(online_hosts)}")

        for host in online_hosts:
            print(f"\nScanning {host} ({len(ports)} ports)...")
            open_ports = scan_ports(host, ports, args.threads, args.timeout, args.banners)
            host_result = {"ip": host, "open_ports": open_ports}
            if open_ports:
                for item in open_ports:
                    line = f"  {item['port']:>5}/tcp  open  {item['service']}"
                    if item["banner"]:
                        line += f"  | {item['banner']}"
                    print(line)
            else:
                print("  No open ports found.")
            if args.os_detect:
                ttl = get_ttl(host, args.timeout)
                os_guess = guess_os(ttl, open_ports)
                print(f"  OS guess: {os_guess} (TTL={ttl})")
                host_result.update({"ttl": ttl, "os_guess": os_guess})
            results["hosts"].append(host_result)

    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        return 130

    elapsed = time.time() - started
    total_open = sum(len(h["open_ports"]) for h in results["hosts"])
    results["elapsed_seconds"] = round(elapsed, 2)
    print(
        f"\nDone: {len(results['hosts'])} host(s) scanned, "
        f"{total_open} open port(s), {elapsed:.1f}s."
    )

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as handle:
                json.dump(results, handle, indent=2)
            print(f"Results saved to {args.output}")
        except OSError as exc:
            print(f"Error: could not write {args.output}: {exc}")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
if __name__ == "__main__":
    main()