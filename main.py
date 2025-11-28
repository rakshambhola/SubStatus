#!/usr/bin/env python3
a='''

░██████╗██╗░░░██╗██████╗░░██████╗████████╗░█████╗░████████╗██╗░░░██╗░██████╗
██╔════╝██║░░░██║██╔══██╗██╔════╝╚══██╔══╝██╔══██╗╚══██╔══╝██║░░░██║██╔════╝
╚█████╗░██║░░░██║██████╦╝╚█████╗░░░░██║░░░███████║░░░██║░░░██║░░░██║╚█████╗░
░╚═══██╗██║░░░██║██╔══██╗░╚═══██╗░░░██║░░░██╔══██║░░░██║░░░██║░░░██║░╚═══██╗
██████╔╝╚██████╔╝██████╦╝██████╔╝░░░██║░░░██║░░██║░░░██║░░░╚██████╔╝██████╔╝
╚═════╝░░╚═════╝░╚═════╝░╚═════╝░░░░╚═╝░░░╚═╝░░╚═╝░░░╚═╝░░░░╚═════╝░╚═════╝░
============================================================================
Author: Raksham Bhola (https://github.com/rakshambhola)
'''
'''
For educational/CTF/lab use only
Author: Raksham Bhola
'''

import subprocess
import requests
import urllib3
import argparse
import socket
import csv
import os
from typing import Optional, Dict, Any, List

TOOL_VERSION = "0.6.9"

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    def tqdm(iterable, **kwargs):
        return iterable

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class colors:
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    MAGENTA = "\033[95m"
    BLUE = "\033[94m"
    WHITE = "\033[97m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"


def get_subdomains(domain: str) -> List[str]:
    try:
        result = subprocess.run(
            ["subfinder", "-silent", "-d", domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode != 0:
            print("[ERROR] subfinder failed. Is it installed?")
            if result.stderr:
                print(result.stderr.strip())
            return []
        return sorted(set(result.stdout.splitlines()))
    except FileNotFoundError:
        print("[ERROR] subfinder not found in PATH.")
        return []
    except Exception as e:
        print(f"[ERROR] {e}")
        return []


def check_domain_http(domain: str) -> Dict[str, Any]:
    protocols = ["https", "http"]
    for protocol in protocols:
        url = f"{protocol}://{domain}"
        try:
            r = requests.head(url, timeout=3, allow_redirects=True, verify=False)
            return {"subdomain": domain, "status": "ONLINE", "code": r.status_code}
        except requests.exceptions.RequestException:
            continue
    return {"subdomain": domain, "status": "OFFLINE", "code": None}


def dns_lookup(domain: str) -> Dict[str, Optional[str]]:
    info = {"ip": None, "rdns": None}
    try:
        host, aliases, ips = socket.gethostbyname_ex(domain)
        if ips:
            info["ip"] = ips[0]
            try:
                ptr, _, _ = socket.gethostbyaddr(ips[0])
                info["rdns"] = ptr
            except Exception:
                info["rdns"] = None
    except Exception:
        pass
    return info


def cname_lookup(domain: str) -> Optional[str]:
    if not HAS_DNSPYTHON:
        return None
    try:
        answers = dns.resolver.resolve(domain, "CNAME")
        if answers:
            return str(answers[0].target).rstrip(".")
    except Exception:
        return None
    return None


def export_results_txt(filepath: str, results: List[Dict[str, Any]], cname: bool, dns: bool):
    with open(filepath, "w", encoding="utf-8") as f:
        for r in results:
            line = f"Subdomain: {r['subdomain']} | Status: {r['status']} | Code: {r['code'] if r['code'] else '-'}"
            if cname:
                line += f" | CNAME: {r.get('cname') or '-'}"
            if dns:
                line += f" | IP: {r.get('ip') or '-'} | rDNS: {r.get('rdns') or '-'}"
            f.write(line + "\n")


def export_results_csv(filepath: str, results: List[Dict[str, Any]], cname: bool, dns: bool):
    fieldnames = ["subdomain", "status", "code"]
    if cname:
        fieldnames.append("cname")
    if dns:
        fieldnames.extend(["ip", "rdns"])

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(r)


def print_results_table(results: List[Dict[str, Any]], cname: bool, dns: bool):
    headers = ["Subdomain", "Status", "Code"]
    if cname:
        headers.append("CNAME")
    if dns:
        headers.extend(["IP", "rDNS"])

    col_widths = {h: len(h) for h in headers}
    for r in results:
        col_widths["Subdomain"] = max(col_widths["Subdomain"], len(r["subdomain"]))
        col_widths["Status"] = max(col_widths["Status"], len(r["status"]))
        col_widths["Code"] = max(col_widths["Code"], len(str(r["code"])) if r["code"] else 1)
        if cname:
            col_widths["CNAME"] = max(col_widths.get("CNAME", 0), len(r.get("cname") or "-"))
        if dns:
            col_widths["IP"] = max(col_widths.get("IP", 0), len(r.get("ip") or "-"))
            col_widths["rDNS"] = max(col_widths.get("rDNS", 0), len(r.get("rdns") or "-"))

    fmt = "  ".join(f"{{{h}:{col_widths[h]}}}" for h in headers)
    print("\n" + fmt.format(**{h: h for h in headers}))
    print("-" * (sum(col_widths.values()) + 2 * (len(headers) - 1)))

    for r in results:
        row = {
            "Subdomain": r["subdomain"],
            "Status": r["status"],
            "Code": r["code"] if r["code"] else "-",
        }
        if cname:
            row["CNAME"] = r.get("cname") or "-"
        if dns:
            row["IP"] = r.get("ip") or "-"
            row["rDNS"] = r.get("rdns") or "-"
        print(fmt.format(**row))


def str_to_bool(s: str) -> bool:
    return s.lower() in ("true", "1", "yes", "y")


def parse_args():
    parser = argparse.ArgumentParser(
        prog="substatus",
        description="Subdomain HTTP status, DNS & CNAME scanner."
    )
    parser.add_argument("-u", required=True, help="Target domain (example.com)")
    parser.add_argument("-c", type=int, help="Filter by specific HTTP status code")
    parser.add_argument("-cname", type=str, default="False", help="CNAME lookup (True/False) | default False")
    parser.add_argument("-dns_lookup", type=str, default="False", help="DNS lookup (True/False) | default False")
    parser.add_argument("-exp", choices=["txt", "csv"], help="Export results (txt/csv)")
    parser.add_argument("-version", action="store_true", help="Show tool version")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.version:
        print(f"substatus version: {TOOL_VERSION}")
        return

    domain = args.u
    filter_code = args.c
    do_cname = str_to_bool(args.cname)
    do_dns = str_to_bool(args.dns_lookup)
    export_type = args.exp

    if do_cname and not HAS_DNSPYTHON:
        print(f"{colors.YELLOW}[WARN] CNAME lookup requires 'dnspython'. Install: pip install dnspython{colors.RESET}")

    if not HAS_TQDM:
        print(f"{colors.YELLOW}[WARN] tqdm not installed. Progress bar disabled. Install: pip install tqdm{colors.RESET}")

    print(f"ðŸ” Fetching subdomains for: {domain}")
    subdomains = get_subdomains(domain)
    if not subdomains:
        print("âŒ No subdomains found.")
        return

    print(f"âœ” Found {len(subdomains)} subdomains")
    print("ðŸŒ Checking their status...")

    results = []
    for sd in tqdm(subdomains, desc="Processing", unit="subdomain"):
        info = check_domain_http(sd)
        if do_cname:
            info["cname"] = cname_lookup(sd)
        if do_dns:
            info.update(dns_lookup(sd))
        results.append(info)

    results.sort(key=lambda r: (r["status"] != "ONLINE", r["code"] if r["code"] else 999))

    if filter_code is not None:
        results = [r for r in results if r["code"] == filter_code]
        print(f"\nðŸŽ¯ Filter: status code {filter_code} â†’ {len(results)} match(es)")

    if not results:
        print("No results to display.")
        return

    print_results_table(results, cname=do_cname, dns=do_dns)

    if not export_type:
        print("\nðŸ“Œ No export selected (-exp). Results shown on screen only.")
        return

    filename = f"substatus_{domain}.{export_type}"
    filepath = os.path.abspath(filename)

    if export_type == "txt":
        export_results_txt(filepath, results, cname=do_cname, dns=do_dns)
    else:
        export_results_csv(filepath, results, cname=do_cname, dns=do_dns)

    print(f"\nðŸ’¾ Results exported to: {filepath}")


if __name__ == "__main__":
    print(f'{colors.BOLD}{colors.CYAN}{a}{colors.RESET}')
    try:
        main()
    except Exception as e:
        print(f"{colors.RED}Error:{e}{colors.RESET}")
        
