#!/usr/bin/env python3

import requests
import re
import argparse
import subprocess
import urllib3
import socket
from requests.exceptions import RequestException

# Disable warnings about unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Reverse DNS using `dig`
def reverse_dns_dig(ip):
    hostnames = set()
    try:
        result = subprocess.run(['dig', '+short', '-x', ip], capture_output=True, text=True)
        output = result.stdout.strip()
        if output and "connection timed out" not in output:
            for line in output.split('\n'):
                hostname = line.strip().rstrip('.').lower()
                if hostname:
                    hostnames.add(hostname)
    except Exception as e:
        print(f"Error performing dig for IP {ip}: {e}")
    return hostnames


# Reverse DNS using `socket` library
def reverse_dns_socket(ip):
    try:
        return {socket.gethostbyaddr(ip)[0].strip().lower()}
    except Exception as e:
        print(f"Error performing socket reverse DNS for IP {ip}: {e}")
        return set()


# Bing search
def search_bing(ip):
    hostnames = set()
    try:
        response = requests.get(f'https://www.bing.com/search?q=ip%3a{ip}', verify=False, timeout=3)
        links = re.findall(r'<a href="([^"]+)" h=', response.text)
        for link in links:
            domain_match = re.search(r'://(.*?)/', link)
            if domain_match:
                domain = domain_match.group(1)
                if not re.search(r'microsoft|bing|pointdecontact', domain, re.I):
                    hostnames.add(domain.strip().rstrip('.').lower())
    except Exception as e:
        print(f"Error querying bing.com for IP {ip}: {e}")
    return hostnames


# Nmap SSL-cert scan
def nmap_ssl_cert(ip):
    hostnames = set()
    try:
        result = subprocess.run(['nmap', '-p443', '-Pn', '--script', 'ssl-cert', ip], capture_output=True, text=True)
        output = result.stdout
        for line in output.split('\n'):
            if 'Subject:' in line:
                common_name_match = re.search(r'commonName=(.*?)(/|$)', line)
                if common_name_match:
                    hostnames.add(common_name_match.group(1).strip().rstrip('.').lower())
    except Exception as e:
        print(f"Error performing nmap ssl-cert for IP {ip}: {e}")
    return hostnames


# Certificate Transparency Logs via crt.sh
def crt_sh(ip):
    hostnames = set()
    try:
        url = f"https://crt.sh/?q={ip}&output=json"
        response = requests.get(url, verify=False, timeout=3)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                hostnames.add(entry['name_value'].lower())
    except Exception as e:
        print(f"Error querying crt.sh for IP {ip}: {e}")
    return hostnames


# Passive DNS using SecurityTrails
def security_trails(ip, api_key):
    hostnames = set()
    try:
        url = f"https://api.securitytrails.com/v1/ips/{ip}/domains"
        headers = {"APIKEY": api_key}
        response = requests.get(url, headers=headers, verify=False, timeout=3)
        if response.status_code == 200:
            data = response.json()
            for domain in data.get('domains', []):
                hostnames.add(domain.lower())
    except Exception as e:
        print(f"Error querying SecurityTrails for IP {ip}: {e}")
    return hostnames


# WHOIS lookup
def whois_lookup(ip):
    hostnames = set()
    try:
        import whois
        data = whois.whois(ip)
        if data.domain_name:
            if isinstance(data.domain_name, list):
                hostnames.update([d.lower() for d in data.domain_name])
            else:
                hostnames.add(data.domain_name.lower())
    except Exception as e:
        print(f"Error performing WHOIS lookup for IP {ip}: {e}")
    return hostnames


# Aggregate all methods
def get_hostnames(ip, api_key=None):
    hostnames = set()
    hostnames.update(reverse_dns_dig(ip))
    hostnames.update(reverse_dns_socket(ip))
    hostnames.update(search_bing(ip))
    hostnames.update(nmap_ssl_cert(ip))
    hostnames.update(crt_sh(ip))
    if api_key:
        hostnames.update(security_trails(ip, api_key))
    hostnames.update(whois_lookup(ip))
    return hostnames


def main():
    parser = argparse.ArgumentParser(description='Get hostnames associated with IPs')
    parser.add_argument('-l', '--list', help='Input file containing IP addresses', required=True)
    parser.add_argument('-o', '--output', help='Output file for hostnames', required=True)
    parser.add_argument('--api-key', help='API key for SecurityTrails (optional)', required=False)
    args = parser.parse_args()

    with open(args.list, 'r') as f, open(args.output, 'w') as outfile:
        ip_list = [line.strip() for line in f if line.strip()]

        for ip in ip_list:
            print(f'Processing IP: {ip}')
            hostnames = get_hostnames(ip, api_key=args.api_key)
            if hostnames:
                output = f'IP: {ip}\n' + '\n'.join(sorted(hostnames)) + '\n\n'
            else:
                output = f'IP: {ip}\nNo hostnames found.\n\n'

            # Print to console and save to file in real time
            print(output, end="")
            outfile.write(output)
            outfile.flush()


if __name__ == '__main__':
    main()
