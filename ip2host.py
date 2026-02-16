#!/usr/bin/env python3

import requests
import re
import argparse
import subprocess
import urllib3
import socket
from requests.exceptions import RequestException, Timeout
from concurrent.futures import ThreadPoolExecutor, as_completed

# Disable warnings about unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# SSL verification: False = desactivar comprobaciones (controlado por -ssl / --no-ssl)
VERIFY_SSL = False


# Resolvers DNS para PTR (distintos pueden devolver distintos PTR)
DNS_RESOLVERS = ['', '8.8.8.8', '1.1.1.1', '8.8.4.4']


# Reverse DNS using `dig` (con varios resolvers para más resultados)
def reverse_dns_dig(ip, timeout=10):
    hostnames = set()
    for resolver in DNS_RESOLVERS:
        try:
            cmd = ['dig', '+short', '-x', ip]
            if resolver:
                cmd.extend(['@' + resolver])
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            output = result.stdout.strip()
            if output and "connection timed out" not in output.lower():
                for line in output.split('\n'):
                    hostname = line.strip().rstrip('.').lower()
                    if hostname and not hostname.startswith(';'):
                        hostnames.add(hostname)
        except (subprocess.TimeoutExpired, Exception):
            continue
    return hostnames


# DNS over HTTPS (DoH) para PTR - útil cuando dig está bloqueado o no disponible
DOH_ENDPOINTS = [
    'https://dns.google/resolve',
    'https://cloudflare-dns.com/dns-query',
]


def reverse_dns_doh(ip, timeout=8):
    hostnames = set()
    # PTR: IP 1.2.3.4 -> 4.3.2.1.in-addr.arpa
    try:
        octets = ip.split('.')
        if len(octets) != 4:
            return hostnames
        ptr_name = '.'.join(reversed(octets)) + '.in-addr.arpa'
    except Exception:
        return hostnames
    for base in DOH_ENDPOINTS:
        try:
            params = {'name': ptr_name, 'type': 'PTR'}
            resp = requests.get(base, params=params, timeout=timeout, headers={'Accept': 'application/dns-json'}, verify=VERIFY_SSL)
            if resp.status_code != 200:
                continue
            data = resp.json()
            for ans in data.get('Answer', data.get('answers', [])):
                # Google: Answer[].data; Cloudflare: answers[].data
                raw = ans.get('data', '')
                if raw:
                    hostname = raw.strip().rstrip('.').lower()
                    if hostname and not hostname.startswith(';'):
                        hostnames.add(hostname)
        except (Timeout, RequestException, ValueError, KeyError):
            continue
    return hostnames


# Reverse DNS using `socket` library
def reverse_dns_socket(ip):
    try:
        return {socket.gethostbyaddr(ip)[0].strip().lower()}
    except Exception as e:
        print(f"Error performing socket reverse DNS for IP {ip}: {e}")
        return set()


# User-Agent tipo navegador para reducir bloqueos en búsquedas
SEARCH_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
}

# Dominios a ignorar al extraer de resultados de búsqueda
SEARCH_SKIP_DOMAINS = re.compile(
    r'google\.com|googleapis|gstatic|bing\.com|microsoft|pointdecontact|'
    r'youtube\.com|google\.|facebook\.com|twitter\.com|w3\.org',
    re.I
)


def _extract_hostnames_from_html(html):
    """Extrae hostnames de URLs en HTML (común para Bing/Google)."""
    hostnames = set()
    # URLs en href o en patrones tipo /url?q=https://...
    for url in re.findall(r'https?://[^"\'\\s>)\]]+', html):
        match = re.search(r'https?://([^/:]+)', url)
        if match:
            domain = match.group(1).split('.')  # quitar puertos implícitos
            domain = '.'.join(domain).strip().rstrip('.').lower()
            if domain and len(domain) > 3 and not SEARCH_SKIP_DOMAINS.search(domain):
                hostnames.add(domain)
    return hostnames


# Bing search
def search_bing(ip, timeout=10):
    hostnames = set()
    try:
        response = requests.get(
            f'https://www.bing.com/search?q=ip%3a{ip}',
            verify=VERIFY_SSL, timeout=timeout, headers=SEARCH_HEADERS
        )
        links = re.findall(r'<a href="([^"]+)" h=', response.text)
        for link in links:
            domain_match = re.search(r'://(.*?)/', link)
            if domain_match:
                domain = domain_match.group(1).strip().rstrip('.').lower()
                if not SEARCH_SKIP_DOMAINS.search(domain):
                    hostnames.add(domain)
        if not hostnames:
            hostnames.update(_extract_hostnames_from_html(response.text))
    except (Timeout, RequestException) as e:
        print(f"Error querying bing.com for IP {ip}: {e}")
    return hostnames


# Google search (puede bloquear o limitar; usar con moderación)
def search_google(ip, timeout=10):
    hostnames = set()
    try:
        url = f'https://www.google.com/search?q=ip%3A{ip}'
        response = requests.get(url, verify=VERIFY_SSL, timeout=timeout, headers=SEARCH_HEADERS)
        if response.status_code != 200:
            return hostnames
        # Enlaces en /url?q= o citas con URLs
        hostnames.update(_extract_hostnames_from_html(response.text))
        # Limpiar: solo parecidos a dominio (al menos algo.tld)
        hostnames = {h for h in hostnames if re.search(r'[a-z0-9][a-z0-9.-]*\.[a-z]{2,}', h)}
    except (Timeout, RequestException) as e:
        print(f"Error querying google.com for IP {ip}: {e}")
    return hostnames


# Nmap SSL-cert scan (más puertos = más cobertura, mayor tiempo)
SSL_PORTS = '443,8443,4433,8080,4443,9443'
NMAP_TIMEOUT = 120  # segundos; configurable con --nmap-timeout
def nmap_ssl_cert(ip, timeout=None):
    to = (timeout if timeout is not None else NMAP_TIMEOUT)
    hostnames = set()
    try:
        result = subprocess.run(
            ['nmap', f'-p{SSL_PORTS}', '-Pn', '--script', 'ssl-cert', ip],
            capture_output=True, text=True, timeout=to
        )
        output = result.stdout
        for line in output.split('\n'):
            if 'Subject:' in line:
                common_name_match = re.search(r'commonName=(.*?)(/|$)', line)
                if common_name_match:
                    hostnames.add(common_name_match.group(1).strip().rstrip('.').lower())
            if 'Subject Alternative Name:' in line:
                # Formato típico: DNS:host1.com, DNS:*.host2.com, IP Address:...
                for dns_match in re.finditer(r'DNS:([^,\s]+)', line):
                    part = dns_match.group(1).strip().rstrip('.').lower()
                    if part and not part.startswith('*'):
                        hostnames.add(part)
    except (subprocess.TimeoutExpired, Exception) as e:
        print(f"Error performing nmap ssl-cert for IP {ip}: {e}")
    return hostnames


# Certificate Transparency Logs via crt.sh
# name_value puede contener varios hostnames separados por newline (SAN)
def crt_sh(ip, timeout=10):
    hostnames = set()
    try:
        url = f"https://crt.sh/?q={ip}&output=json"
        response = requests.get(url, verify=VERIFY_SSL, timeout=timeout)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                raw = entry.get('name_value', '')
                for name in raw.replace(',', '\n').split():
                    name = name.strip().rstrip('.').lower()
                    if name and not name.startswith('*') and not re.match(r'^\d+\.\d+\.\d+\.\d+$', name):
                        hostnames.add(name)
    except (Timeout, RequestException) as e:
        print(f"Error querying crt.sh for IP {ip}: {e}")
    return hostnames


# Passive DNS using SecurityTrails
def security_trails(ip, api_key, timeout=10):
    hostnames = set()
    try:
        url = f"https://api.securitytrails.com/v1/ips/{ip}/domains"
        headers = {"APIKEY": api_key}
        response = requests.get(url, headers=headers, verify=VERIFY_SSL, timeout=timeout)
        if response.status_code == 200:
            data = response.json()
            for domain in data.get('domains', []):
                hostnames.add(domain.lower())
    except (Timeout, RequestException) as e:
        print(f"Error querying SecurityTrails for IP {ip}: {e}")
    return hostnames


# Patrón FQDN en cabecera Server (excluir nombres de software conocidos)
SERVER_SKIP = re.compile(
    r'^(nginx|apache|caddy|openresty|microsoft-iis|cloudflare|'
    r'gws|gse|esf|server|jetty|tomcat|wildfly|node|varnish|'
    r'[\d.]+)$',
    re.I
)


def _hostname_like(s):
    """True si s parece un hostname (ej. algo.dominio.tld), no solo software."""
    s = s.strip().rstrip('.').lower()
    if not s or len(s) < 4 or re.match(r'^\d+\.\d+\.\d+\.\d+$', s):
        return None
    if SERVER_SKIP.match(s):
        return None
    if re.match(r'^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$', s) and '.' in s:
        return s
    return None


# Sondeo HTTP/HTTPS: Location (redirect), cabecera Server cuando parece hostname
def http_probe(ip, timeout=8):
    hostnames = set()
    for scheme in ('https', 'http'):
        try:
            url = f'{scheme}://{ip}/'
            resp = requests.get(url, verify=VERIFY_SSL, timeout=timeout, allow_redirects=False)
            location = resp.headers.get('Location', '')
            if location:
                match = re.search(r'https?://([^/:]+)', location)
                if match:
                    hostnames.add(match.group(1).strip().rstrip('.').lower())
            server = resp.headers.get('Server', '')
            if server:
                # Server puede ser "nginx/1.2" o "host.example.com"; extraer posibles FQDN
                for part in re.split(r'[/\s,;()]', server):
                    part = part.strip()
                    if part:
                        h = _hostname_like(part)
                        if h:
                            hostnames.add(h)
        except (Timeout, RequestException):
            pass
    return hostnames


# WHOIS lookup (python-whois; si falla, fallback a whois por línea de comandos)
def whois_lookup(ip):
    hostnames = set()
    try:
        import whois as whois_mod
        query = getattr(whois_mod, 'whois', None)
        if query is None:
            raise AttributeError('whois.whois no existe: instala con pip install python-whois')
        data = query(ip)
        if data.domain_name:
            if isinstance(data.domain_name, list):
                hostnames.update([str(d).lower() for d in data.domain_name if d])
            else:
                hostnames.add(str(data.domain_name).lower())
    except AttributeError as e:
        hostnames.update(_whois_subprocess_fallback(ip))
        if not hostnames:
            print(f"WHOIS IP {ip}: {e}. Prueba: pip install python-whois")
    except Exception as e:
        hostnames.update(_whois_subprocess_fallback(ip))
        if not hostnames:
            print(f"Error performing WHOIS lookup for IP {ip}: {e}")
    return hostnames


def _whois_subprocess_fallback(ip, timeout=15):
    """Fallback: ejecutar whois por CLI y extraer NetName/descr si parecen hostname."""
    out = set()
    try:
        r = subprocess.run(['whois', ip], capture_output=True, text=True, timeout=timeout)
        text = (r.stdout or '') + (r.stderr or '')
        for line in text.splitlines():
            line = line.strip()
            for key in ('NetName:', 'netname:', 'descr:', 'OrgName:', 'org-name:'):
                if line.lower().startswith(key.lower()):
                    val = line.split(':', 1)[-1].strip()
                    if val and re.match(r'^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.(com|net|org|io|app|[a-z]{2,})$', val, re.I):
                        out.add(val.lower().rstrip('.'))
                    break
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        pass
    return out


# Aggregate all methods
def get_hostnames(ip, api_key=None):
    hostnames = set()
    hostnames.update(reverse_dns_dig(ip))
    hostnames.update(reverse_dns_doh(ip))
    hostnames.update(reverse_dns_socket(ip))
    hostnames.update(search_bing(ip))
    hostnames.update(search_google(ip))
    hostnames.update(nmap_ssl_cert(ip))
    hostnames.update(crt_sh(ip))
    hostnames.update(http_probe(ip))
    if api_key:
        hostnames.update(security_trails(ip, api_key))
    hostnames.update(whois_lookup(ip))
    return hostnames


def process_ip(ip, api_key):
    print(f'Processing IP: {ip}')
    hostnames = get_hostnames(ip, api_key)
    if hostnames:
        output = f'IP: {ip}\n' + '\n'.join(sorted(hostnames)) + '\n\n'
        print(output, end="")
        return output
    return None  # Skip IPs with no hostnames


def main():
    global VERIFY_SSL, NMAP_TIMEOUT
    parser = argparse.ArgumentParser(description='Get hostnames associated with IPs')
    parser.add_argument('-l', '--list', help='Input file containing IP addresses', required=True)
    parser.add_argument('-o', '--output', help='Output file for hostnames', required=True)
    parser.add_argument('-ssl', '--no-ssl', action='store_true', help='Disable SSL certificate verification')
    parser.add_argument('--api-key', help='API key for SecurityTrails (optional)', required=False)
    parser.add_argument('--threads', help='Number of threads for parallel execution', type=int, default=10)
    parser.add_argument('--nmap-timeout', type=int, default=120, metavar='SEC', help='Timeout en segundos para el escaneo nmap ssl-cert (default: 120)')
    args = parser.parse_args()

    if args.no_ssl:
        VERIFY_SSL = False  # desactivar verificación SSL en todas las peticiones
    NMAP_TIMEOUT = args.nmap_timeout

    with open(args.list, 'r') as f:
        ip_list = [line.strip() for line in f if line.strip()]

    with open(args.output, 'w') as outfile:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_ip = {executor.submit(process_ip, ip, args.api_key): ip for ip in ip_list}
            for future in as_completed(future_to_ip):
                result = future.result()
                if result:  # Only write non-empty results
                    outfile.write(result)
                    outfile.flush()


if __name__ == '__main__':
    main()
