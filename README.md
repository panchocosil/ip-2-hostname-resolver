# IP to Hostname Resolver

**IP to Hostname Resolver** is a Python-based tool for discovering hostnames associated with IP addresses. It employs various techniques such as reverse DNS lookups, search engine queries, SSL certificate analysis, and passive DNS services.

## Features
- Reverse DNS: `dig` (varios resolvers), **DNS over HTTPS (DoH)** (Google, Cloudflare) y `socket`.
- Búsqueda en **Bing** y **Google** (scraping; Google puede limitar o bloquear con muchas peticiones).
- SSL: inspección con `nmap` en varios puertos (443, 8443, 4433, 8080, 4443, 9443).
- **Certificate Transparency** (`crt.sh`).
- Sondeo HTTP/HTTPS: redirecciones (`Location`) y cabecera **Server** cuando parece hostname.
- Passive DNS: SecurityTrails API (opcional).
- WHOIS para información de dominio.

## Installation

### Prerequisites
- Python 3.x
- External tools:
  - `nmap` (for SSL certificate analysis).
  - `dig` (for reverse DNS lookups).

### Install Python dependencies:
```bash
pip install requests python-whois
```

## Usage
Run the script with the following arguments:
- `-l`, `--list`: Input file containing one IP address per line.
- `-o`, `--output`: Output file to store the discovered hostnames.
- `--api-key`: (Optional) API key for SecurityTrails to enable passive DNS queries.

### Example:
```bash
python3 ip2host.py -l input_ips.txt -o output_hostnames.txt --api-key YOUR_SECURITYTRAILS_API_KEY
```

### Input File:
Create a plain text file (e.g., `input_ips.txt`) with one IP address per line:
```
192.168.1.1
8.8.8.8
1.1.1.1
```

### Output File:
The results will be saved in the specified output file (e.g., `output_hostnames.txt`) in the following format:
```
IP: 192.168.1.1
hostname1.example.com
hostname2.example.net

IP: 8.8.8.8
google-public-dns-a.google.com
```

## Techniques
The tool uses the following methods to discover hostnames:
1. **Reverse DNS**: `dig` con varios resolvers (sistema, 8.8.8.8, 1.1.1.1, 8.8.4.4); **DoH** (Google, Cloudflare) para redes donde `dig` está bloqueado; `socket.gethostbyaddr`.
2. **Search engines**: Bing y Google (búsqueda `ip:X.X.X.X`). Se usa User-Agent tipo navegador; Google puede aplicar límites o bloqueos.
3. **SSL (nmap)**: Puertos 443, 8443, 4433, 8080, 4443, 9443; extrae CN y SAN de certificados.
4. **Certificate Transparency**: `crt.sh` por IP.
5. **HTTP/HTTPS probe**: Redirecciones (`Location`) y cabecera `Server` cuando el valor parece un hostname (FQDN).
6. **Passive DNS** (opcional): SecurityTrails API.
7. **WHOIS**: Dominio en registros WHOIS.

## Requirements
Ensure the following tools are installed and accessible:
- `nmap`
- `dig`

## Limitations
- HTTPS verification is disabled for simplicity. Enable it for production use.
- Rate-limiting o bloqueos: Google y Bing pueden limitar o bloquear muchas peticiones; usar con listas moderadas o menos hilos.
- Algunas técnicas dependen de servicios externos y pueden devolver datos incompletos o antiguos.

## Contributing
Contributions are welcome! If you have ideas for additional hostname discovery techniques or improvements, feel free to open an issue or submit a pull request.
