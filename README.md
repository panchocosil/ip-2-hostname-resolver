# IP to Hostname Resolver

**IP to Hostname Resolver** is a Python-based tool for discovering hostnames associated with IP addresses. It employs various techniques such as reverse DNS lookups, search engine queries, SSL certificate analysis, and passive DNS services.

## Features
- Reverse DNS lookups using `dig` and Python's `socket` library.
- Search engine scraping for hostnames.
- SSL certificate inspection using `nmap`.
- Integration with **Certificate Transparency Logs** (`crt.sh`).
- Passive DNS queries using SecurityTrails API (optional).
- WHOIS lookups for domain information.

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
1. **Reverse DNS Lookups**:
   - Uses `dig` and Python's `socket` library.
2. **Search Engine Queries**:
   - Scrapes Bing search results for IP-related domains.
3. **SSL Certificate Analysis**:
   - Extracts domains from SSL certificates using `nmap`.
4. **Certificate Transparency Logs**:
   - Queries `crt.sh` for SSL-related domains.
5. **Passive DNS Lookups** (Optional):
   - Uses the SecurityTrails API for historical DNS records.
6. **WHOIS Lookups**:
   - Fetches domain information from WHOIS records.

## Requirements
Ensure the following tools are installed and accessible:
- `nmap`
- `dig`

## Limitations
- HTTPS verification is disabled for simplicity. Enable it for production use.
- Rate-limiting may apply for APIs or web scraping.
- Some techniques rely on external services, which might return incomplete or outdated data.

## Contributing
Contributions are welcome! If you have ideas for additional hostname discovery techniques or improvements, feel free to open an issue or submit a pull request.
