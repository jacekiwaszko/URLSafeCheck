# URLSafeCheck

## Description
**URLSafeCheck** is a lightweight Bash script that analyzes the safety and network details of a given URL. It performs a two-level analysis:
- **Top-Level Domain (TLD)**: Extracts the TLD (e.g., `example.com` from `https://example.com/path`) and retrieves DNS A record, PTR record, ASN, provider, abuse contact email, and scam indicators via Scamalytics.
- **Full URL**: Scans the complete URL for malicious content using VirusTotal’s API.

The script provides a clean, color-coded output (blue for safe/unknown, red for malicious) to help assess a website’s trustworthiness. It’s ideal for security researchers, system administrators, or anyone curious about a URL’s safety.

## Features
- **Single URL Input**: Provide a URL (e.g., `https://example.com/path`), and the script extracts the TLD automatically.
- **Comprehensive Checks**:
  - DNS A and PTR records
  - ASN and provider via ipinfo.io
  - Abuse contact email via WHOIS
  - Scamalytics for IP blacklists and proxy detection
  - VirusTotal for domain and URL safety
- **Color-Coded Output**: Blue for safe/unknown, red for malicious or risky results.
- **Cross-Platform Support**: Works on Debian/Ubuntu, Windows (WSL/Cygwin), CentOS, and macOS (Homebrew).
- **VirusTotal API Integration**: Includes a 20-second wait with a dot animation for URL scans, with a 15-second retry for reliability.

## Dependencies
URLSafeCheck requires the following tools, each serving a specific purpose:
- **dig**: Resolves DNS A and PTR records to retrieve the IP address and reverse DNS information for the domain.
- **curl**: Makes HTTP requests to fetch data from ipinfo.io (for ASN/provider), Scamalytics (for blacklist/proxy checks), and VirusTotal (for domain/URL scans).
- **jq**: Parses JSON responses from ipinfo.io and VirusTotal APIs to extract relevant data.
- **whois**: Queries WHOIS databases to obtain abuse contact email addresses for the IP.

If any dependency is missing, the script will display platform-specific installation commands (see Installation).

## VirusTotal API Key
URLSafeCheck uses the VirusTotal API for domain and URL scans. To avoid rate limits with the default key, get your own API key:
1. Sign up or log in at [virustotal.com](https://www.virustotal.com/).
2. Navigate to your profile settings and find the API key section.
3. Copy your personal API key.
4. Open `urlsafecheck.sh` in a text editor.
5. Replace the placeholder `VT_API_KEY="d7076e80834b0078854372f3d13b3e49bbd427bfd3c672ce7c141dfeb61a5a1c"` (line 8) with your key, e.g.:
   ```bash
   VT_API_KEY="your-api-key-here"
   ```
6. Save the file.

Note: The free VirusTotal API has a 4/min request limit. A personal key ensures better reliability.

## Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/<your-username>/URLSafeCheck.git
   cd URLSafeCheck
   ```

2. **Install Dependencies**:
   Ensure `dig`, `curl`, `jq`, and `whois` are installed. If any are missing, the script will show commands for your platform:
   - **Debian/Ubuntu**:
     ```bash
     sudo apt update && sudo apt install dnsutils curl jq whois
     ```
   - **Windows (WSL Ubuntu)**:
     ```bash
     sudo apt update && sudo apt install dnsutils curl jq whois
     ```
   - **Windows (Cygwin)**:
     ```bash
     apt-cyg install bind-utils curl jq whois
     ```
     Note: Install `apt-cyg` in Cygwin first if needed.
   - **CentOS**:
     ```bash
     sudo yum install bind-utils curl jq whois || sudo dnf install bind-utils curl jq whois
     ```
   - **macOS (Homebrew)**:
     ```bash
     brew install dig curl jq whois
     ```
     Note: Install Homebrew first if not present (`/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`).

3. **Make the Script Executable**:
   ```bash
   chmod +x urlsafecheck.sh
   ```

## Usage
Run the script with a single URL as the argument:
```bash
./urlsafecheck.sh <url>
```

### Examples
- Check a specific URL:
  ```bash
  ./urlsafecheck.sh https://example.com/path
  ```
  Output (colors in terminal):
  ```
  URL submitted to VirusTotal. ID: u-1234...abcd. Please wait...[dots]

  Domain Analysis: example.com
  ===================

  DNS A Record: [93.184.216.34 in blue]
  PTR Record: [None in blue]

  ASN: [AS15133 in blue]
  Provider: [EdgeCast Networks, Inc. in blue]
  Abuse Contact: [abuse@edgecast.com in blue]

  Scamalytics (IP):
  - External Blacklists: [No in blue]
  - Proxies: [No in blue]

  VirusTotal (Domain): [Clean (0/95 detections) in blue]
  VirusTotal (URL https://example.com/path): [Clean (0/95 detections) in blue]
  ```

- If the VirusTotal URL scan is incomplete:
  ```
  URL submitted to VirusTotal. ID: u-1234...abcd. Please wait...[dots]
  Scan incomplete, retrying after 15 seconds...
  VirusTotal (URL https://example.com/path): [Scan in progress or incomplete in blue]
  ```

## Notes
- **VirusTotal API**: Replace the default API key with your own for better rate limits (see VirusTotal API Key section).
- **Scan Delays**: VirusTotal URL scans may take time. The script waits 20 seconds initially and retries after 15 seconds if incomplete. Check the submission ID on [virustotal.com](https://www.virustotal.com/) for full results.
- **Domain Extraction**: The script extracts the TLD (e.g., `example.com`). For complex TLDs (e.g., `co.uk`), it may need adjustment.
- **Colors**: Requires a Bash-compatible terminal for color output. Verify with:
  ```bash
  echo -e "\033[34mBlue text\033[0m"
  ```

## Troubleshooting
- **Missing Dependencies**:
  If a dependency is missing, the script shows installation commands for your platform. Ensure the package manager (e.g., `brew`, `apt-cyg`) is installed.
- **VirusTotal Scan Incomplete**:
  If the URL scan shows "Scan in progress or incomplete," increase the wait time (edit `sleep 20` to `sleep 30` in `urlsafecheck.sh`) or check the submission ID:
  ```bash
  curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/analyses/u-1234...abcd" | jq .
  ```
- **Rate Limit Issues**:
  If submission fails, verify API limits:
  ```bash
  curl -s -X POST -H "x-apikey: $VT_API_KEY" -H "Content-Type: application/x-www-form-urlencoded" \
      --data-urlencode "url=https://example.com/path" \
      "https://www.virustotal.com/api/v3/urls" | jq .
  ```
- **Other Issues**:
  Debug specific sections:
  ```bash
  whois 93.184.216.34 | grep -iE 'abuse|e-mail'  # Abuse Email
  curl -s "https://ipinfo.io/93.184.216.34/json" | jq .  # ASN/Provider
  curl -s "https://scamalytics.com/ip/93.184.216.34" | grep -A 20 "External Blacklists"  # Scamalytics
  ```

## Contributing
Contributions are welcome! Submit issues or pull requests for bug fixes, feature enhancements, or better TLD handling.

## License
[MIT License](LICENSE) - Free to use, modify, and distribute.