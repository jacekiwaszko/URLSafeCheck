#!/bin/bash

# Usage: ./domaincheck.sh <url>
# Requires: dig, curl, jq, whois
# Install dependencies if needed:
#   Debian/Ubuntu: sudo apt update && sudo apt install dnsutils curl jq whois
#   Windows (WSL Ubuntu): sudo apt update && sudo apt install dnsutils curl jq whois
#   Windows (Cygwin): apt-cyg install bind-utils curl jq whois
#   CentOS: sudo yum install bind-utils curl jq whois || sudo dnf install bind-utils curl jq whois
#   macOS (Homebrew): brew install dig curl jq whois

URL="${1:?Usage: $0 <url>}"
VT_API_KEY="REPLACE ME WITH YOUR VIRUSTOTAL API KEY"

# Extract domain from URL (e.g., wykop.pl from https://wykop.pl/...)
DOMAIN=$(echo "$URL" | awk -F/ '{sub(/^www\./, "", $3); print $3}' | awk -F. '{print $(NF-1)"."$NF}')

# ANSI color codes
BLUE='\033[34m'
RED='\033[31m'
RESET='\033[0m'

# Check for required dependencies
for cmd in dig curl jq whois; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: '$cmd' is not installed. Install it with:"
        echo "  Debian/Ubuntu: sudo apt update && sudo apt install dnsutils curl jq whois"
        echo "  Windows (WSL Ubuntu): sudo apt update && sudo apt install dnsutils curl jq whois"
        echo "  Windows (Cygwin): apt-cyg install bind-utils curl jq whois"
        echo "  CentOS: sudo yum install bind-utils curl jq whois || sudo dnf install bind-utils curl jq whois"
        echo "  macOS (Homebrew): brew install dig curl jq whois"
        exit 1
    fi
done

# 1. Get DNS A record IP
IP=$(dig +short A "$DOMAIN" | head -n1)
if [ -z "$IP" ]; then
    echo "Error: No A record found for $DOMAIN"
    exit 1
fi

# PTR record for IP
PTR=$(dig +short -x "$IP" | head -n1)

# 2. ASN, Provider, and Abuse Contact from IP (using ipinfo.io and whois)
IP_INFO=$(curl -s "https://ipinfo.io/$IP/json")
if [ -n "$IP_INFO" ]; then
    # Try to extract ASN from nested asn.asn or directly from asn
    ASN=$(echo "$IP_INFO" | jq -r '.asn.asn // .asn // "Unknown"')
    PROVIDER=$(echo "$IP_INFO" | jq -r '.org // "Unknown"')
    # Fallback: Extract ASN from org field if direct extraction fails
    if [ "$ASN" = "Unknown" ] && [ "$PROVIDER" != "Unknown" ]; then
        ASN=$(echo "$PROVIDER" | grep -oE 'AS[0-9]+' || echo "Unknown")
    fi
else
    ASN="Unknown"
    PROVIDER="Unknown"
fi

# Get abuse contact email from whois
ABUSE_EMAIL=$(whois "$IP" | grep -iE 'abuse|abuse-c|e-mail' | grep -iE 'abuse.*@' | head -n1 | awk '{print $NF}' | grep -E '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
if [ -z "$ABUSE_EMAIL" ]; then
    ABUSE_EMAIL="Unknown"
fi

# 3. Scamalytics check for IP
SCAMA_PAGE=$(curl -s "https://scamalytics.com/ip/$IP")
if [ -n "$SCAMA_PAGE" ]; then
    BLACKLISTS_YES=$(echo "$SCAMA_PAGE" | grep -A 20 "External Blacklists" | grep -o "Yes" | wc -l)
    PROXIES_YES=$(echo "$SCAMA_PAGE" | grep -A 20 "Proxies" | grep -o "Yes" | wc -l)
    BLACKLISTS_STATUS=$([ "$BLACKLISTS_YES" -gt 0 ] && echo "Yes (listed on external blacklists)" || echo "No")
    PROXIES_STATUS=$([ "$PROXIES_YES" -gt 0 ] && echo "Yes (identified as proxy)" || echo "No")
else
    BLACKLISTS_STATUS="Unknown (Scamalytics request failed)"
    PROXIES_STATUS="Unknown (Scamalytics request failed)"
fi

# 4. VirusTotal check for domain
VT_RESPONSE=$(curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/domains/$DOMAIN")
if [ -n "$VT_RESPONSE" ]; then
    MALICIOUS_DOMAIN=$(echo "$VT_RESPONSE" | jq -r '.data.attributes.last_analysis_stats.malicious // 0')
    TOTAL_DOMAIN=$(echo "$VT_RESPONSE" | jq -r '(.data.attributes.last_analysis_stats.malicious // 0) + (.data.attributes.last_analysis_stats.suspicious // 0) + (.data.attributes.last_analysis_stats.undetected // 0) + (.data.attributes.last_analysis_stats.harmless // 0) + (.data.attributes.last_analysis_stats.timeout // 0)')
    if [ -z "$TOTAL_DOMAIN" ] || [ "$TOTAL_DOMAIN" -eq 0 ]; then
        VT_DOMAIN_STATUS="Unknown (API response incomplete)"
    else
        VT_DOMAIN_STATUS=$([ "$MALICIOUS_DOMAIN" -gt 0 ] && echo "Malicious ($MALICIOUS_DOMAIN/$TOTAL_DOMAIN detections)" || echo "Clean (0/$TOTAL_DOMAIN detections)")
    fi
else
    VT_DOMAIN_STATUS="Unknown (VirusTotal API request failed)"
fi

# Output all results except VirusTotal URL
printf "\nDomain Analysis: %s\n" "$DOMAIN"
printf "===================\n\n"
printf "DNS A Record: %b%s%b\n" "$BLUE" "$IP" "$RESET"
printf "PTR Record: %b%s%b\n" "$BLUE" "${PTR:-None}" "$RESET"
printf "\n"
printf "ASN: %b%s%b\n" "$BLUE" "$ASN" "$RESET"
printf "Provider: %b%s%b\n" "$BLUE" "$PROVIDER" "$RESET"
printf "Abuse Contact: %b%s%b\n" "$BLUE" "$ABUSE_EMAIL" "$RESET"
printf "\n"
printf "Scamalytics (IP):\n"
if [ "$BLACKLISTS_YES" -gt 0 ]; then
    echo -e "- External Blacklists: ${RED}$BLACKLISTS_STATUS${RESET}"
else
    echo -e "- External Blacklists: ${BLUE}$BLACKLISTS_STATUS${RESET}"
fi
if [ "$PROXIES_YES" -gt 0 ]; then
    echo -e "- Proxies: ${RED}$PROXIES_STATUS${RESET}"
else
    echo -e "- Proxies: ${BLUE}$PROXIES_STATUS${RESET}"
fi
printf "\n"
if [ "$MALICIOUS_DOMAIN" -gt 0 ]; then
    echo -e "VirusTotal (Domain): ${RED}$VT_DOMAIN_STATUS${RESET}"
else
    echo -e "VirusTotal (Domain): ${BLUE}$VT_DOMAIN_STATUS${RESET}"
fi

# 5. VirusTotal check for URL
MALICIOUS_URL=0
VT_URL_STATUS="Unknown (URL scan not performed)"
# Submit URL for scanning
SUBMIT_RESPONSE=$(curl -s -X POST -H "x-apikey: $VT_API_KEY" -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "url=$URL" "https://www.virustotal.com/api/v3/urls")
SUBMIT_ID=$(echo "$SUBMIT_RESPONSE" | jq -r '.data.id // empty')
if [ -n "$SUBMIT_ID" ]; then
    printf "URL submitted to VirusTotal. ID: %s. Please wait" "$SUBMIT_ID"
    for ((i=0; i<20; i++)); do
        printf "."
        sleep 1
        if (( (i+1) % 3 == 0 )); then
            printf "\b\b\b   \b\b\b"
        fi
    done
    printf "\n"
    # Retrieve scan results
    SCAN_RESPONSE=$(curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/analyses/$SUBMIT_ID")
    if [ -n "$SCAN_RESPONSE" ]; then
        MALICIOUS_URL=$(echo "$SCAN_RESPONSE" | jq -r '.data.attributes.stats.malicious // 0')
        TOTAL_URL=$(echo "$SCAN_RESPONSE" | jq -r '(.data.attributes.stats.malicious // 0) + (.data.attributes.stats.suspicious // 0) + (.data.attributes.stats.undetected // 0) + (.data.attributes.stats.harmless // 0) + (.data.attributes.stats.timeout // 0)')
        if [ -z "$TOTAL_URL" ] || [ "$TOTAL_URL" -eq 0 ]; then
            printf "Scan incomplete, retrying after 15 seconds...\n"
            sleep 15
            SCAN_RESPONSE=$(curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/analyses/$SUBMIT_ID")
            if [ -n "$SCAN_RESPONSE" ]; then
                MALICIOUS_URL=$(echo "$SCAN_RESPONSE" | jq -r '.data.attributes.stats.malicious // 0')
                TOTAL_URL=$(echo "$SCAN_RESPONSE" | jq -r '(.data.attributes.stats.malicious // 0) + (.data.attributes.stats.suspicious // 0) + (.data.attributes.stats.undetected // 0) + (.data.attributes.stats.harmless // 0) + (.data.attributes.stats.timeout // 0)')
                if [ -z "$TOTAL_URL" ] || [ "$TOTAL_URL" -eq 0 ]; then
                    VT_URL_STATUS="Scan in progress or incomplete"
                else
                    VT_URL_STATUS=$([ "$MALICIOUS_URL" -gt 0 ] && echo "Malicious ($MALICIOUS_URL/$TOTAL_URL detections)" || echo "Clean (0/$TOTAL_URL detections)")
                fi
            else
                VT_URL_STATUS="Failed to retrieve scan results"
            fi
        else
            VT_URL_STATUS=$([ "$MALICIOUS_URL" -gt 0 ] && echo "Malicious ($MALICIOUS_URL/$TOTAL_URL detections)" || echo "Clean (0/$TOTAL_URL detections)")
        fi
    else
        VT_URL_STATUS="Failed to retrieve scan results"
    fi
else
    VT_URL_STATUS="Failed to submit URL for scanning"
fi

# Output VirusTotal URL result
if [ "$MALICIOUS_URL" -gt 0 ]; then
    echo -e "VirusTotal (URL $URL): ${RED}$VT_URL_STATUS${RESET}"
else
    echo -e "VirusTotal (URL $URL): ${BLUE}$VT_URL_STATUS${RESET}"
fi
printf "\n"