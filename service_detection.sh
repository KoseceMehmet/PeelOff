#!/bin/bash

# Enhanced Service Detection Module
# Comprehensive service discovery beyond HTTP

set -euo pipefail

# Source configuration
source "$(dirname "$0")/config.sh"

# IP Generation Functions
generate_ips_from_prefixes() {
    local prefix_file="$1"
    local output_file="$2"
    
    log "INFO" "Generating IP list from $(wc -l < "$prefix_file") prefixes"
    
    if command -v mapcidr &> /dev/null; then
        log "INFO" "Using mapcidr for IP generation"
        cat "$prefix_file" | mapcidr -silent > "$output_file"
    elif command -v prips &> /dev/null; then
        log "INFO" "Using prips for IP generation"
        while read -r prefix; do
            prips "$prefix" 2>/dev/null || true
        done < "$prefix_file" > "$output_file"
    else
        log "INFO" "Using nmap for IP generation (slower)"
        nmap -sL -n -iL "$prefix_file" 2>/dev/null | \
            awk '/Nmap scan report/{print $5}' > "$output_file"
    fi
    
    # Filter private IPs if disabled
    if [[ "$PRIVATE_SCAN" != "true" ]]; then
        log "INFO" "Filtering private IP ranges"
        grep -vE '^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])|^127\.|^169\.254\.' \
            "$output_file" > "${output_file}.tmp"
        mv "${output_file}.tmp" "$output_file"
    fi
    
    local count=$(wc -l < "$output_file" 2>/dev/null || echo "0")
    log "SUCCESS" "Generated $count IP addresses"
}

# Live Host Detection
detect_live_hosts() {
    local ip_file="$1"
    local output_file="$2"
    local method="${3:-fping}"
    
    log "INFO" "Detecting live hosts from $(wc -l < "$ip_file") IPs using $method"
    
    case "$method" in
        "fping")
            if command -v fping &> /dev/null; then
                log "INFO" "Using fping for fast host discovery"
                
                if [[ "$FAST_MODE_ENABLED" == "true" ]]; then
                    log "INFO" "FAST MODE enabled - using aggressive parameters"
                    if ! fping -a -q -i 20 -t 200 -r 1 < "$ip_file" 2>/dev/null > "$output_file"; then
                        log "WARN" "fping execution failed, falling back to nmap"
                        detect_live_hosts_nmap "$ip_file" "$output_file"
                    fi
                else
                    log "INFO" "THROTTLED MODE enabled - internet-safe scanning"
                    # Geçici dosya oluştur
                    touch "$output_file"
                    
                    # IP listesini 1000'er satırlık parçalara böl ve döngüye sok
                    split -l 1000 "$ip_file" ip_chunk_
                    
                    local chunk_count=$(ls ip_chunk_* | wc -l)
                    local current_chunk=0
                    
                    for chunk in ip_chunk_*; do
                        current_chunk=$((current_chunk + 1))
                        log "INFO" "Processing chunk $current_chunk/$chunk_count ($(wc -l < "$chunk") IPs)"
                        
                        # Nazik parametreler: -i 50 (50ms bekleme), -t 300
                        if fping -a -q -i 50 -t 300 -r 1 < "$chunk" >> "$output_file" 2>/dev/null; then
                            echo -n "."
                        fi
                        
                        rm "$chunk"
                        sleep 2 # Her 1000 IP'de bir modeme 2 saniye dinlenme süresi
                    done
                    echo "" # Alt satıra geç
                    
                    if [ ! -s "$output_file" ]; then
                        log "WARN" "fping failed to find live hosts, falling back to nmap"
                        detect_live_hosts_nmap "$ip_file" "$output_file"
                    fi
                fi
            else
                log "WARN" "fping not available, falling back to nmap"
                detect_live_hosts_nmap "$ip_file" "$output_file"
            fi
            ;;
        "masscan")
            if command -v masscan &> /dev/null; then
                log "INFO" "Using masscan for ultra-fast host discovery"
                masscan --rate 1000 --wait 0 -p80,443,22,21,25,53,110,143,993,995 \
                    -iL "$ip_file" --exclude 0.0.0.0/0 2>/dev/null | \
                    grep -E 'Discovered open port' | \
                    awk '{print $6}' | sort -u > "$output_file"
            else
                log "WARN" "masscan not available, falling back to fping"
                detect_live_hosts "$ip_file" "$output_file" "fping"
            fi
            ;;
        "nmap"|*)
            detect_live_hosts_nmap "$ip_file" "$output_file"
            ;;
    esac
    
    local count=$(wc -l < "$output_file" 2>/dev/null || echo "0")
    log "SUCCESS" "Found $count live hosts"
}

detect_live_hosts_nmap() {
    local ip_file="$1"
    local output_file="$2"
    
    log "INFO" "Using nmap for host discovery"
    nmap -sn -n --min-rate "$RATE_LIMIT" -iL "$ip_file" 2>/dev/null | \
        grep "Up" | awk '{print $2}' > "$output_file"
}

# Port Scanning
scan_ports() {
    local live_ips_file="$1"
    local output_file="$2"
    local ports="${3:-}"
    
    log "INFO" "Scanning ports on $(wc -l < "$live_ips_file") live hosts"
    
    if [[ -z "$ports" ]]; then
        ports="21,22,23,25,53,80,110,135,139,143,443,993,995,1433,1521,3306,3389,5432,5900,8080,8443"
    fi
    
    if command -v naabu &> /dev/null; then
        log "INFO" "Using naabu for port scanning"
        naabu -hL "$live_ips_file" -ports "$ports" -rate "$RATE_LIMIT" -silent -o "$output_file"
    elif command -v masscan &> /dev/null; then
        log "INFO" "Using masscan for port scanning"
        masscan -p "$ports" --rate "$RATE_LIMIT" -iL "$live_ips_file" -oL "$output_file" \
            --wait 0 2>/dev/null || true
        # Convert masscan output to standard format
        awk '{print $4":"$3}' "$output_file" | sort -u > "${output_file}.tmp"
        mv "${output_file}.tmp" "$output_file"
    else
        log "INFO" "Using nmap for port scanning"
        nmap -sS -n -p "$ports" --min-rate "$RATE_LIMIT" -iL "$live_ips_file" \
            -oG - 2>/dev/null | grep "Ports:" | \
            awk '{
                split($0, a, ":");
                ip = a[1];
                gsub(/^.*Host: /, "", ip);
                gsub(/ .*/, "", ip);
                
                for(i=1; i<=NF; i++) {
                    if($i ~ /^[0-9]+\/open/) {
                        port = substr($i, 1, index($i, "/")-1);
                        print ip":"port;
                    }
                }
            }' | sort -u > "$output_file"
    fi
    
    local count=$(wc -l < "$output_file" 2>/dev/null || echo "0")
    log "SUCCESS" "Found $count open ports"
}

# Service Detection and Fingerprinting
detect_services() {
    local open_ports_file="$1"
    local output_file="$2"
    
    log "INFO" "Detecting services on $(wc -l < "$open_ports_file") open ports"
    
    # Use httpx for web services
    if command -v httpx &> /dev/null; then
        log "INFO" "Using httpx for web service detection"
        httpx -l "$open_ports_file" -sc -title -td -server -cdn -probe -silent \
            -json -o "${output_file}_http.json" || true
        
        # Convert to readable format
        jq -r '. | "\(.url) [\(.status_code)] \(.title // "N/A") \(.server // "N/A")"' \
            "${output_file}_http.json" 2>/dev/null > "${output_file}_http.txt" || true
    fi
    
    # Use nmap for comprehensive service detection
    if command -v nmap &> /dev/null; then
        log "INFO" "Using nmap for detailed service detection"
        
        # Create a temporary file with targets only
        awk -F: '{print $1}' "$open_ports_file" | sort -u > "${open_ports_file}_targets"
        
        # Extract ports to scan
        awk -F: '{print $2}' "$open_ports_file" | sort -u | tr '\n' ',' | sed 's/,$//' > "${open_ports_file}_ports"
        local ports=$(cat "${open_ports_file}_ports")
        
        nmap -sV -sC -n -p "$ports" --min-rate "$RATE_LIMIT" -iL "${open_ports_file}_targets" \
            -oN "${output_file}_nmap.txt" -oX "${output_file}_nmap.xml" 2>/dev/null || true
        
        # Parse nmap results to standard format
        parse_nmap_results "${output_file}_nmap.txt" "$output_file"
        
        # Cleanup
        rm -f "${open_ports_file}_targets" "${open_ports_file}_ports"
    fi
}

parse_nmap_results() {
    local nmap_file="$1"
    local output_file="$2"
    
    log "INFO" "Parsing nmap service detection results"
    
    awk '
    /^Nmap scan report for/ {
        ip = $5
        gsub(/\([^)]*\)/, "", ip)
    }
    /^PORT/ { next }
    /^[0-9]+\/tcp/ {
        split($0, a, "/")
        port = a[1]
        state = a[2]
        service = a[4]
        if (state == "open") {
            print ip ":" port " | " service
            print ip ":" port " [" service "] " version
        }
    }
    ' "$nmap_file" > "$output_file"
}

# IP Organization Enrichment Function
enrich_ip_organizations() {
    local ip_file="$1"
    local output_file="$2"
    
    log "INFO" "Enriching $(wc -l < "$ip_file") IPs with organization information"
    
    > "$output_file"
    
    while read -r ip; do
        if [[ -n "$ip" ]]; then
            # Get organization info from ipinfo.io
            local org_info=$(curl -s -A "Mozilla/5.0" --max-time 5 "https://ipinfo.io/${ip}/org" 2>/dev/null | tr -d '\r\n')
            
            if [[ -n "$org_info" ]]; then
                echo "${ip} | ${org_info}" >> "$output_file"
            else
                echo "${ip} | Unknown" >> "$output_file"
            fi
            
            # Small delay to avoid rate limiting
            sleep 0.5
        fi
    done < "$ip_file"
    
    log "SUCCESS" "IP organization enrichment completed"
}

# Advanced Service Detection
detect_advanced_services() {
    local open_ports_file="$1"
    local output_dir="$2"
    
    log "INFO" "Running advanced service detection"
    mkdir -p "$output_dir"
    
    # SSH Key Fingerprinting
    detect_ssh_services "$open_ports_file" "${output_dir}/ssh_services.txt"
    
    # SSL/TLS Certificate Analysis
    detect_ssl_services "$open_ports_file" "${output_dir}/ssl_services.txt"
    
    # DNS Service Detection
    detect_dns_services "$open_ports_file" "${output_dir}/dns_services.txt"
    
    # SMB Service Detection
    detect_smb_services "$open_ports_file" "${output_dir}/smb_services.txt"
    
    # Database Service Detection
    detect_database_services "$open_ports_file" "${output_dir}/database_services.txt"
}

detect_ssh_services() {
    local open_ports_file="$1"
    local output_file="$2"
    
    log "INFO" "Detecting SSH services"
    
    grep ":22$" "$open_ports_file" | awk -F: '{print $1}' | \
    while read -r ip; do
        if timeout 5 ssh-keyscan "$ip" 2>/dev/null | grep -q "ssh-rsa"; then
            echo "$ip:22 - SSH Key Available"
        else
            echo "$ip:22 - SSH Service"
        fi
    done > "$output_file"
}

detect_ssl_services() {
    local open_ports_file="$1"
    local output_file="$2"
    
    log "INFO" "Detecting SSL/TLS services"
    
    grep -E ":(443|8443|993|995|636|465|587|990|992)$" "$open_ports_file" | \
    while IFS=: read -r ip port; do
        if timeout 10 openssl s_client -connect "$ip:$port" -showcerts </dev/null 2>/dev/null | \
           grep -q "BEGIN CERTIFICATE"; then
            cert_info=$(timeout 10 openssl s_client -connect "$ip:$port" -showcerts </dev/null 2>/dev/null | \
                       openssl x509 -noout -subject -issuer 2>/dev/null | tr '\n' ' | ' || echo "Unknown")
            echo "$ip:$port - SSL/TLS - $cert_info"
        fi
    done > "$output_file"
}

detect_dns_services() {
    local open_ports_file="$1"
    local output_file="$2"
    
    log "INFO" "Detecting DNS services"
    
    grep -E ":(53|5353)$" "$open_ports_file" | \
    while IFS=: read -r ip port; do
        if timeout 5 dig @"$ip" google.com +short 2>/dev/null | grep -q .; then
            echo "$ip:$port - DNS Service (Responsive)"
        else
            echo "$ip:$port - DNS Service (Non-responsive)"
        fi
    done > "$output_file"
}

detect_smb_services() {
    local open_ports_file="$1"
    local output_file="$2"
    
    log "INFO" "Detecting SMB services"
    
    grep -E ":(139|445)$" "$open_ports_file" | \
    while IFS=: read -r ip port; do
        if timeout 10 smbclient -L "$ip" -N 2>/dev/null | grep -q "Sharename"; then
            echo "$ip:$port - SMB Service (Share enumeration available)"
        else
            echo "$ip:$port - SMB Service"
        fi
    done > "$output_file"
}

detect_database_services() {
    local open_ports_file="$1"
    local output_file="$2"
    
    log "INFO" "Detecting database services"
    
    grep -E ":(1433|1521|3306|5432|6379|27017|11211|5000|1521)$" "$open_ports_file" | \
    while IFS=: read -r ip port; do
        case "$port" in
            1433) service="MSSQL" ;;
            1521) service="Oracle" ;;
            3306) service="MySQL" ;;
            5432) service="PostgreSQL" ;;
            6379) service="Redis" ;;
            27017) service="MongoDB" ;;
            11211) service="Memcached" ;;
            5000) service="DB2" ;;
            *) service="Unknown Database" ;;
        esac
        echo "$ip:$port - $service Service"
    done > "$output_file"
}

# Internet-wide Search Integration
internet_wide_search() {
    local target="$1"
    local output_file="$2"
    
    log "INFO" "Running internet-wide search for target: $target"
    
    if command -v uncover &> /dev/null; then
        log "INFO" "Using uncover for internet-wide search"
        uncover -q "$target" -silent >> "$output_file" || true
    fi
    
    # Shodan search if API key available
    if [[ " ${AVAILABLE_APIS[*]} " =~ " shodan " ]]; then
        log "INFO" "Using Shodan for internet-wide search"
        local url="https://api.shodan.io/shodan/host/search?key=$SHODAN_API_KEY&query=$target&limit=100"
        if safe_api_call "$url" "SHODAN_API_KEY" 30 | \
           jq -r '.matches[] | "\(.ip_str):\(.port) [\(.product // "Unknown")] \(.info // "")"' >> "$output_file"; then
            log "SUCCESS" "Shodan search completed"
        else
            log "WARN" "Shodan search failed - Shodan features skipped"
        fi
    else
        log "INFO" "Shodan API not available - skipping Shodan search"
    fi
    
    # Censys search if API key available
    if [[ " ${AVAILABLE_APIS[*]} " =~ " censys " ]]; then
        log "INFO" "Using Censys for internet-wide search"
        local url="https://search.censys.io/api/v2/hosts/search?q=$target&per_page=100"
        if safe_api_call "$url" "CENSYS_API_ID" 30 | \
           jq -r '.result.hits[] | "\(.ip):\(.services[]?.port // "80") [\(.services[]?.service_name // "http")]"' >> "$output_file"; then
            log "SUCCESS" "Censys search completed"
        else
            log "WARN" "Censys search failed - Censys features skipped"
        fi
    else
        log "INFO" "Censys API not available - skipping Censys search"
    fi
}

# Generate Comprehensive Report
generate_service_report() {
    local target="$1"
    local output_dir="$2"
    
    log "INFO" "Generating comprehensive service report"
    
    local report_file="${output_dir}/${target}_service_report.txt"
    
    cat > "$report_file" << EOF
=============================================================
Service Detection Report for: $target
Generated: $(date)
=============================================================

SUMMARY:
--------
Total IPs Generated: $(wc -l < "${output_dir}/all_ips.txt" 2>/dev/null || echo "0")
Live Hosts Found: $(wc -l < "${output_dir}/live_ips.txt" 2>/dev/null || echo "0")
Open Ports Found: $(wc -l < "${output_dir}/open_ports.txt" 2>/dev/null || echo "0")

WEB SERVICES:
-------------
$(cat "${output_dir}/http_services.txt" 2>/dev/null || echo "No web services found")

SSH SERVICES:
-------------
$(cat "${output_dir}/ssh_services.txt" 2>/dev/null || echo "No SSH services found")

SSL/TLS SERVICES:
-----------------
$(cat "${output_dir}/ssl_services.txt" 2>/dev/null || echo "No SSL/TLS services found")

DATABASE SERVICES:
------------------
$(cat "${output_dir}/database_services.txt" 2>/dev/null || echo "No database services found")

DNS SERVICES:
-------------
$(cat "${output_dir}/dns_services.txt" 2>/dev/null || echo "No DNS services found")

SMB SERVICES:
-------------
$(cat "${output_dir}/smb_services.txt" 2>/dev/null || echo "No SMB services found")

INTERNET-WIDE DISCOVERY:
------------------------
$(cat "${output_dir}/internet_wide.txt" 2>/dev/null || echo "No internet-wide results found")

DETAILED SERVICE INFORMATION:
-----------------------------
$(cat "${output_dir}/services_detailed.txt" 2>/dev/null || echo "No detailed service information")

=============================================================
Report completed: $(date)
=============================================================
EOF
    
    log "SUCCESS" "Service report generated: $report_file"
}

# Main Service Detection Function
detect_services_comprehensive() {
    local target="$1"
    local prefix_file="$2"
    local output_dir="$3"
    
    log "INFO" "Starting comprehensive service detection for target: $target"
    
    mkdir -p "$output_dir"
    
    # Generate IP list
    generate_ips_from_prefixes "$prefix_file" "${output_dir}/all_ips.txt"
    
    # Detect live hosts
    detect_live_hosts "${output_dir}/all_ips.txt" "${output_dir}/live_ips.txt"
    
    # Scan ports
    scan_ports "${output_dir}/live_ips.txt" "${output_dir}/open_ports.txt"
    
    # NEW: Stealth web service detection on ALL IPs (ping'e cevap vermeyenler için)
    if [[ -f "${output_dir}/all_ips.txt" && -s "${output_dir}/all_ips.txt" ]]; then
        log "INFO" "Scanning all IPs for stealth web services (rate-limited)..."
        
        # Tüm IP listesini sadece web portları için çok yavaş tara
        local stealth_rate=1000
        if [[ "$FAST_MODE_ENABLED" == "true" ]]; then
            stealth_rate=1500
        fi
        
        naabu -hL "${output_dir}/all_ips.txt" -ports 80,443,8080,8443 -rate "$stealth_rate" -timeout 500 -silent -o "${output_dir}/stealth_web_services.txt"
        
        # Stealth sonuçlarını ana sonuçlarla birleştir
        if [[ -f "${output_dir}/stealth_web_services.txt" && -s "${output_dir}/stealth_web_services.txt" ]]; then
            cat "${output_dir}/stealth_web_services.txt" >> "${output_dir}/open_ports.txt"
            sort -u "${output_dir}/open_ports.txt" > "${output_dir}/open_ports.tmp"
            mv "${output_dir}/open_ports.tmp" "${output_dir}/open_ports.txt"
            log "SUCCESS" "Stealth web services merged with live host results"
        fi
    fi
    
    # NEW: Organization enrichment for live IPs
    if [[ -f "${output_dir}/live_ips.txt" && -s "${output_dir}/live_ips.txt" ]]; then
        log "INFO" "Enriching live IPs with organization information..."
        enrich_ip_organizations "${output_dir}/live_ips.txt" "${output_dir}/live_ips_enriched.txt"
    fi
    
    # Detect services
    detect_services "${output_dir}/open_ports.txt" "${output_dir}/services_detailed.txt"
    
    # Advanced service detection
    detect_advanced_services "${output_dir}/open_ports.txt" "$output_dir"
    
    # Internet-wide search
    internet_wide_search "$target" "${output_dir}/internet_wide.txt"
    
    # Generate comprehensive report
    generate_service_report "$target" "$output_dir"
    
    log "SUCCESS" "Comprehensive service detection completed"
}

# If script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -lt 3 ]]; then
        echo "Usage: $0 <target> <prefix_file> <output_dir>"
        echo "Example: $0 tesla tesla_prefixes.txt tesla_results"
        exit 1
    fi
    
    init_config
    detect_services_comprehensive "$1" "$2" "$3"
fi
