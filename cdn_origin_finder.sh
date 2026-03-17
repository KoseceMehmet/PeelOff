#!/bin/bash

# Advanced CDN Detection and Origin IP Discovery Module

set -euo pipefail

# Source configuration
source "$(dirname "$0")/config.sh"

# CDN Detection Functions
detect_cdn_services() {
    local target="$1"
    local output_file="$2"
    
    log "INFO" "Detecting CDN services for target: $target"
    
    # Check for common CDN headers and DNS records
    check_cloudflare "$target" "$output_file"
    check_akamai "$target" "$output_file"
    check_fastly "$target" "$output_file"
    check_cloudfront "$target" "$output_file"
    check_azure "$target" "$output_file"
    check_google_cloud "$target" "$output_file"
    check_alibaba "$target" "$output_file"
    check_other_cdns "$target" "$output_file"
}

check_cloudflare() {
    local target="$1"
    local output_file="$2"
    
    log "INFO" "Checking Cloudflare CDN"
    
    # DNS check for Cloudflare
    if command -v dig &> /dev/null; then
        local ns_records=$(dig +short NS "$target" 2>/dev/null || echo "")
        if echo "$ns_records" | grep -qi "cloudflare"; then
            echo "CLOUDFLARE: DNS records indicate Cloudflare usage" >> "$output_file"
        fi
    fi
    
    # HTTP header check
    if command -v curl &> /dev/null; then
        local headers=$(curl -s -I "https://$target" 2>/dev/null || echo "")
        if echo "$headers" | grep -qi "cloudflare"; then
            echo "CLOUDFLARE: HTTP headers indicate Cloudflare usage" >> "$output_file"
        fi
    fi
    
    # IP range check
    if command -v whois &> /dev/null; then
        local ip=$(dig +short "$target" 2>/dev/null | head -n1 || echo "")
        if [[ -n "$ip" ]]; then
            local whois_info=$(whois "$ip" 2>/dev/null || echo "")
            if echo "$whois_info" | grep -qi "cloudflare"; then
                echo "CLOUDFLARE: IP $ip belongs to Cloudflare range" >> "$output_file"
            fi
        fi
    fi
}

check_akamai() {
    local target="$1"
    local output_file="$2"
    
    log "INFO" "Checking Akamai CDN"
    
    if command -v curl &> /dev/null; then
        local headers=$(curl -s -I "https://$target" 2>/dev/null || echo "")
        if echo "$headers" | grep -qi "akamai"; then
            echo "AKAMAI: HTTP headers indicate Akamai usage" >> "$output_file"
        fi
    fi
    
    if command -v dig &> /dev/null; then
        local ip=$(dig +short "$target" 2>/dev/null | head -n1 || echo "")
        if [[ -n "$ip" ]]; then
            local whois_info=$(whois "$ip" 2>/dev/null || echo "")
            if echo "$whois_info" | grep -qi "akamai"; then
                echo "AKAMAI: IP $ip belongs to Akamai range" >> "$output_file"
            fi
        fi
    fi
}

check_fastly() {
    local target="$1"
    local output_file="$2"
    
    log "INFO" "Checking Fastly CDN"
    
    if command -v curl &> /dev/null; then
        local headers=$(curl -s -I "https://$target" 2>/dev/null || echo "")
        if echo "$headers" | grep -qi "fastly"; then
            echo "FASTLY: HTTP headers indicate Fastly usage" >> "$output_file"
        fi
    fi
    
    if command -v dig &> /dev/null; then
        local ip=$(dig +short "$target" 2>/dev/null | head -n1 || echo "")
        if [[ -n "$ip" ]]; then
            local whois_info=$(whois "$ip" 2>/dev/null || echo "")
            if echo "$whois_info" | grep -qi "fastly"; then
                echo "FASTLY: IP $ip belongs to Fastly range" >> "$output_file"
            fi
        fi
    fi
}

check_cloudfront() {
    local target="$1"
    local output_file="$2"
    
    log "INFO" "Checking AWS CloudFront CDN"
    
    if command -v curl &> /dev/null; then
        local headers=$(curl -s -I "https://$target" 2>/dev/null || echo "")
        if echo "$headers" | grep -qi "cloudfront"; then
            echo "CLOUDFRONT: HTTP headers indicate CloudFront usage" >> "$output_file"
        fi
    fi
    
    if command -v dig &> /dev/null; then
        local ip=$(dig +short "$target" 2>/dev/null | head -n1 || echo "")
        if [[ -n "$ip" ]]; then
            local whois_info=$(whois "$ip" 2>/dev/null || echo "")
            if echo "$whois_info" | grep -qi "amazon"; then
                echo "CLOUDFRONT: IP $ip belongs to AWS range" >> "$output_file"
            fi
        fi
    fi
}

check_azure() {
    local target="$1"
    local output_file="$2"
    
    log "INFO" "Checking Microsoft Azure CDN"
    
    if command -v curl &> /dev/null; then
        local headers=$(curl -s -I "https://$target" 2>/dev/null || echo "")
        if echo "$headers" | grep -qi "azure"; then
            echo "AZURE: HTTP headers indicate Azure usage" >> "$output_file"
        fi
    fi
    
    if command -v dig &> /dev/null; then
        local ip=$(dig +short "$target" 2>/dev/null | head -n1 || echo "")
        if [[ -n "$ip" ]]; then
            local whois_info=$(whois "$ip" 2>/dev/null || echo "")
            if echo "$whois_info" | grep -qi "microsoft"; then
                echo "AZURE: IP $ip belongs to Microsoft Azure range" >> "$output_file"
            fi
        fi
    fi
}

check_google_cloud() {
    local target="$1"
    local output_file="$2"
    
    log "INFO" "Checking Google Cloud CDN"
    
    if command -v curl &> /dev/null; then
        local headers=$(curl -s -I "https://$target" 2>/dev/null || echo "")
        if echo "$headers" | grep -qi "gws|google"; then
            echo "GOOGLE_CLOUD: HTTP headers indicate Google Cloud usage" >> "$output_file"
        fi
    fi
    
    if command -v dig &> /dev/null; then
        local ip=$(dig +short "$target" 2>/dev/null | head -n1 || echo "")
        if [[ -n "$ip" ]]; then
            local whois_info=$(whois "$ip" 2>/dev/null || echo "")
            if echo "$whois_info" | grep -qi "google"; then
                echo "GOOGLE_CLOUD: IP $ip belongs to Google Cloud range" >> "$output_file"
            fi
        fi
    fi
}

check_alibaba() {
    local target="$1"
    local output_file="$2"
    
    log "INFO" "Checking Alibaba Cloud CDN"
    
    if command -v curl &> /dev/null; then
        local headers=$(curl -s -I "https://$target" 2>/dev/null || echo "")
        if echo "$headers" | grep -qi "alibaba"; then
            echo "ALIBABA: HTTP headers indicate Alibaba Cloud usage" >> "$output_file"
        fi
    fi
}

check_other_cdns() {
    local target="$1"
    local output_file="$2"
    
    log "INFO" "Checking other CDN providers"
    
    if command -v curl &> /dev/null; then
        local headers=$(curl -s -I "https://$target" 2>/dev/null || echo "")
        
        if echo "$headers" | grep -qi "edgecast"; then
            echo "EDGECAST: HTTP headers indicate Edgecast usage" >> "$output_file"
        fi
        
        if echo "$headers" | grep -qi "limelight"; then
            echo "LIMELIGHT: HTTP headers indicate Limelight usage" >> "$output_file"
        fi
        
        if echo "$headers" | grep -qi "keycdn"; then
            echo "KEYCDN: HTTP headers indicate KeyCDN usage" >> "$output_file"
        fi
        
        if echo "$headers" | grep -qi "maxcdn"; then
            echo "MAXCDN: HTTP headers indicate MaxCDN usage" >> "$output_file"
        fi
    fi
}

# Origin IP Discovery Techniques
discover_origin_ips() {
    local target="$1"
    local asn_file="$2"
    local output_file="$3"
    
    log "INFO" "Discovering origin IPs for target: $target"
    
    # Method 1: DNS Record Enumeration
    discover_dns_records "$target" "$output_file"
    
    # Method 2: Certificate Transparency Logs
    discover_ct_logs "$target" "$output_file"
    
    # Method 3: Subdomain Enumeration
    discover_subdomains "$target" "$output_file"
    
    # Method 4: Historical DNS Records
    discover_historical_dns "$target" "$output_file"
    
    # Method 5: ASN-based Origin IP Finding
    discover_asn_origins "$target" "$asn_file" "$output_file"
    
    # Method 6: Social Media and Code Repositories
    discover_social_origins "$target" "$output_file"
}

discover_dns_records() {
    local target="$1"
    local output_file="$2"
    
    log "INFO" "Discovering origin IPs through DNS record enumeration"
    
    if command -v dig &> /dev/null; then
        # A records
        local a_records=$(dig +short A "$target" 2>/dev/null || echo "")
        for ip in $a_records; do
            if is_origin_ip "$ip"; then
                echo "DNS_A: $ip" >> "$output_file"
            fi
        done
        
        # AAAA records (if IPv6 enabled)
        if [[ "$IPV6_ENABLED" == "true" ]]; then
            local aaaa_records=$(dig +short AAAA "$target" 2>/dev/null || echo "")
            for ip in $aaaa_records; do
                if is_origin_ip "$ip"; then
                    echo "DNS_AAAA: $ip" >> "$output_file"
                fi
            done
        fi
        
        # MX records
        local mx_records=$(dig +short MX "$target" 2>/dev/null || echo "")
        echo "$mx_records" | awk '{print $2}' | while read -r mx_host; do
            local mx_ips=$(dig +short "$mx_host" 2>/dev/null || echo "")
            for ip in $mx_ips; do
                if is_origin_ip "$ip"; then
                    echo "DNS_MX: $ip ($mx_host)" >> "$output_file"
                fi
            done
        done
        
        # NS records
        local ns_records=$(dig +short NS "$target" 2>/dev/null || echo "")
        for ns in $ns_records; do
            local ns_ips=$(dig +short "$ns" 2>/dev/null || echo "")
            for ip in $ns_ips; do
                if is_origin_ip "$ip"; then
                    echo "DNS_NS: $ip ($ns)" >> "$output_file"
                fi
            done
        done
        
        # TXT records (might contain IP addresses)
        local txt_records=$(dig +short TXT "$target" 2>/dev/null || echo "")
        echo "$txt_records" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | \
        while read -r ip; do
            if is_origin_ip "$ip"; then
                echo "DNS_TXT: $ip" >> "$output_file"
            fi
        done
    fi
}

discover_ct_logs() {
    local target="$1"
    local output_file="$2"
    
    log "INFO" "Discovering origin IPs through Certificate Transparency logs"
    
    # Use crt.sh to find certificates
    if command -v curl &> /dev/null; then
        local ct_url="https://crt.sh/?q=%.$target&output=json"
        local ct_data=$(curl -s --max-time 30 "$ct_url" 2>/dev/null || echo "")
        
        if echo "$ct_data" | jq . >/dev/null 2>&1; then
            echo "$ct_data" | jq -r '.[].common_name' 2>/dev/null | \
            sort -u | \
            while read -r domain; do
                if [[ "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                    local ips=$(dig +short "$domain" 2>/dev/null || echo "")
                    for ip in $ips; do
                        if is_origin_ip "$ip"; then
                            echo "CT_LOG: $ip ($domain)" >> "$output_file"
                        fi
                    done
                fi
            done
        fi
    fi
}

discover_subdomains() {
    local target="$1"
    local output_file="$2"
    
    log "INFO" "Discovering origin IPs through subdomain enumeration"
    
    # Common subdomain list
    local subdomains=(
        "www" "mail" "ftp" "admin" "api" "blog" "shop" "store" "app" "dev"
        "test" "staging" "production" "vpn" "remote" "secure" "portal" "dashboard"
        "cdn" "static" "assets" "images" "media" "files" "download" "upload"
        "smtp" "pop" "imap" "exchange" "webmail" "autodiscover" "mx" "ns1" "ns2"
        "origin" "backend" "internal" "private" "corporate" "enterprise" "cloud"
    )
    
    if command -v dig &> /dev/null; then
        for subdomain in "${subdomains[@]}"; do
            local full_domain="${subdomain}.${target}"
            local ips=$(dig +short "$full_domain" 2>/dev/null || echo "")
            for ip in $ips; do
                if is_origin_ip "$ip"; then
                    echo "SUBDOMAIN: $ip ($full_domain)" >> "$output_file"
                fi
            done
        done
    fi
}

discover_historical_dns() {
    local target="$1"
    local output_file="$2"
    
    log "INFO" "Discovering origin IPs through historical DNS records"
    
    # SecurityTrails API if available
    if [[ " ${AVAILABLE_APIS[*]} " =~ " securitytrails " ]]; then
        local url="https://api.securitytrails.com/v1/history/$target/dns/a"
        if safe_api_call "$url" "SECURITYTRAILS_API_KEY" 30 | \
           jq -r '.records[].values[]' 2>/dev/null | \
           while read -r ip; do
               if is_origin_ip "$ip"; then
                   echo "HISTORICAL_DNS: $ip (SecurityTrails)" >> "$output_file"
               fi
           done; then
            log "SUCCESS" "Historical DNS discovery completed via SecurityTrails"
        fi
    fi
    
    # VirusTotal API if available (you would need to add VT_API_KEY to config)
    if [[ -n "${VIRUSTOTAL_API_KEY:-}" ]]; then
        local url="https://www.virustotal.com/vtapi/v2/domain/report?apikey=$VIRUSTOTAL_API_KEY&domain=$target"
        if safe_api_call "$url" "VIRUSTOTAL_API_KEY" 30 | \
           jq -r '.subdomains[]?' 2>/dev/null | \
           while read -r subdomain; do
               local ips=$(dig +short "$subdomain" 2>/dev/null || echo "")
               for ip in $ips; do
                   if is_origin_ip "$ip"; then
                       echo "HISTORICAL_VT: $ip ($subdomain)" >> "$output_file"
                   fi
               done
           done; then
            log "SUCCESS" "Historical DNS discovery completed via VirusTotal"
        fi
    fi
}

discover_asn_origins() {
    local target="$1"
    local asn_file="$2"
    local output_file="$3"
    
    log "INFO" "Discovering origin IPs through ASN analysis"
    
    if [[ ! -f "$asn_file" ]]; then
        log "WARN" "ASN file not found: $asn_file"
        return 1
    fi
    
    while read -r asn; do
        # Get IP blocks for this ASN
        local asn_num=$(echo "$asn" | sed 's/^AS//')
        
        # Query RIPE for announced prefixes
        local prefixes=$(curl -s "https://stat.ripe.net/data/announced-prefixes/data.json?resource=$asn" 2>/dev/null | \
                        jq -r '.data.prefixes[].prefix' 2>/dev/null || echo "")
        
        for prefix in $prefixes; do
            # Sample a few IPs from each prefix to check if they belong to target
            if command -v mapcidr &> /dev/null; then
                local sample_ips=$(mapcidr -cidr "$prefix" -silent | head -10)
                for ip in $sample_ips; do
                    if check_ip_belongs_to_target "$ip" "$target"; then
                        echo "ASN_ORIGIN: $ip ($asn)" >> "$output_file"
                    fi
                done
            fi
        done
    done < "$asn_file"
}

discover_social_origins() {
    local target="$1"
    local output_file="$2"
    
    log "INFO" "Discovering origin IPs through social media and code repositories"
    
    # GitHub search (if API key available)
    if [[ " ${AVAILABLE_APIS[*]} " =~ " github " ]]; then
        local url="https://api.github.com/search/code?q=$target+in:file+filename:env+filename:config"
        if safe_api_call "$url" "GITHUB_TOKEN" 30 | \
           jq -r '.items[].html_url' 2>/dev/null | \
           while read -r repo_url; do
               # Extract raw file content and look for IP addresses
               local raw_url=$(echo "$repo_url" | sed 's/github.com/raw.githubusercontent.com/' | sed 's/blob\///')
               local content=$(curl -s "$raw_url" 2>/dev/null || echo "")
               echo "$content" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | \
               while read -r ip; do
                   if is_origin_ip "$ip"; then
                       echo "GITHUB: $ip ($repo_url)" >> "$output_file"
                   fi
               done
           done; then
            log "SUCCESS" "GitHub origin discovery completed"
        else
            log "WARN" "GitHub origin discovery failed - GitHub features skipped"
        fi
    else
        log "INFO" "GitHub API not available - skipping GitHub origin discovery"
    fi
}

# Helper Functions
is_origin_ip() {
    local ip="$1"
    
    # Check if IP is in known CDN ranges
    if command -v cdncheck &> /dev/null; then
        if echo "$ip" | cdncheck -silent | grep -q "cdn"; then
            return 1
        fi
    else
        # Manual CDN check
        local whois_info=$(whois "$ip" 2>/dev/null || echo "")
        if echo "$whois_info" | grep -qi "cloudflare\|akamai\|fastly\|cloudfront\|azure\|google"; then
            return 1
        fi
    fi
    
    # Check if IP is private
    if echo "$ip" | grep -qE '^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])|^127\.|^169\.254\.'; then
        return 1
    fi
    
    return 0
}

check_ip_belongs_to_target() {
    local ip="$1"
    local target="$2"
    
    # Reverse DNS lookup
    if command -v dig &> /dev/null; then
        local ptr=$(dig -x "$ip" +short 2>/dev/null || echo "")
        if echo "$ptr" | grep -qi "$target"; then
            return 0
        fi
    fi
    
    # HTTP check
    if command -v curl &> /dev/null; then
        local response=$(curl -s -I "http://$ip" 2>/dev/null || echo "")
        if echo "$response" | grep -qi "$target"; then
            return 0
        fi
    fi
    
    return 1
}

# Generate CDN and Origin Report
generate_cdn_origin_report() {
    local target="$1"
    local output_dir="$2"
    
    log "INFO" "Generating CDN and Origin IP report"
    
    local report_file="${output_dir}/${target}_cdn_origin_report.txt"
    
    cat > "$report_file" << EOF
=============================================================
CDN and Origin IP Discovery Report for: $target
Generated: $(date)
=============================================================

CDN DETECTION:
--------------
$(cat "${output_dir}/cdn_detection.txt" 2>/dev/null || echo "No CDN services detected")

ORIGIN IP DISCOVERY:
--------------------
$(cat "${output_dir}/origin_ips.txt" 2>/dev/null || echo "No origin IPs found")

UNIQUE ORIGIN IPS:
------------------
$(cat "${output_dir}/origin_ips.txt" 2>/dev/null | awk -F': ' '{print $2}' | sort -u || echo "No origin IPs found")

ORIGIN IP ANALYSIS:
-------------------
$(cat "${output_dir}/origin_ips.txt" 2>/dev/null | awk -F': ' '{print $2}' | sort -u | \
  while read -r ip; do
      if [[ -n "$ip" ]]; then
          echo "IP: $ip"
          echo "  PTR: $(dig -x "$ip" +short 2>/dev/null || echo "N/A")"
          echo "  Whois: $(whois "$ip" 2>/dev/null | grep -i "orgname\|netname" | head -1 || echo "N/A")"
          echo ""
      fi
  done)

RECOMMENDATIONS:
----------------
$(cat "${output_dir}/cdn_detection.txt" 2>/dev/null | grep -qi "cloudflare" && echo "- Consider using CloudFlair tool for automated origin IP discovery" || echo "")
$(cat "${output_dir}/origin_ips.txt" 2>/dev/null | wc -l | grep -q "^0$" && echo "- No origin IPs found. Consider manual investigation or alternative methods" || echo "- Found $(cat "${output_dir}/origin_ips.txt" 2>/dev/null | wc -l) potential origin IPs")
- Validate discovered IPs before using in security assessments
- Consider legal and ethical implications of origin IP usage

=============================================================
Report completed: $(date)
=============================================================
EOF
    
    log "SUCCESS" "CDN and Origin report generated: $report_file"
}

# Main CDN and Origin Discovery Function
discover_cdn_and_origins() {
    local target="$1"
    local asn_file="$2"
    local output_dir="$3"
    
    log "INFO" "Starting CDN detection and origin IP discovery for target: $target"
    
    mkdir -p "$output_dir"
    
    # Detect CDN services
    detect_cdn_services "$target" "${output_dir}/cdn_detection.txt"
    
    # Discover origin IPs
    discover_origin_ips "$target" "$asn_file" "${output_dir}/origin_ips.txt"
    
    # Generate comprehensive report
    generate_cdn_origin_report "$target" "$output_dir"
    
    log "SUCCESS" "CDN and origin IP discovery completed"
}

# If script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -lt 3 ]]; then
        echo "Usage: $0 <target> <asn_file> <output_dir>"
        echo "Example: $0 tesla tesla_asns.txt tesla_results"
        exit 1
    fi
    
    init_config
    discover_cdn_and_origins "$1" "$2" "$3"
fi
