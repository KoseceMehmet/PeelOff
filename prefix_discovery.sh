#!/bin/bash

# Enhanced Prefix Discovery Module
# Supports multiple sources with parallel processing

set -euo pipefail

# Source configuration
source "$(dirname "$0")/config.sh"

# Prefix Discovery Functions
discover_prefixes_ripe_stat() {
    local asn="$1"
    local output_file="$2"
    
    log "INFO" "Discovering prefixes from RIPE Stat for $asn"
    
    local url="https://stat.ripe.net/data/announced-prefixes/data.json?resource=$asn"
    if safe_api_call "$url" "NO_KEY_REQUIRED" 30 | \
       jq -r '.data.prefixes[].prefix' 2>/dev/null >> "$output_file"; then
        log "SUCCESS" "RIPE Stat discovery completed for $asn"
    else
        log "WARN" "RIPE Stat discovery failed for $asn"
    fi
}

discover_prefixes_bgpview() {
    local asn="$1"
    local output_file="$2"
    
    log "INFO" "Discovering prefixes from BGPView for $asn"
    
    local asn_num=$(echo "$asn" | sed 's/^AS//')
    local url="https://api.bgpview.io/asn/$asn_num/prefixes"
    if safe_api_call "$url" "NO_KEY_REQUIRED" 30 | \
       jq -r '.data.ipv4_prefixes[].prefix' 2>/dev/null >> "$output_file"; then
        log "SUCCESS" "BGPView discovery completed for $asn"
    else
        log "WARN" "BGPView discovery failed for $asn"
    fi
}

discover_prefixes_bgpview_ipv6() {
    local asn="$1"
    local output_file="$2"
    
    if [[ "$IPV6_ENABLED" != "true" ]]; then
        return 0
    fi
    
    log "INFO" "Discovering IPv6 prefixes from BGPView for $asn"
    
    local asn_num=$(echo "$asn" | sed 's/^AS//')
    local url="https://api.bgpview.io/asn/$asn_num/prefixes"
    if safe_api_call "$url" "NO_KEY_REQUIRED" 30 | \
       jq -r '.data.ipv6_prefixes[].prefix' 2>/dev/null >> "$output_file"; then
        log "SUCCESS" "BGPView IPv6 discovery completed for $asn"
    else
        log "WARN" "BGPView IPv6 discovery failed for $asn"
    fi
}

discover_prefixes_radb() {
    local asn="$1"
    local output_file="$2"
    
    log "INFO" "Discovering prefixes from RADB for $asn"
    
    # Try multiple RADB query methods
    local methods=(
        "-i origin $asn"
        "-i mnt-by MAINT-$asn"
        "-i mnt-by MAINT-$(echo $asn | sed 's/^AS//')"
    )
    
    for method in "${methods[@]}"; do
        if whois -h whois.radb.net -- "$method" 2>/dev/null | \
           grep -E 'route|route6' | \
           awk '{print $2}' >> "$output_file"; then
            log "SUCCESS" "RADB discovery completed for $asn (method: $method)"
            return 0
        fi
    done
    
    log "WARN" "RADB discovery failed for $asn (all methods)"
}

discover_prefixes_arin() {
    local asn="$1"
    local output_file="$2"
    
    log "INFO" "Discovering prefixes from ARIN for $asn"
    
    # Get OrgID first
    local org_id=$(whois "$asn" 2>/dev/null | grep -i "OrgId" | awk '{print $2}' | head -n 1)
    
    if [[ -n "$org_id" ]]; then
        if whois -h whois.arin.net "n + $org_id" 2>/dev/null | \
           grep CIDR | awk '{print $2}' >> "$output_file"; then
            log "SUCCESS" "ARIN discovery completed for $asn (OrgID: $org_id)"
        else
            log "WARN" "ARIN discovery failed for $asn"
        fi
    else
        log "WARN" "No OrgID found for $asn"
    fi
}

discover_prefixes_ripe() {
    local asn="$1"
    local output_file="$2"
    
    log "INFO" "Discovering prefixes from RIPE for $asn"
    
    if whois -h whois.ripe.net "$asn" 2>/dev/null | \
       grep -E 'route|route6' | \
       awk '{print $2}' >> "$output_file"; then
        log "SUCCESS" "RIPE discovery completed for $asn"
    else
        log "WARN" "RIPE discovery failed for $asn"
    fi
}

discover_prefixes_apnic() {
    local asn="$1"
    local output_file="$2"
    
    log "INFO" "Discovering prefixes from APNIC for $asn"
    
    if whois -h whois.apnic.net "$asn" 2>/dev/null | \
       grep -E 'route|route6' | \
       awk '{print $2}' >> "$output_file"; then
        log "SUCCESS" "APNIC discovery completed for $asn"
    else
        log "WARN" "APNIC discovery failed for $asn"
    fi
}

discover_prefixes_lacnic() {
    local asn="$1"
    local output_file="$2"
    
    log "INFO" "Discovering prefixes from LACNIC for $asn"
    
    if whois -h whois.lacnic.net "$asn" 2>/dev/null | \
       grep -E 'route|route6' | \
       awk '{print $2}' >> "$output_file"; then
        log "SUCCESS" "LACNIC discovery completed for $asn"
    else
        log "WARN" "LACNIC discovery failed for $asn"
    fi
}

discover_prefixes_afrinic() {
    local asn="$1"
    local output_file="$2"
    
    log "INFO" "Discovering prefixes from AFRINIC for $asn"
    
    if whois -h whois.afrinic.net "$asn" 2>/dev/null | \
       grep -E 'route|route6' | \
       awk '{print $2}' >> "$output_file"; then
        log "SUCCESS" "AFRINIC discovery completed for $asn"
    else
        log "WARN" "AFRINIC discovery failed for $asn"
    fi
}

discover_prefixes_shodan() {
    local asn="$1"
    local output_file="$2"
    
    log "INFO" "Discovering prefixes from Shodan for $asn"
    
    local url="https://api.shodan.io/shodan/host/search?key=$SHODAN_API_KEY&query=asn:$asn&facets=asn"
    if safe_api_call "$url" "SHODAN_API_KEY" 30 | \
       jq -r '.matches[] | .ip_str' 2>/dev/null | \
       while read -r ip; do
           # Convert single IP to /24 subnet for broader coverage
           if [[ "$ip" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
               echo "${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}.0/24"
           fi
       done | sort -u >> "$output_file"; then
        log "SUCCESS" "Shodan discovery completed for $asn"
    else
        log "WARN" "Shodan discovery failed for $asn - Shodan features skipped"
    fi
}

discover_prefixes_censys() {
    local asn="$1"
    local output_file="$2"
    
    log "INFO" "Discovering prefixes from Censys for $asn"
    
    local url="https://search.censys.io/api/v2/hosts/search?q=autonomous_system.asn:$asn&per_page=100"
    if safe_api_call "$url" "CENSYS_API_ID" 30 | \
       jq -r '.result.hits[] | .ip' 2>/dev/null | \
       while read -r ip; do
           # Convert to /24 subnet
           if [[ "$ip" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
               echo "${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}.0/24"
           fi
       done | sort -u >> "$output_file"; then
        log "SUCCESS" "Censys discovery completed for $asn"
    else
        log "WARN" "Censys discovery failed for $asn - Censys features skipped"
    fi
}

# Process single ASN for prefix discovery
process_asn_prefixes() {
    local asn="$1"
    local output_file="$2"
    
    log "INFO" "Processing prefixes for ASN: $asn"
    
    # Free sources (always available)
    discover_prefixes_ripe_stat "$asn" "$output_file"
    discover_prefixes_bgpview "$asn" "$output_file"
    discover_prefixes_radb "$asn" "$output_file"
    discover_prefixes_arin "$asn" "$output_file"
    discover_prefixes_ripe "$asn" "$output_file"
    discover_prefixes_apnic "$asn" "$output_file"
    discover_prefixes_lacnic "$asn" "$output_file"
    discover_prefixes_afrinic "$asn" "$output_file"
    
    # IPv6 if enabled
    discover_prefixes_bgpview_ipv6 "$asn" "$output_file"
    
    # Paid sources if available
    if [[ " ${AVAILABLE_APIS[*]} " =~ " shodan " ]]; then
        discover_prefixes_shodan "$asn" "$output_file"
    else
        log "INFO" "Shodan API not available - skipping Shodan prefix discovery for $asn"
    fi
    
    if [[ " ${AVAILABLE_APIS[*]} " =~ " censys " ]]; then
        discover_prefixes_censys "$asn" "$output_file"
    else
        log "INFO" "Censys API not available - skipping Censys prefix discovery for $asn"
    fi
}

# Main Prefix Discovery Function
discover_prefixes() {
    local asn_file="$1"
    local output_file="$2"
    local parallel="${3:-false}"
    
    log "INFO" "Starting comprehensive prefix discovery from $(wc -l < "$asn_file") ASNs"
    
    local temp_file=$(mktemp)
    trap "rm -f $temp_file" EXIT
    
    if [[ "$parallel" == "true" ]] && command -v parallel &> /dev/null; then
        log "INFO" "Using parallel processing for prefix discovery"
        
        # Export functions for parallel execution
        export -f discover_prefixes_ripe_stat discover_prefixes_bgpview
        export -f discover_prefixes_bgpview_ipv6 discover_prefixes_radb
        export -f discover_prefixes_arin discover_prefixes_ripe discover_prefixes_apnic
        export -f discover_prefixes_lacnic discover_prefixes_afrinic
        export -f discover_prefixes_shodan discover_prefixes_censys
        export -f process_asn_prefixes log safe_api_call check_api_key
        
        # Run ASNs in parallel with limited jobs
        cat "$asn_file" | parallel --no-notice --jobs "$CONCURRENT_REQUESTS" \
            "process_asn_prefixes {} $temp_file"
    else
        log "INFO" "Using sequential processing for prefix discovery"
        
        while read -r asn; do
            process_asn_prefixes "$asn" "$temp_file"
        done < "$asn_file"
    fi
    
    # Clean and validate prefixes
    grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$' "$temp_file" 2>/dev/null | \
    grep -vE '^0\.|^255\.|^127\.|^169\.254\.|^224\.|^240\.' | \
    sort -u > "$output_file"
    
    local count=$(wc -l < "$output_file" 2>/dev/null || echo "0")
    log "SUCCESS" "Prefix discovery completed. Found $count unique prefixes"
    
    return 0
}

# CDN and Cloud Filtering
filter_prefixes() {
    local input_file="$1"
    local output_file="$2"
    
    log "INFO" "Filtering CDN and cloud prefixes"
    
    if [[ "$CDN_FILTER" != "true" ]]; then
        log "INFO" "CDN filtering disabled, copying all prefixes"
        cp "$input_file" "$output_file"
        return 0
    fi
    
    # Use cdncheck if available, otherwise use manual filtering
    if command -v cdncheck &> /dev/null; then
        log "INFO" "Using manual CDN filtering (cdncheck format issue)"
        grep -vE 'Akamai|Cloudflare|Amazon|Google|Azure|Oracle|Fastly|Edgecast|Limelight|CloudFront|Alibaba|Tencent|IBM|DigitalOcean|Vultr|Linode|Rackspace|OVH|Hetzner|Contabo|Scaleway|UpCloud|Kamatera|Vultr|PhoenixNAP|Choopa|Leaseweb|i3D|Serverius|Hostinger|Namecheap|GoDaddy|Bluehost|HostGator|SiteGround|WP Engine|Kinsta|Fly.io|Render|Vercel|Netlify|GitHub Pages|GitLab Pages|Bitbucket|Heroku|Netlify|Cloudflare Pages|Firebase|Supabase|PlanetScale|MongoDB Atlas|Redis Labs|Elastic Cloud|AWS|GCP|Azure|DigitalOcean|Linode|Vultr|OVH|Hetzner|Contabo|Scaleway|UpCloud|Rackspace|IBM Cloud|Alibaba Cloud|Tencent Cloud|Oracle Cloud|Google Cloud|Microsoft Azure|Amazon AWS|Cloudflare|Akamai|Fastly|Edgecast|Limelight|Level 3|Cogent|Hurricane Electric|NTT|Telia|Telia|Tata|Reliance|Airtel|Vodafone|Orange|Deutsche Telekom|British Telecom|AT&T|Verizon|Comcast|Charter|Cox|Mediacom|Frontier|Windstream|CenturyLink|Spectrum|Xfinity' \
            "$input_file" > "$output_file"
    else
        log "INFO" "Using manual CDN filtering"
        grep -vE 'Akamai|Cloudflare|Amazon|Google|Azure|Oracle|Fastly|Edgecast|Limelight|CloudFront|Alibaba|Tencent|IBM|DigitalOcean|Vultr|Linode|Rackspace|OVH|Hetzner|Contabo|Scaleway|UpCloud|Kamatera|Vultr|PhoenixNAP|Choopa|Leaseweb|i3D|Serverius|Hostinger|Namecheap|GoDaddy|Bluehost|HostGator|SiteGround|WP Engine|Kinsta|Fly.io|Render|Vercel|Netlify|GitHub Pages|GitLab Pages|Bitbucket|Heroku|Netlify|Cloudflare Pages|Firebase|Supabase|PlanetScale|MongoDB Atlas|Redis Labs|Elastic Cloud|AWS|GCP|Azure|DigitalOcean|Linode|Vultr|OVH|Hetzner|Contabo|Scaleway|UpCloud|Rackspace|IBM Cloud|Alibaba Cloud|Tencent Cloud|Oracle Cloud|Google Cloud|Microsoft Azure|Amazon AWS|Cloudflare|Akamai|Fastly|Edgecast|Limelight|Level 3|Cogent|Hurricane Electric|NTT|Telia|Telia|Tata|Reliance|Airtel|Vodafone|Orange|Deutsche Telekom|British Telecom|AT&T|Verizon|Comcast|Charter|Cox|Mediacom|Frontier|Windstream|CenturyLink|Spectrum|Xfinity' \
            "$input_file" > "$output_file"
    fi
    
    local original_count=$(wc -l < "$input_file" 2>/dev/null || echo "0")
    local filtered_count=$(wc -l < "$output_file" 2>/dev/null || echo "0")
    local removed_count=$((original_count - filtered_count))
    
    log "SUCCESS" "CDN filtering completed. Removed $removed_count prefixes, $filtered_count remaining"
}

# If script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -lt 2 ]]; then
        echo "Usage: $0 <asn_file> <output_file> [--parallel]"
        echo "Example: $0 tesla_asns.txt tesla_prefixes.txt --parallel"
        exit 1
    fi
    
    init_config
    
    parallel_flag=false
    if [[ $# -ge 3 && "$3" == "--parallel" ]]; then
        parallel_flag=true
    fi
    
    discover_prefixes "$1" "$2" "$parallel_flag"
    
    # Merge overlapping prefixes to eliminate redundancy
    if command -v mapcidr &> /dev/null; then
        log "INFO" "Merging overlapping prefixes to eliminate redundancy"
        cat "$2" | mapcidr -aggregate -silent > "${2}_merged.txt"
        mv "${2}_merged.txt" "$2"
    fi
    
    filter_prefixes "$2" "${2}_filtered.txt"
fi
