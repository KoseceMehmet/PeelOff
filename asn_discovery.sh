#!/bin/bash

# Enhanced ASN Discovery Module
# Supports multiple sources with graceful degradation

set -euo pipefail

# Source configuration
source "$(dirname "$0")/config.sh"

# ASN Discovery Functions
discover_asn_asnmap() {
    local target="$1"
    local output_file="$2"
    
    log "INFO" "Discovering ASNs using asnmap for target: $target"
    
    # Try both organization name and domain name
    local found_asns=false
    
    # First try as organization name
    if [[ -n "${ORG_TARGET:-}" ]]; then
        log "INFO" "Trying asnmap with organization: $ORG_TARGET"
        local org_results=$(asnmap -i "$ORG_TARGET" -silent 2>/dev/null | awk '{print $1}' | grep -E '^AS[0-9]+$')
        if [[ -n "$org_results" ]]; then
            echo "$org_results" >> "$output_file"
            found_asns=true
            log "SUCCESS" "asnmap organization search completed"
        fi
    fi
    
    # Then try as domain name
    if [[ -n "${DOMAIN_TARGET:-}" ]]; then
        log "INFO" "Trying asnmap with domain: $DOMAIN_TARGET"
        local domain_results=$(asnmap -d "$DOMAIN_TARGET" -silent 2>/dev/null | awk '{print $1}' | grep -E '^AS[0-9]+$')
        if [[ -n "$domain_results" ]]; then
            echo "$domain_results" >> "$output_file"
            found_asns=true
            log "SUCCESS" "asnmap domain search completed"
        fi
    fi
    
    if [[ "$found_asns" == "true" ]]; then
        log "SUCCESS" "asnmap discovery completed"
    else
        log "WARN" "asnmap discovery failed"
    fi
}

discover_asn_bgpview() {
    local target="$1"
    local output_file="$2"
    
    log "INFO" "Discovering ASNs using BGPView API for target: $target"
    
    # Try multiple BGPView endpoints
    local urls=(
        "https://api.bgpview.io/search?query=$target"
        "https://api.bgpview.io/ipv4/$target"
        "https://api.bgpview.io/search/$target"
    )
    
    local found_asns=false
    for url in "${urls[@]}"; do
        local response=$(curl -s -A "Mozilla/5.0" --max-time 10 "$url" 2>/dev/null)
        if [[ -n "$response" ]]; then
            # Extract all AS numbers using grep -oE
            local asns=$(echo "$response" | grep -oE 'AS[0-9]+' | sort -u)
            if [[ -n "$asns" ]]; then
                echo "$asns" >> "$output_file"
                found_asns=true
                log "SUCCESS" "BGPView API discovery completed from: $url"
                break
            fi
        fi
    done
    
    if [[ "$found_asns" != "true" ]]; then
        log "WARN" "BGPView API discovery failed - all endpoints failed"
    fi
}

discover_asn_he_net() {
    local target="$1"
    local output_file="$2"
    
    log "INFO" "Discovering ASNs using HE.net scraping for target: $target"
    
    # Use ORG_TARGET for better organization search results
    local url="https://bgp.he.net/search?search%5Bsearch%5D=${ORG_TARGET:-$target}"
    local response=$(curl -s -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" --max-time 30 "$url" 2>/dev/null)
 
    if [[ -n "$response" ]]; then
        # Extract all AS numbers using grep -oE
        local asns=$(echo "$response" | grep -oE 'AS[0-9]+' | sort -u)
        if [[ -n "$asns" ]]; then
            echo "$asns" >> "$output_file"
            log "SUCCESS" "HE.net scraping completed"
        else
            log "WARN" "HE.net: No ASNs found in response"
        fi
    else
        log "WARN" "HE.net scraping failed - no response"
    fi
}

discover_asn_shodan() {
    local target="$1"
    local output_file="$2"
    
    log "INFO" "Discovering ASNs using Shodan API for target: $target"
    
    local url="https://api.shodan.io/shodan/host/search?key=$SHODAN_API_KEY&query=$target"
    if safe_api_call "$url" "SHODAN_API_KEY" 30 | jq -r '.matches[] | select(.asn) | .asn' 2>/dev/null | sort -u >> "$output_file"; then
        log "SUCCESS" "Shodan API discovery completed"
    else
        log "WARN" "Shodan API discovery failed - Shodan features skipped"
    fi
}

discover_asn_censys() {
    local target="$1"
    local output_file="$2"
    
    log "INFO" "Discovering ASNs using Censys API for target: $target"
    
    local url="https://search.censys.io/api/v2/hosts/search?q=$target&per_page=100"
    if safe_api_call "$url" "CENSYS_API_ID" 30 | \
       jq -r '.result.hits[] | select(.autonomous_system.asn) | "AS\(.autonomous_system.asn)"' >> "$output_file"; then
        log "SUCCESS" "Censys API discovery completed"
    else
        log "WARN" "Censys API discovery failed - Censys features skipped"
    fi
}

discover_asn_securitytrails() {
    local target="$1"
    local output_file="$2"
    
    log "INFO" "Discovering ASNs using SecurityTrails API for target: $target"
    
    local url="https://api.securitytrails.com/v1/domain/$target"
    if safe_api_call "$url" "SECURITYTRAILS_API_KEY" 30 | \
       jq -r '.ips[] | select(.asn) | "AS\(.asn)"' 2>/dev/null | sort -u >> "$output_file"; then
        log "SUCCESS" "SecurityTrails API discovery completed"
    else
        log "WARN" "SecurityTrails API discovery failed - SecurityTrails features skipped"
    fi
}

discover_asn_crt_sh() {
    local target="$1"
    local output_file="$2"
    
    log "INFO" "Discovering ASNs using crt.sh for target: $target"
    
    # Use DOMAIN_TARGET for certificate-based discovery
    local url="https://crt.sh/?q=%.${DOMAIN_TARGET:-$target}&output=json"
    local response=$(curl -s --max-time 30 "$url" 2>/dev/null)
    
    if [[ -n "$response" ]]; then
        # Extract domains and resolve to IPs, then get ASNs
        echo "$response" | jq -r '.[].common_name' 2>/dev/null | \
        sort -u | \
        while read -r domain; do
            if [[ "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                if command -v dnsx &> /dev/null; then
                    dnsx -l "$domain" -silent -a 2>/dev/null | \
                    awk '{print $2}' | \
                    while read -r ip; do
                        if [[ -n "$ip" ]]; then
                            local asn=$(whois "$ip" 2>/dev/null | grep origin | awk '{print $2}' | head -1)
                            if [[ -n "$asn" ]]; then
                                echo "$asn"
                            fi
                        fi
                    done || true
                else
                    # Fallback to dig
                    local ip=$(dig +short "$domain" 2>/dev/null | head -1)
                    if [[ -n "$ip" ]]; then
                        local asn=$(whois "$ip" 2>/dev/null | grep origin | awk '{print $2}' | head -1)
                        if [[ -n "$asn" ]]; then
                            echo "$asn"
                        fi
                    fi
                fi
            fi
        done >> "$output_file" 2>/dev/null || log "WARN" "crt.sh domain resolution failed"
        
        log "SUCCESS" "crt.sh discovery completed"
    else
        log "WARN" "crt.sh discovery failed"
    fi
}

# Main ASN Discovery Function
discover_asns() {
    local target="$1"
    local output_file="$2"
    local user_asn_file="${3:-}"
    
    log "INFO" "Starting comprehensive ASN discovery for target: $target"
    
    # Create temporary file for this discovery session
    local temp_file=$(mktemp)
    trap "rm -f $temp_file" EXIT
    
    # Free sources (always available)
    discover_asn_asnmap "$target" "$temp_file"
    discover_asn_bgpview "$target" "$temp_file"
    discover_asn_he_net "$target" "$temp_file"
    discover_asn_crt_sh "$target" "$temp_file"
    
    # Paid sources (if API keys available)
    if [[ " ${AVAILABLE_APIS[*]} " =~ " shodan " ]]; then
        discover_asn_shodan "$target" "$temp_file"
    else
        log "INFO" "Shodan API not available - skipping Shodan discovery"
    fi
    
    if [[ " ${AVAILABLE_APIS[*]} " =~ " censys " ]]; then
        discover_asn_censys "$target" "$temp_file"
    else
        log "INFO" "Censys API not available - skipping Censys discovery"
    fi
    
    if [[ " ${AVAILABLE_APIS[*]} " =~ " securitytrails " ]]; then
        discover_asn_securitytrails "$target" "$temp_file"
    else
        log "INFO" "SecurityTrails API not available - skipping SecurityTrails discovery"
    fi
    
    # Add user-provided ASNs if file exists
    if [[ -n "$user_asn_file" && -f "$user_asn_file" ]]; then
        log "INFO" "Adding user-provided ASNs from: $user_asn_file"
        cat "$user_asn_file" >> "$temp_file"
    fi
    
    # Clean and deduplicate results
    grep -iE '^AS[0-9]+' "$temp_file" 2>/dev/null | \
    sed 's/^as/AS/' | \
    sort -u > "$output_file"
    
    local count=$(wc -l < "$output_file" 2>/dev/null || echo "0")
    log "SUCCESS" "ASN discovery completed. Found $count unique ASNs"
    
    return 0
}

# Parallel ASN Discovery (for large targets)
discover_asns_parallel() {
    local target="$1"
    local output_file="$2"
    local user_asn_file="${3:-}"
    
    log "INFO" "Starting parallel ASN discovery for target: $target"
    
    local temp_file=$(mktemp)
    trap "rm -f $temp_file" EXIT
    
    # Export functions for parallel execution
    export -f discover_asn_asnmap discover_asn_bgpview discover_asn_he_net
    export -f discover_asn_shodan discover_asn_censys discover_asn_securitytrails
    export -f discover_asn_crt_sh log safe_api_call check_api_key
    
    # Run free sources in parallel
    {
        discover_asn_asnmap "$target" "$temp_file" &
        discover_asn_bgpview "$target" "$temp_file" &
        discover_asn_he_net "$target" "$temp_file" &
        discover_asn_crt_sh "$target" "$temp_file" &
        wait
    }
    
    # Run paid sources if available (in parallel too)
    if [[ " ${AVAILABLE_APIS[*]} " =~ " shodan " ]] || \
       [[ " ${AVAILABLE_APIS[*]} " =~ " censys " ]] || \
       [[ " ${AVAILABLE_APIS[*]} " =~ " securitytrails " ]]; then
        {
            if [[ " ${AVAILABLE_APIS[*]} " =~ " shodan " ]]; then
                discover_asn_shodan "$target" "$temp_file" &
            fi
            if [[ " ${AVAILABLE_APIS[*]} " =~ " censys " ]]; then
                discover_asn_censys "$target" "$temp_file" &
            fi
            if [[ " ${AVAILABLE_APIS[*]} " =~ " securitytrails " ]]; then
                discover_asn_securitytrails "$target" "$temp_file" &
            fi
            wait
        }
    fi
    
    # Add user ASNs
    if [[ -n "$user_asn_file" && -f "$user_asn_file" ]]; then
        cat "$user_asn_file" >> "$temp_file"
    fi
    
    # Clean and deduplicate
    grep -iE '^AS[0-9]+' "$temp_file" 2>/dev/null | \
    sed 's/^as/AS/' | \
    sort -u > "$output_file"
    
    local count=$(wc -l < "$output_file" 2>/dev/null || echo "0")
    log "SUCCESS" "Parallel ASN discovery completed. Found $count unique ASNs"
}

# If script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -lt 2 ]]; then
        echo "Usage: $0 <target> <output_file> [user_asn_file]"
        echo "Example: $0 tesla tesla_asns.txt"
        exit 1
    fi
    
    init_config
    discover_asns "$1" "$2" "${3:-}"
fi
