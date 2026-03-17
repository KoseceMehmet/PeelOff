#!/bin/bash

# Advanced Origin IP Discovery Tool
# Comprehensive IP reconnaissance with modular architecture

set -euo pipefail

# Script Information
SCRIPT_VERSION="4.0"
SCRIPT_AUTHOR="Security Research Team"
SCRIPT_DESC="Advanced Origin IP Discovery and Service Enumeration Tool"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Source modules
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

# Banner
show_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
 _____ _ _ _   _    _    _   _  ____ _____ ____  
| ____| | | | | / \  | |  | \ | |/ ___| ____|  _ \ 
|  _| | | | |_| |/ _ \ | |  |  \| | |   |  _| | | | |
| |___|_|_ _  / ___ \| |  | |\  | |___| |___| |_| |
|_____|_|_|_|/_/   \_\_|  |_| \_|\____|_____|____/ 
                                                   
    Advanced Origin IP Discovery Tool v4.0
    Comprehensive IP Reconnaissance Framework
EOF
    echo -e "${NC}"
    echo -e "${BLUE}$SCRIPT_DESC${NC}"
    echo -e "${YELLOW}Author: $SCRIPT_AUTHOR${NC}"
    echo ""
}

# Usage information
usage() {
    echo -e "${CYAN}Usage:${NC}"
    echo "  $0 -t <target> [options]"
    echo ""
    echo -e "${CYAN}Required Parameters:${NC}"
    echo "  -t <target>        Target domain or organization name"
    echo ""
    echo -e "${CYAN}Optional Parameters:${NC}"
    echo "  -l <asn_file>      File containing additional ASNs"
    echo "  -o <output_dir>    Output directory (default: results_<target>)"
    echo "  -p                 Enable parallel processing"
    echo "  -v                 Verbose output"
    echo "  -q                 Quiet mode (minimal output)"
    echo "  --skip-cdn         Skip CDN detection"
    echo "  --skip-services    Skip service detection"
    echo "  --ipv6             Include IPv6 addresses"
    echo "  --private          Include private IP ranges"
    echo "  --rate <rate>      Custom rate limit (default: 1000)"
    echo "  --threads <num>    Number of threads (default: 50)"
    echo "  --modules <list>   Comma-separated modules to run"
    echo "                     Available: asn,prefix,services,cdn,all (default: all)"
    echo "  -h, --help         Show this help message"
    echo ""
    echo -e "${CYAN}Examples:${NC}"
    echo "  $0 -t tesla"
    echo "  $0 -t tesla -l custom_asns.txt -p"
    echo "  $0 -t tesla --modules asn,prefix --skip-services"
    echo "  $0 -t tesla --rate 2000 --threads 100"
    echo ""
    echo -e "${YELLOW}Note: This tool is for authorized security testing only.${NC}"
    exit 1
}

# Parse command line arguments
parse_arguments() {
    TARGET=""
    USER_ASN_FILE=""
    OUTPUT_DIR=""
    PARALLEL_MODE=false
    VERBOSE_MODE=false
    QUIET_MODE=false
    SKIP_CDN=false
    SKIP_SERVICES=false
    IPV6_ENABLED=false
    PRIVATE_SCAN=false
    CUSTOM_RATE=""
    CUSTOM_THREADS=""
    MODULES="all"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t)
                TARGET="$2"
                shift 2
                ;;
            -l)
                USER_ASN_FILE="$2"
                shift 2
                ;;
            -o)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -p)
                PARALLEL_MODE=true
                shift
                ;;
            -v)
                VERBOSE_MODE=true
                shift
                ;;
            -q)
                QUIET_MODE=true
                shift
                ;;
            --skip-cdn)
                SKIP_CDN=true
                shift
                ;;
            --skip-services)
                SKIP_SERVICES=true
                shift
                ;;
            --ipv6)
                IPV6_ENABLED=true
                shift
                ;;
            --private)
                PRIVATE_SCAN=true
                shift
                ;;
            --rate)
                CUSTOM_RATE="$2"
                shift 2
                ;;
            --threads)
                CUSTOM_THREADS="$2"
                shift 2
                ;;
            --modules)
                MODULES="$2"
                shift 2
                ;;
            -h|--help)
                usage
                ;;
            *)
                echo -e "${RED}[!] Unknown option: $1${NC}"
                usage
                ;;
        esac
    done
    
    # Validate required parameters
    if [[ -z "$TARGET" ]]; then
        echo -e "${RED}[!] Target is required${NC}"
        usage
    fi
    
    # Set defaults
    if [[ -z "$OUTPUT_DIR" ]]; then
        OUTPUT_DIR="results_${TARGET}"
    fi
    
    # Apply custom settings
    if [[ -n "$CUSTOM_RATE" ]]; then
        RATE_LIMIT="$CUSTOM_RATE"
    fi
    
    if [[ -n "$CUSTOM_THREADS" ]]; then
        THREADS="$CUSTOM_THREADS"
    fi
    
    # Parse modules
    IFS=',' read -ra MODULE_ARRAY <<< "$MODULES"
    for module in "${MODULE_ARRAY[@]}"; do
        case "$module" in
            "asn"|"prefix"|"services"|"cdn"|"all")
                ;;
            *)
                echo -e "${RED}[!] Unknown module: $module${NC}"
                usage
                ;;
        esac
    done
}

# Enhanced logging functions
log_info() {
    if [[ "$QUIET_MODE" != "true" ]]; then
        echo -e "${BLUE}[INFO]${NC} $1"
    fi
}

log_success() {
    if [[ "$QUIET_MODE" != "true" ]]; then
        echo -e "${GREEN}[SUCCESS]${NC} $1"
    fi
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_verbose() {
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        echo -e "${PURPLE}[VERBOSE]${NC} $1"
    fi
}

# Progress indicator
show_progress() {
    local current="$1"
    local total="$2"
    local desc="$3"
    local percent=$((current * 100 / total))
    
    printf "\r${CYAN}[%3d%%]${NC} %s" "$percent" "$desc"
    
    if [[ "$current" -eq "$total" ]]; then
        echo ""
    fi
}

# Smart Input Normalizer
normalize_target_input() {
    local target_input="$1"
    
    log_info "Normalizing target input: $target_input"
    
    if [[ "$target_input" == *"."* ]]; then
        # Eğer nokta varsa: Bu bir DOMAIN'dir.
        DOMAIN_TARGET="$target_input"
        ORG_TARGET="${target_input%.*}" # Uzantıyı sil (tesla.com -> tesla)
        log_info "Detected domain format - Domain: $DOMAIN_TARGET, Organization: $ORG_TARGET"
    else
        # Eğer nokta yoksa: Bu bir ORGANİZASYON'dur.
        ORG_TARGET="$target_input"
        DOMAIN_TARGET="${target_input}.com" # Standart .com ekle (tesla -> tesla.com)
        log_info "Detected organization format - Organization: $ORG_TARGET, Domain: $DOMAIN_TARGET"
    fi
    
    # Export variables for use in modules
    export DOMAIN_TARGET
    export ORG_TARGET
    
    log_info "Smart normalization completed"
}

# Validate target
validate_target() {
    local target="$1"
    
    log_info "Validating target: $target"
    
    # Basic validation
    if [[ ! "$target" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        log_error "Invalid target format: $target"
        return 1
    fi
    
    # Check if target resolves
    if command -v dig &> /dev/null; then
        if dig +short "$target" &> /dev/null; then
            log_success "Target resolves successfully"
            return 0
        else
            log_warn "Target does not resolve, but continuing anyway"
            return 0
        fi
    else
        log_warn "dig not available, skipping DNS validation"
        return 0
    fi
}

# Setup output directory
setup_output_directory() {
    local output_dir="$1"
    
    log_info "Setting up output directory: $output_dir"
    
    if [[ -d "$output_dir" ]]; then
        log_warn "Output directory already exists, backing up"
        mv "$output_dir" "${output_dir}_backup_$(date +%s)"
    fi
    
    mkdir -p "$output_dir"
    mkdir -p "$output_dir/logs"
    mkdir -p "$output_dir/reports"
    
    log_success "Output directory created"
}

# Module execution functions
run_asn_discovery() {
    log_info "Starting ASN discovery module"
    
    local asn_file="$OUTPUT_DIR/asn.txt"
    
    if [[ "$PARALLEL_MODE" == "true" ]]; then
        "$SCRIPT_DIR/asn_discovery.sh" "$TARGET" "$asn_file" "$USER_ASN_FILE" --parallel
    else
        "$SCRIPT_DIR/asn_discovery.sh" "$TARGET" "$asn_file" "$USER_ASN_FILE"
    fi
    
    local asn_count=$(wc -l < "$asn_file" 2>/dev/null || echo "0")
    log_success "ASN discovery completed: $asn_count ASNs found"
    
    return 0
}

run_prefix_discovery() {
    log_info "Starting prefix discovery module"
    
    local asn_file="$OUTPUT_DIR/asn.txt"
    local prefix_file="$OUTPUT_DIR/prefix.txt"
    
    if [[ ! -f "$asn_file" ]]; then
        log_error "ASN file not found: $asn_file"
        return 1
    fi
    
    if [[ "$PARALLEL_MODE" == "true" ]]; then
        "$SCRIPT_DIR/prefix_discovery.sh" "$asn_file" "$prefix_file" --parallel
    else
        "$SCRIPT_DIR/prefix_discovery.sh" "$asn_file" "$prefix_file"
    fi
    
    local prefix_count=$(wc -l < "$prefix_file" 2>/dev/null || echo "0")
    log_success "Prefix discovery completed: $prefix_count prefixes found"
    
    return 0
}

run_service_detection() {
    log_info "Starting service detection module"
    
    local prefix_file="$OUTPUT_DIR/prefix.txt"
    
    if [[ ! -f "$prefix_file" ]]; then
        log_error "Prefix file not found: $prefix_file"
        return 1
    fi
    
    "$SCRIPT_DIR/service_detection.sh" "$TARGET" "$prefix_file" "$OUTPUT_DIR"
    
    log_success "Service detection completed"
    
    return 0
}

run_cdn_origin_discovery() {
    log_info "Starting CDN and origin discovery module"
    
    local asn_file="$OUTPUT_DIR/asn.txt"
    
    if [[ ! -f "$asn_file" ]]; then
        log_error "ASN file not found: $asn_file"
        return 1
    fi
    
    "$SCRIPT_DIR/cdn_origin_finder.sh" "$TARGET" "$asn_file" "$OUTPUT_DIR"
    
    log_success "CDN and origin discovery completed"
    
    return 0
}

# Generate final report
generate_final_report() {
    log_info "Generating comprehensive final report"
    
    local report_file="$OUTPUT_DIR/reports/${TARGET}_final_report.txt"
    local json_report="$OUTPUT_DIR/reports/${TARGET}_final_report.json"
    
    # Text report
    cat > "$report_file" << EOF
=============================================================
COMPREHENSIVE ORIGIN IP DISCOVERY REPORT
Target: $TARGET
Generated: $(date)
Tool Version: $SCRIPT_VERSION
=============================================================

EXECUTION SUMMARY:
------------------
Target: $TARGET
Output Directory: $OUTPUT_DIR
Parallel Mode: $PARALLEL_MODE
IPv6 Enabled: $IPV6_ENABLED
Private IP Scan: $PRIVATE_SCAN
Rate Limit: $RATE_LIMIT
Threads: $THREADS

DISCOVERY RESULTS:
-----------------

ASN Discovery:
- Total ASNs Found: $(wc -l < "$OUTPUT_DIR/asn.txt" 2>/dev/null || echo "0")
- ASN File: $OUTPUT_DIR/asn.txt

Prefix Discovery:
- Total Prefixes Found: $(wc -l < "$OUTPUT_DIR/prefix.txt" 2>/dev/null || echo "0")
- Filtered Prefixes: $(wc -l < "$OUTPUT_DIR/prefix_filtered.txt" 2>/dev/null || echo "0")
- Prefix File: $OUTPUT_DIR/prefix.txt

Service Detection:
- Total IPs Generated: $(wc -l < "$OUTPUT_DIR/all_ips.txt" 2>/dev/null || echo "0")
- Live Hosts Found: $(wc -l < "$OUTPUT_DIR/live_ips.txt" 2>/dev/null || echo "0")
- Open Ports Found: $(wc -l < "$OUTPUT_DIR/open_ports.txt" 2>/dev/null || echo "0")
- Web Services: $(wc -l < "$OUTPUT_DIR/http_services.txt" 2>/dev/null || echo "0")
- SSH Services: $(wc -l < "$OUTPUT_DIR/ssh_services.txt" 2>/dev/null || echo "0")
- SSL/TLS Services: $(wc -l < "$OUTPUT_DIR/ssl_services.txt" 2>/dev/null || echo "0")
- Database Services: $(wc -l < "$OUTPUT_DIR/database_services.txt" 2>/dev/null || echo "0")

CDN and Origin Discovery:
- CDN Services Detected: $(wc -l < "$OUTPUT_DIR/cdn_detection.txt" 2>/dev/null || echo "0")
- Origin IPs Found: $(wc -l < "$OUTPUT_DIR/origin_ips.txt" 2>/dev/null || echo "0")
- Unique Origin IPs: $(cat "$OUTPUT_DIR/origin_ips.txt" 2>/dev/null | awk -F': ' '{print $2}' | sort -u | wc -l || echo "0")

DETAILED FINDINGS:
------------------

Top ASNs by Coverage:
$(cat "$OUTPUT_DIR/asn.txt" 2>/dev/null | head -10 | while read asn; do
    echo "- $asn"
done)

Top Open Ports:
$(cat "$OUTPUT_DIR/open_ports.txt" 2>/dev/null | awk -F: '{print $2}' | sort | uniq -c | sort -nr | head -10 | while read count port; do
    echo "- Port $port: $count hosts"
done)

Web Services Summary:
$(cat "$OUTPUT_DIR/http_services.txt" 2>/dev/null | head -10 || echo "No web services found")

Origin IP Analysis:
$(cat "$OUTPUT_DIR/origin_ips.txt" 2>/dev/null | awk -F': ' '{print $2}' | sort -u | head -10 | while read ip; do
    if [[ -n "$ip" ]]; then
        echo "- $ip ($(dig -x "$ip" +short 2>/dev/null || echo "No PTR") )"
    fi
done)

RECOMMENDATIONS:
----------------
1. Validate discovered origin IPs before using in assessments
2. Consider legal and ethical implications of origin IP usage
3. Monitor discovered services for security vulnerabilities
4. Implement proper access controls on identified services
5. Regularly scan for new infrastructure deployments

SECURITY CONSIDERATIONS:
-----------------------
- This tool should only be used for authorized security testing
- Respect rate limits and terms of service of all APIs used
- Ensure proper authorization before scanning any infrastructure
- Consider the potential impact of network scanning activities

=============================================================
Report completed: $(date)
=============================================================
EOF
    
    # JSON report (if jq is available)
    if command -v jq &> /dev/null; then
        cat > "$json_report" << EOF
{
  "target": "$TARGET",
  "generated": "$(date -Iseconds)",
  "tool_version": "$SCRIPT_VERSION",
  "execution": {
    "output_directory": "$OUTPUT_DIR",
    "parallel_mode": $PARALLEL_MODE,
    "ipv6_enabled": $IPV6_ENABLED,
    "private_scan": $PRIVATE_SCAN,
    "rate_limit": $RATE_LIMIT,
    "threads": $THREADS
  },
  "results": {
    "asn_discovery": {
      "total_asns": $(wc -l < "$OUTPUT_DIR/asn.txt" 2>/dev/null || echo "0"),
      "file": "$OUTPUT_DIR/asn.txt"
    },
    "prefix_discovery": {
      "total_prefixes": $(wc -l < "$OUTPUT_DIR/prefix.txt" 2>/dev/null || echo "0"),
      "filtered_prefixes": $(wc -l < "$OUTPUT_DIR/prefix_filtered.txt" 2>/dev/null || echo "0"),
      "file": "$OUTPUT_DIR/prefix.txt"
    },
    "service_detection": {
      "total_ips": $(wc -l < "$OUTPUT_DIR/all_ips.txt" 2>/dev/null || echo "0"),
      "live_hosts": $(wc -l < "$OUTPUT_DIR/live_ips.txt" 2>/dev/null || echo "0"),
      "open_ports": $(wc -l < "$OUTPUT_DIR/open_ports.txt" 2>/dev/null || echo "0"),
      "web_services": $(wc -l < "$OUTPUT_DIR/http_services.txt" 2>/dev/null || echo "0"),
      "ssh_services": $(wc -l < "$OUTPUT_DIR/ssh_services.txt" 2>/dev/null || echo "0"),
      "ssl_services": $(wc -l < "$OUTPUT_DIR/ssl_services.txt" 2>/dev/null || echo "0"),
      "database_services": $(wc -l < "$OUTPUT_DIR/database_services.txt" 2>/dev/null || echo "0")
    },
    "cdn_origin_discovery": {
      "cdn_services": $(wc -l < "$OUTPUT_DIR/cdn_detection.txt" 2>/dev/null || echo "0"),
      "origin_ips": $(wc -l < "$OUTPUT_DIR/origin_ips.txt" 2>/dev/null || echo "0"),
      "unique_origin_ips": $(cat "$OUTPUT_DIR/origin_ips.txt" 2>/dev/null | awk -F': ' '{print $2}' | sort -u | wc -l || echo "0")
    }
  }
}
EOF
    fi
    
    log_success "Final report generated: $report_file"
    if command -v jq &> /dev/null; then
        log_success "JSON report generated: $json_report"
    fi
}

# Main execution function
main() {
    # Show banner
    show_banner
    
    # Parse arguments
    parse_arguments "$@"
    
    # Initialize configuration
    init_config
    
    # Smart Input Normalizer
    normalize_target_input "$TARGET"
    
    # Validate target
    validate_target "$TARGET"
    
    # Setup output directory
    setup_output_directory "$OUTPUT_DIR"
    
    # Start execution
    log_info "Starting comprehensive origin IP discovery for: $TARGET"
    log_info "Output directory: $OUTPUT_DIR"
    
    local start_time=$(date +%s)
    
    # Execute modules based on selection
    for module in "${MODULE_ARRAY[@]}"; do
        case "$module" in
            "asn")
                run_asn_discovery
                ;;
            "prefix")
                run_prefix_discovery
                ;;
            "services")
                if [[ "$SKIP_SERVICES" != "true" ]]; then
                    run_service_detection
                else
                    log_info "Skipping service detection (disabled)"
                fi
                ;;
            "cdn")
                if [[ "$SKIP_CDN" != "true" ]]; then
                    run_cdn_origin_discovery
                else
                    log_info "Skipping CDN detection (disabled)"
                fi
                ;;
            "all")
                run_asn_discovery
                run_prefix_discovery
                if [[ "$SKIP_SERVICES" != "true" ]]; then
                    run_service_detection
                fi
                if [[ "$SKIP_CDN" != "true" ]]; then
                    run_cdn_origin_discovery
                fi
                ;;
        esac
    done
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Generate final report
    generate_final_report
    
    # Show completion summary
    echo ""
    echo -e "${GREEN}=================================================${NC}"
    echo -e "${GREEN}         DISCOVERY COMPLETED SUCCESSFULLY!        ${NC}"
    echo -e "${GREEN}=================================================${NC}"
    echo -e "${CYAN}Target:${NC} $TARGET"
    echo -e "${CYAN}Duration:${NC} $duration seconds"
    echo -e "${CYAN}Output:${NC} $OUTPUT_DIR"
    echo -e "${CYAN}Report:${NC} $OUTPUT_DIR/reports/${TARGET}_final_report.txt"
    echo ""
    echo -e "${YELLOW}Key Files:${NC}"
    echo -e "  • ASNs: $OUTPUT_DIR/asn.txt"
    echo -e "  • Prefixes: $OUTPUT_DIR/prefix.txt"
    echo -e "  • Live IPs: $OUTPUT_DIR/live_ips.txt"
    echo -e "  • Open Ports: $OUTPUT_DIR/open_ports.txt"
    echo -e "  • Web Services: $OUTPUT_DIR/http_services.txt"
    echo -e "  • Origin IPs: $OUTPUT_DIR/origin_ips.txt"
    echo ""
    echo -e "${GREEN}Happy hunting! 🎯${NC}"
}

# Execute main function
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
