#!/bin/bash

# Configuration Loader for Origin IP Discovery Tool
# Loads settings from .env file with defaults and validation

set -euo pipefail

# Default Configuration
DEFAULT_RATE_LIMIT=1000
MAX_CONCURRENT_REQUESTS=10
API_TIMEOUT=30
ENABLE_IPV6=false
ENABLE_PRIVATE_IP_SCAN=false
MAX_PORTS_PER_SCAN=1000
CDN_FILTER_ENABLED=true
FAST_MODE=false

# Tool Dependencies
REQUIRED_TOOLS=("asnmap" "jq" "curl" "mapcidr" "naabu" "httpx" "fping")
OPTIONAL_TOOLS=("uncover" "cdncheck" "dnsx" "prips")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Load environment variables
load_config() {
    local env_file=".env"
    
    if [[ -f "$env_file" ]]; then
        echo -e "${BLUE}[+] Loading configuration from $env_file${NC}"
        
        # Export all variables from .env file
        set -a
        source "$env_file"
        set +a
        
        echo -e "${GREEN}[+] Configuration loaded successfully${NC}"
    else
        echo -e "${YELLOW}[!] No .env file found, using defaults${NC}"
        echo -e "${YELLOW}[!] Copy .env.example to .env and configure API keys for enhanced features${NC}"
    fi
    
    # Set defaults if not defined
    RATE_LIMIT=${RATE_LIMIT:-$DEFAULT_RATE_LIMIT}
    CONCURRENT_REQUESTS=${MAX_CONCURRENT_REQUESTS:-$MAX_CONCURRENT_REQUESTS}
    TIMEOUT=${API_TIMEOUT:-$API_TIMEOUT}
    IPV6_ENABLED=${ENABLE_IPV6:-$ENABLE_IPV6}
    PRIVATE_SCAN=${ENABLE_PRIVATE_IP_SCAN:-$ENABLE_PRIVATE_IP_SCAN}
    PORT_LIMIT=${MAX_PORTS_PER_SCAN:-$MAX_PORTS_PER_SCAN}
    CDN_FILTER=${CDN_FILTER_ENABLED:-$CDN_FILTER_ENABLED}
    FAST_MODE_ENABLED=${FAST_MODE:-$FAST_MODE}
}

# Check if API key is available and valid
check_api_key() {
    local service="$1"
    local key_var="$2"
    local key_type="${3:-API_KEY}"
    
    if [[ -z "${!key_var:-}" ]]; then
        log "WARN" "$service API key not configured - $service features will be skipped"
        return 1
    fi
    
    # Basic validation (non-empty and reasonable length)
    local key="${!key_var}"
    if [[ ${#key} -lt 10 ]]; then
        log "WARN" "$service API key appears invalid (too short) - $service features will be skipped"
        return 1
    fi
    
    # Check for placeholder values
    if [[ "$key" =~ ^(your_|placeholder|example|test|xxx) ]]; then
        log "WARN" "$service API key appears to be a placeholder - $service features will be skipped"
        return 1
    fi
    
    log "SUCCESS" "$service API key is valid and will be used"
    return 0
}

# Check multi-part API credentials (like Censys)
check_api_credentials() {
    local service="$1"
    local id_var="$2"
    local secret_var="$3"
    
    local id="${!id_var:-}"
    local secret="${!secret_var:-}"
    
    if [[ -z "$id" || -z "$secret" ]]; then
        log "WARN" "$service API credentials incomplete - $service features will be skipped"
        return 1
    fi
    
    # Check for placeholder values
    if [[ "$id" =~ ^(your_|placeholder|example|test|xxx) ]] || [[ "$secret" =~ ^(your_|placeholder|example|test|xxx) ]]; then
        log "WARN" "$service API credentials appear to be placeholders - $service features will be skipped"
        return 1
    fi
    
    log "SUCCESS" "$service API credentials are valid and will be used"
    return 0
}

# Test API key validity with actual API call
test_api_key() {
    local service="$1"
    local key_var="$2"
    local test_url="$3"
    local auth_header="${4:-}"
    
    if ! check_api_key "$service" "$key_var"; then
        return 1
    fi
    
    log "INFO" "Testing $service API key validity..."
    
    local key="${!key_var}"
    local curl_cmd="curl -s --max-time 10 --fail"
    
    if [[ -n "$auth_header" ]]; then
        curl_cmd="$curl_cmd -H \"$auth_header: $key\""
    fi
    
    if eval "$curl_cmd \"$test_url\"" >/dev/null 2>&1; then
        log "SUCCESS" "$service API key is valid and accessible"
        return 0
    else
        log "WARN" "$service API key test failed - $service features will be skipped"
        return 1
    fi
}

# Check tool availability
check_dependencies() {
    local missing_tools=()
    
    echo -e "${BLUE}[+] Checking required tools...${NC}"
    
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
            echo -e "${RED}[!] Missing required tool: $tool${NC}"
        else
            echo -e "${GREEN}[+] Found: $tool${NC}"
        fi
    done
    
    echo -e "${BLUE}[+] Checking optional tools...${NC}"
    for tool in "${OPTIONAL_TOOLS[@]}"; do
        if command -v "$tool" &> /dev/null; then
            echo -e "${GREEN}[+] Found optional: $tool${NC}"
        else
            echo -e "${YELLOW}[!] Optional tool not found: $tool${NC}"
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo -e "${RED}[!] Missing required tools: ${missing_tools[*]}${NC}"
        echo -e "${RED}[!] Please install missing tools before continuing${NC}"
        return 1
    fi
    
    return 0
}

# Validate API keys
validate_api_keys() {
    echo -e "${BLUE}[+] Validating API keys...${NC}"
    
    local available_apis=()
    local skipped_apis=()
    
    # Check each API key
    check_api_key "Shodan" "SHODAN_API_KEY" && available_apis+=("shodan") || skipped_apis+=("shodan")
    
    check_api_credentials "Censys" "CENSYS_API_ID" "CENSYS_API_SECRET" && available_apis+=("censys") || skipped_apis+=("censys")
    
    check_api_key "SecurityTrails" "SECURITYTRAILS_API_KEY" && available_apis+=("securitytrails") || skipped_apis+=("securitytrails")
    
    check_api_credentials "Fofa" "FOFA_EMAIL" "FOFA_KEY" && available_apis+=("fofa") || skipped_apis+=("fofa")
    
    check_api_key "ZoomEye" "ZOOMEYE_API_KEY" && available_apis+=("zoomeye") || skipped_apis+=("zoomeye")
    
    check_api_key "BinaryEdge" "BINARYEDGE_API_KEY" && available_apis+=("binaryedge") || skipped_apis+=("binaryedge")
    
    check_api_key "VirusTotal" "VIRUSTOTAL_API_KEY" && available_apis+=("virustotal") || skipped_apis+=("virustotal")
    
    check_api_key "GitHub" "GITHUB_TOKEN" && available_apis+=("github") || skipped_apis+=("github")
    
    # Summary
    if [[ ${#available_apis[@]} -eq 0 ]]; then
        echo -e "${YELLOW}[!] No API keys configured - using free sources only${NC}"
        echo -e "${YELLOW}[!] The following features are skipped: ${skipped_apis[*]}${NC}"
    else
        echo -e "${GREEN}[+] Available APIs: ${available_apis[*]}${NC}"
        if [[ ${#skipped_apis[@]} -gt 0 ]]; then
            echo -e "${YELLOW}[!] Skipped APIs: ${skipped_apis[*]}${NC}"
        fi
    fi
    
    # Export available APIs for use in other scripts
    export AVAILABLE_APIS="${available_apis[*]}"
    export SKIPPED_APIS="${skipped_apis[*]}"
    
    # Show detailed skip reasons
    if [[ ${#skipped_apis[@]} -gt 0 ]]; then
        echo -e "${YELLOW}[!] Skipped features:${NC}"
        for api in "${skipped_apis[@]}"; do
            case "$api" in
                "shodan")
                    echo -e "    • Shodan: Internet-wide device search"
                    ;;
                "censys")
                    echo -e "    • Censys: Internet asset discovery"
                    ;;
                "securitytrails")
                    echo -e "    • SecurityTrails: DNS and infrastructure intelligence"
                    ;;
                "fofa")
                    echo -e "    • Fofa: Chinese cyber threat intelligence"
                    ;;
                "zoomeye")
                    echo -e "    • ZoomEye: Chinese cyberspace search engine"
                    ;;
                "binaryedge")
                    echo -e "    • BinaryEdge: Internet scanning service"
                    ;;
                "virustotal")
                    echo -e "    • VirusTotal: Historical DNS and subdomain discovery"
                    ;;
                "github")
                    echo -e "    • GitHub: Code repository scanning for origin IPs"
                    ;;
            esac
        done
        echo -e "${YELLOW}[!] To enable these features, configure the corresponding API keys in .env file${NC}"
    fi
}

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "ERROR")
            echo -e "${RED}[ERROR]${NC} [$timestamp] $message" >&2
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} [$timestamp] $message" >&2
            ;;
        "INFO")
            echo -e "${BLUE}[INFO]${NC} [$timestamp] $message"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[SUCCESS]${NC} [$timestamp] $message"
            ;;
        *)
            echo -e "[LOG] [$timestamp] $message"
            ;;
    esac
}

# Safe API call with timeout and error handling
safe_api_call() {
    local url="$1"
    local service="$2"
    local timeout="${3:-$TIMEOUT}"
    local auth_header="${4:-}"
    local auth_value="${5:-}"
    
    # Check if API key is available for this service
    case "$service" in
        "SHODAN_API_KEY")
            if ! check_api_key "Shodan" "SHODAN_API_KEY"; then
                log "WARN" "Shodan API call skipped - no valid API key"
                return 1
            fi
            auth_header="Authorization"
            auth_value="Bearer $SHODAN_API_KEY"
            ;;
        "CENSYS_API_ID")
            if ! check_api_credentials "Censys" "CENSYS_API_ID" "CENSYS_API_SECRET"; then
                log "WARN" "Censys API call skipped - no valid API credentials"
                return 1
            fi
            auth_header="Authorization"
            auth_value="Basic $(echo -n "$CENSYS_API_ID:$CENSYS_API_SECRET" | base64)"
            ;;
        "SECURITYTRAILS_API_KEY")
            if ! check_api_key "SecurityTrails" "SECURITYTRAILS_API_KEY"; then
                log "WARN" "SecurityTrails API call skipped - no valid API key"
                return 1
            fi
            auth_header="apikey"
            auth_value="$SECURITYTRAILS_API_KEY"
            ;;
        "GITHUB_TOKEN")
            if ! check_api_key "GitHub" "GITHUB_TOKEN"; then
                log "WARN" "GitHub API call skipped - no valid token"
                return 1
            fi
            auth_header="Authorization"
            auth_value="token $GITHUB_TOKEN"
            ;;
        "VIRUSTOTAL_API_KEY")
            if ! check_api_key "VirusTotal" "VIRUSTOTAL_API_KEY"; then
                log "WARN" "VirusTotal API call skipped - no valid API key"
                return 1
            fi
            auth_header="x-apikey"
            auth_value="$VIRUSTOTAL_API_KEY"
            ;;
        "NO_KEY_REQUIRED")
            # No authentication needed
            ;;
        *)
            log "WARN" "Unknown service: $service - API call skipped"
            return 1
            ;;
    esac
    
    log "INFO" "Calling $service API: $url"
    
    # Build curl command
    local curl_cmd="curl -s --max-time $timeout --fail"
    
    if [[ -n "$auth_header" && -n "$auth_value" ]]; then
        curl_cmd="$curl_cmd -H \"$auth_header: $auth_value\""
    fi
    
    # Add user agent if configured
    if [[ -n "${HTTP_USER_AGENT:-}" ]]; then
        curl_cmd="$curl_cmd -H \"User-Agent: $HTTP_USER_AGENT\""
    fi
    
    curl_cmd="$curl_cmd \"$url\""
    
    # Execute API call
    if eval "$curl_cmd" 2>/dev/null; then
        log "SUCCESS" "$service API call successful"
        return 0
    else
        log "WARN" "$service API call failed - feature will be skipped"
        return 1
    fi
}

# Initialize configuration
init_config() {
    load_config
    check_dependencies || exit 1
    validate_api_keys
}

# Export functions for use in other scripts
export -f log safe_api_call check_api_key

# If this script is run directly, initialize config
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    init_config
fi
