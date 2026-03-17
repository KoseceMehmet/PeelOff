#!/bin/bash

# Installation Script for Origin IP Discovery Tool
# Automatically installs all required dependencies

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Script information
SCRIPT_VERSION="4.0"
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Detection functions
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get &> /dev/null; then
            echo "debian"
        elif command -v yum &> /dev/null; then
            echo "redhat"
        elif command -v dnf &> /dev/null; then
            echo "fedora"
        elif command -v pacman &> /dev/null; then
            echo "arch"
        else
            echo "linux_unknown"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

detect_package_manager() {
    local os="$1"
    
    case "$os" in
        "debian")
            echo "apt"
            ;;
        "redhat"|"fedora")
            echo "yum"
            ;;
        "arch")
            echo "pacman"
            ;;
        "macos")
            if command -v brew &> /dev/null; then
                echo "brew"
            else
                echo "brew_missing"
            fi
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Install function for different package managers
install_package() {
    local package="$1"
    local os="$2"
    local pkg_manager="$3"
    
    log_info "Installing $package..."
    
    case "$pkg_manager" in
        "apt")
            sudo apt-get update -qq
            sudo apt-get install -y "$package"
            ;;
        "yum")
            sudo yum install -y "$package"
            ;;
        "pacman")
            sudo pacman -S --noconfirm "$package"
            ;;
        "brew")
            brew install "$package"
            ;;
        *)
            log_error "Unsupported package manager: $pkg_manager"
            return 1
            ;;
    esac
}

# Install Go
install_go() {
    local os="$1"
    
    if command_exists go; then
        log_success "Go is already installed: $(go version)"
        return 0
    fi
    
    log_info "Installing Go..."
    
    case "$os" in
        "debian"|"redhat"|"fedora"|"arch")
            install_package "golang-go" "$os" "$(detect_package_manager "$os")"
            ;;
        "macos")
            install_package "go" "$os" "brew"
            ;;
        *)
            log_error "Manual Go installation required for this OS"
            log_info "Please visit https://golang.org/dl/ to download Go"
            return 1
            ;;
    esac
    
    # Verify installation
    if command_exists go; then
        log_success "Go installed successfully: $(go version)"
    else
        log_error "Go installation failed"
        return 1
    fi
}

# Install Python packages
install_python_packages() {
    log_info "Installing Python packages..."
    
    # Check if pip is available
    if ! command_exists pip3 && ! command_exists pip; then
        log_warn "pip not found, installing..."
        local os="$1"
        local pkg_manager="$(detect_package_manager "$os")"
        
        case "$pkg_manager" in
            "apt")
                install_package "python3-pip" "$os" "$pkg_manager"
                ;;
            "yum")
                install_package "python3-pip" "$os" "$pkg_manager"
                ;;
            "pacman")
                install_package "python-pip" "$os" "$pkg_manager"
                ;;
            "brew")
                install_package "python3" "$os" "$pkg_manager"
                ;;
        esac
    fi
    
    # Install required Python packages
    local pip_cmd="pip3"
    if ! command_exists pip3; then
        pip_cmd="pip"
    fi
    
    $pip_cmd install --user requests jq >/dev/null 2>&1 || true
    
    log_success "Python packages installed"
}

# Install Go tools
install_go_tools() {
    log_info "Installing Go-based security tools..."
    
    local tools=(
        "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
        "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
        "github.com/projectdiscovery/naabu/cmd/naabu@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        "github.com/projectdiscovery/uncover/cmd/uncover@latest"
        "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
        "github.com/ffuf/ffuf@latest"
        "github.com/tomnomnom/waybackurls@latest"
        "github.com/tomnomnom/anew@latest"
    )
    
    for tool in "${tools[@]}"; do
        local tool_name=$(echo "$tool" | cut -d'/' -f6 | cut -d'@' -f1)
        
        if command_exists "$tool_name"; then
            log_success "$tool_name is already installed"
            continue
        fi
        
        log_info "Installing $tool_name..."
        
        if go install "$tool" 2>/dev/null; then
            log_success "$tool_name installed successfully"
        else
            log_warn "Failed to install $tool_name"
        fi
    done
}

# Install system tools
install_system_tools() {
    local os="$1"
    local pkg_manager="$(detect_package_manager "$os")"
    
    log_info "Installing system tools..."
    
    case "$os" in
        "debian")
            sudo apt-get update -qq
            sudo apt-get install -y curl wget git nmap whois dnsutils fping \
                jq parallel masscan prips
            ;;
        "redhat"|"fedora")
            sudo yum install -y curl wget git nmap whois bind-utils fping \
                jq parallel masscan prips
            ;;
        "arch")
            sudo pacman -S --noconfirm curl wget git nmap whois bind fping \
                jq parallel masscan
            ;;
        "macos")
            brew install curl wget git nmap whois bind fping jq parallel masscan
            ;;
        *)
            log_warn "Automatic system tool installation not supported for this OS"
            log_info "Please install manually: curl, wget, git, nmap, whois, dig, fping, jq, parallel"
            ;;
    esac
}

# Install additional tools
install_additional_tools() {
    log_info "Installing additional security tools..."
    
    # Install masscan if not available
    if ! command_exists masscan; then
        log_info "Installing masscan..."
        if command_exists apt-get; then
            sudo apt-get install -y masscan
        elif command_exists yum; then
            sudo yum install -y masscan
        elif command_exists brew; then
            brew install masscan
        else
            log_warn "Manual masscan installation required"
        fi
    fi
    
    # Install prips if not available
    if ! command_exists prips; then
        log_info "Installing prips..."
        if command_exists apt-get; then
            sudo apt-get install -y prips
        elif command_exists yum; then
            sudo yum install -y prips
        elif command_exists brew; then
            brew install prips
        else
            log_warn "Manual prips installation required"
        fi
    fi
    
    # Install parallel if not available
    if ! command_exists parallel; then
        log_info "Installing parallel..."
        if command_exists apt-get; then
            sudo apt-get install -y parallel
        elif command_exists yum; then
            sudo yum install -y parallel
        elif command_exists brew; then
            brew install parallel
        else
            log_warn "Manual parallel installation required"
        fi
    fi
}

# Setup environment
setup_environment() {
    log_info "Setting up environment..."
    
    # Add Go bin to PATH if not already there
    local go_bin="$HOME/go/bin"
    if [[ ":$PATH:" != *":$go_bin:"* ]]; then
        echo 'export PATH="$PATH:'$HOME'/go/bin"' >> ~/.bashrc
        echo 'export PATH="$PATH:'$HOME'/go/bin"' >> ~/.zshrc 2>/dev/null || true
        export PATH="$PATH:$HOME/go/bin"
        log_info "Added Go bin to PATH"
    fi
    
    # Create .env file if it doesn't exist
    if [[ ! -f "$INSTALL_DIR/.env" ]]; then
        if [[ -f "$INSTALL_DIR/.env.example" ]]; then
            cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
            log_success "Created .env file from template"
            log_warn "Please edit .env file with your API keys"
        else
            log_warn "No .env.example file found"
        fi
    fi
    
    # Make scripts executable
    chmod +x "$INSTALL_DIR"/*.sh
    
    log_success "Environment setup completed"
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."
    
    local missing_tools=()
    local optional_tools=()
    
    # Required tools
    local required=("asnmap" "jq" "curl" "nmap" "whois" "dig")
    
    # Optional but recommended tools
    local optional=("mapcidr" "naabu" "httpx" "dnsx" "uncover" "cdncheck" "fping" "parallel" "masscan" "prips")
    
    echo ""
    echo -e "${BLUE}Required Tools Status:${NC}"
    
    for tool in "${required[@]}"; do
        if command_exists "$tool"; then
            echo -e "  ${GREEN}✓${NC} $tool"
        else
            echo -e "  ${RED}✗${NC} $tool"
            missing_tools+=("$tool")
        fi
    done
    
    echo ""
    echo -e "${BLUE}Optional Tools Status:${NC}"
    
    for tool in "${optional[@]}"; do
        if command_exists "$tool"; then
            echo -e "  ${GREEN}✓${NC} $tool"
        else
            echo -e "  ${YELLOW}○${NC} $tool (optional)"
            optional_tools+=("$tool")
        fi
    done
    
    echo ""
    
    if [[ ${#missing_tools[@]} -eq 0 ]]; then
        log_success "All required tools are installed!"
    else
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Please install them manually or re-run the installer"
        return 1
    fi
    
    if [[ ${#optional_tools[@]} -gt 0 ]]; then
        log_warn "Some optional tools are missing: ${optional_tools[*]}"
        log_info "The tool will work without them, but with reduced functionality"
    fi
    
    return 0
}

# Show usage
show_usage() {
    echo "Origin IP Discovery Tool Installer v$SCRIPT_VERSION"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -v, --verbose  Verbose output"
    echo "  --dry-run      Show what would be installed without installing"
    echo "  --tools-only   Only install Go tools, skip system packages"
    echo "  --system-only  Only install system packages, skip Go tools"
    echo ""
    echo "Examples:"
    echo "  $0                    # Full installation"
    echo "  $0 --dry-run         # Preview installation"
    echo "  $0 --tools-only       # Only Go tools"
    echo "  $0 --system-only      # Only system packages"
}

# Main installation function
main() {
    local dry_run=false
    local tools_only=false
    local system_only=false
    local verbose=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            --dry-run)
                dry_run=true
                shift
                ;;
            --tools-only)
                tools_only=true
                shift
                ;;
            --system-only)
                system_only=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Show banner
    echo -e "${BLUE}"
    cat << "EOF"
 _____ _ _ _   _    _    _   _  ____ _____ ____  
| ____| | | | | / \  | |  | \ | |/ ___| ____|  _ \ 
|  _| | | | |_| |/ _ \ | |  |  \| | |   |  _| | | | |
| |___|_|_ _  / ___ \| |  | |\  | |___| |___| |_| |
|_____|_|_|_|/_/   \_\_|  |_| \_|\____|_____|____/ 
                                                   
               Installation Script v4.0
EOF
    echo -e "${NC}"
    
    # Detect OS
    local os=$(detect_os)
    local pkg_manager=$(detect_package_manager "$os")
    
    log_info "Detected OS: $os"
    log_info "Package manager: $pkg_manager"
    
    if [[ "$dry_run" == "true" ]]; then
        log_info "Dry run mode - no actual installation will be performed"
        echo ""
        echo "Would install:"
        echo "  • System packages (curl, wget, git, nmap, whois, dig, fping, jq, parallel, masscan, prips)"
        echo "  • Go language"
        echo "  • Go tools (asnmap, mapcidr, naabu, httpx, dnsx, uncover, cdncheck, ffuf, waybackurls, anew)"
        echo "  • Python packages (requests, jq)"
        echo "  • Environment setup (.env file, PATH updates)"
        echo ""
        exit 0
    fi
    
    # Check if running as root for system package installation
    if [[ "$system_only" != "true" && "$tools_only" != "true" ]] && [[ "$EUID" -ne 0 ]]; then
        log_warn "Some installations require sudo privileges"
        log_info "You may be prompted for your password"
    fi
    
    # Installation steps
    local start_time=$(date +%s)
    
    if [[ "$tools_only" != "true" ]]; then
        log_info "Starting system package installation..."
        install_system_tools "$os"
        install_additional_tools
        install_python_packages
    fi
    
    if [[ "$system_only" != "true" ]]; then
        log_info "Starting Go tool installation..."
        install_go "$os"
        install_go_tools
    fi
    
    setup_environment
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Verify installation
    if verify_installation; then
        echo ""
        echo -e "${GREEN}=================================================${NC}"
        echo -e "${GREEN}      INSTALLATION COMPLETED SUCCESSFULLY!      ${NC}"
        echo -e "${GREEN}=================================================${NC}"
        echo -e "${CYAN}Duration:${NC} $duration seconds"
        echo -e "${CYAN}Location:${NC} $INSTALL_DIR"
        echo ""
        echo -e "${YELLOW}Next steps:${NC}"
        echo -e "  1. Edit ${INSTALL_DIR}/.env with your API keys"
        echo -e "  2. Run: ${INSTALL_DIR}/origin_ip_discovery.sh -t <target>"
        echo -e "  3. For help: ${INSTALL_DIR}/origin_ip_discovery.sh --help"
        echo ""
        echo -e "${GREEN}Happy hunting! 🎯${NC}"
    else
        log_error "Installation verification failed"
        log_info "Please check the error messages above and resolve any issues"
        exit 1
    fi
}

# Run main function
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
