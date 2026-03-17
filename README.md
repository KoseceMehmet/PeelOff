# Advanced Origin IP Discovery Tool v4.0

Comprehensive IP reconnaissance framework for discovering origin IP addresses, ASN information, and running services behind CDN-protected infrastructure.

## 🚀 Features

### Core Capabilities
- **Multi-source ASN Discovery**: asnmap, BGPView API, HE.net, crt.sh, Shodan, Censys, SecurityTrails
- **Comprehensive Prefix Discovery**: RIPE Stat, BGPView, RADB, all RIR databases (ARIN, RIPE, APNIC, LACNIC, AFRINIC)
- **Advanced Service Detection**: HTTP/HTTPS, SSH, SSL/TLS, DNS, SMB, Database services
- **CDN Detection & Origin Finding**: Cloudflare, Akamai, Fastly, CloudFront, Azure, Google Cloud, Alibaba
- **Parallel Processing**: Multi-threaded execution for large-scale reconnaissance
- **Dynamic Configuration**: API key management with graceful degradation

### Advanced Features
- **IPv6 Support**: Optional IPv6 address discovery and scanning
- **Private IP Scanning**: Configurable private network exploration
- **Rate Limiting**: Configurable scan rates to avoid detection
- **JSON & Text Reports**: Comprehensive reporting in multiple formats
- **Modular Architecture**: Individual modules for specific tasks
- **Error Handling**: Robust error recovery and logging

## 📋 Requirements

### System Requirements
- Linux/macOS (Windows with WSL2)
- Bash 4.0+
- Go 1.19+
- Python 3.6+

### Required Tools
- **asnmap** - ASN discovery
- **mapcidr** - CIDR manipulation
- **naabu** - Port scanning
- **httpx** - HTTP probing
- **jq** - JSON processing
- **nmap** - Network scanning
- **curl** - HTTP requests

### Optional Tools
- **dnsx** - DNS toolkit
- **uncover** - Internet-wide search
- **cdncheck** - CDN detection
- **fping** - Fast ping
- **parallel** - Parallel processing
- **masscan** - Ultra-fast port scanning

## 🛠️ Installation

### Quick Install (Recommended)
```bash
# Clone the repository
git clone https://github.com/KoseceMehmet/PeelOff.git
cd PeelOff

# Run the installer
chmod +x install.sh
./install.sh

# Configure API keys (optional but recommended)
cp .env.example .env
# Edit .env with your API keys
```

### Manual Install
```bash
# Install Go tools
go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest
go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
go install github.com/projectdiscovery/naabu/cmd/naabu@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/uncover/cmd/uncover@latest
go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest

# Install system packages (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y curl jq nmap whois dnsutils fping parallel

# Make scripts executable
chmod +x *.sh
```

## ⚙️ Configuration

### Environment Variables
Copy `.env.example` to `.env` and configure your API keys:

```bash
# API Keys (Optional - enhances discovery capabilities)
SHODAN_API_KEY=your_shodan_api_key
CENSYS_API_ID=your_censys_api_id
CENSYS_API_SECRET=your_censys_api_secret
SECURITYTRAILS_API_KEY=your_securitytrails_api_key
FOFA_EMAIL=your_fofa_email
FOFA_KEY=your_fofa_key
ZOOMEYE_API_KEY=your_zoomeye_api_key
BINARYEDGE_API_KEY=your_binaryedge_api_key

# Scan Configuration
DEFAULT_RATE_LIMIT=1000
MAX_CONCURRENT_REQUESTS=10
ENABLE_IPV6=false
ENABLE_PRIVATE_IP_SCAN=false
CDN_FILTER_ENABLED=true

# Performance Mode (Internet Safety)
FAST_MODE=false
# WARNING: Set to true only if you have very fast and stable internet
# Default throttled mode prevents internet connection issues on slow connections
```

### ⚠️ Internet Safety Notice

**Default Mode (Throttled)**: The tool runs in throttled mode by default to prevent internet connection issues on normal connections. This mode processes IPs in chunks of 1000 with 2-second delays between chunks.

**Fast Mode**: Enable `FAST_MODE=true` only if you have high-speed, stable internet. Fast mode uses aggressive scanning parameters that may cause connection issues on slower networks.

### 🛡️ CDN Filtering Notice

The tool automatically filters out CDN and cloud provider IP ranges to focus on origin infrastructure. The filtering includes:

**Major CDN Providers**: Cloudflare, Akamai, Fastly, CloudFront, Edgecast, Limelight

**Cloud Platforms**: AWS, Google Cloud, Azure, DigitalOcean, Linode, Vultr, OVH, Hetzner, IBM Cloud, Alibaba Cloud, Tencent Cloud, Oracle Cloud

**Hosting Providers**: GoDaddy, Bluehost, HostGator, SiteGround, WP Engine, Kinsta, Namecheap, Hostinger

**Modern Platforms**: Vercel, Netlify, Fly.io, Render, GitHub Pages, GitLab Pages, Firebase, Supabase, PlanetScale

**Major ISPs**: Level 3, Cogent, Hurricane Electric, NTT, Telia, Tata, AT&T, Verizon, Comcast, Vodafone, Orange, Deutsche Telekom

This ensures you focus on actual origin infrastructure rather than CDN endpoints and hosting services.

### API Key Benefits
- **Shodan**: Enhanced internet-wide IP discovery
- **Censys**: Comprehensive service fingerprinting
- **SecurityTrails**: Historical DNS and infrastructure data
- **Fofa/ZoomEye**: Additional internet-wide search capabilities

## 🎯 Usage

### Basic Usage
```bash
# Simple target scan
./origin_ip_discovery.sh -t tesla

# With custom ASN file
./origin_ip_discovery.sh -t tesla -l custom_asns.txt

# Parallel processing for large targets
./origin_ip_discovery.sh -t tesla -p

# Verbose output
./origin_ip_discovery.sh -t tesla -v
```

### Advanced Usage
```bash
# Custom modules only
./origin_ip_discovery.sh -t tesla --modules asn,prefix

# Skip certain modules
./origin_ip_discovery.sh -t tesla --skip-services --skip-cdn

# Custom rate limiting
./origin_ip_discovery.sh -t tesla --rate 2000 --threads 100

# Include IPv6 and private IPs
./origin_ip_discovery.sh -t tesla --ipv6 --private

# Custom output directory
./origin_ip_discovery.sh -t tesla -o /path/to/output
```

### Module-Specific Usage
```bash
# ASN discovery only
./asn_discovery.sh tesla tesla_asns.txt

# Prefix discovery with parallel processing
./prefix_discovery.sh tesla_asns.txt tesla_prefixes.txt --parallel

# Service detection
./service_detection.sh tesla tesla_prefixes.txt tesla_results

# CDN and origin finding
./cdn_origin_finder.sh tesla tesla_asns.txt tesla_results
```

## 📊 Output Structure

```
results_<target>/
├── asn.txt                    # Discovered ASNs
├── prefix.txt                 # IP prefixes/blocks
├── prefix_filtered.txt        # CDN-filtered prefixes
├── all_ips.txt               # All generated IPs
├── live_ips.txt              # Live hosts only
├── open_ports.txt            # Open ports
├── http_services.txt         # Web services
├── ssh_services.txt          # SSH services
├── ssl_services.txt          # SSL/TLS services
├── database_services.txt     # Database services
├── dns_services.txt          # DNS services
├── smb_services.txt          # SMB services
├── origin_ips.txt            # Potential origin IPs
├── cdn_detection.txt         # CDN services detected
├── services_detailed.txt     # Detailed service info
├── internet_wide.txt         # Internet-wide discovery
└── reports/
    ├── <target>_final_report.txt     # Comprehensive report
    ├── <target>_final_report.json    # JSON report
    ├── <target>_service_report.txt   # Service analysis
    └── <target>_cdn_origin_report.txt # CDN/Origin analysis
```

## 🔧 Modules

### ASN Discovery (`asn_discovery.sh`)
- **Free Sources**: asnmap, BGPView API, HE.net, crt.sh
- **Paid Sources**: Shodan, Censys, SecurityTrails (with API keys)
- **Parallel Processing**: Optional multi-threaded execution

### Prefix Discovery (`prefix_discovery.sh`)
- **RIR Integration**: All 5 Regional Internet Registries
- **BGP Data**: RIPE Stat, BGPView APIs
- **CDN Filtering**: Automatic CDN range exclusion
- **IPv6 Support**: Optional IPv6 prefix discovery

### Service Detection (`service_detection.sh`)
- **Live Host Detection**: fping, nmap, masscan support
- **Port Scanning**: naabu, nmap, masscan options
- **Service Fingerprinting**: HTTP, SSH, SSL, DNS, SMB, Database
- **Internet-wide Search**: uncover, Shodan, Censys integration

### CDN Origin Finder (`cdn_origin_finder.sh`)
- **CDN Detection**: 8+ major CDN providers
- **Origin Discovery**: DNS enumeration, CT logs, subdomains
- **Historical Data**: SecurityTrails, VirusTotal integration
- **Social Engineering**: GitHub, code repository analysis

## 🛡️ Legal & Ethical Considerations

### Authorized Use Only
- This tool is designed for authorized security testing
- Always obtain proper permission before scanning
- Respect terms of service of all APIs and services

### Rate Limiting
- Built-in rate limiting to avoid detection
- Configurable scan rates for different environments
- API key rotation recommended for large-scale scans

### Data Privacy
- No data is sent to third parties without explicit API usage
- Local processing of all discovered information
- Secure handling of API keys and sensitive data

## 🐛 Troubleshooting

### Common Issues

#### Installation Problems
```bash
# If Go tools not found, check PATH
echo $PATH | grep go/bin

# Add Go bin to PATH
export PATH="$PATH:$HOME/go/bin"
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
```

#### API Key Issues
```bash
# Test API key validity
curl -H "Authorization: Bearer $SHODAN_API_KEY" "https://api.shodan.io/account/profile"

# Check .env file permissions
chmod 600 .env
```

#### Performance Issues
```bash
# Reduce rate limit for stability
./origin_ip_discovery.sh -t target --rate 500

# Use parallel processing for large targets
./origin_ip_discovery.sh -t target -p --threads 20
```

#### Permission Errors
```bash
# Fix script permissions
chmod +x *.sh

# Fix output directory permissions
chmod 755 results_*
```

### Debug Mode
```bash
# Enable verbose logging
./origin_ip_discovery.sh -t target -v

# Check individual modules
./asn_discovery.sh target asns.txt
./prefix_discovery.sh asns.txt prefixes.txt
```

## 📈 Performance Optimization

### Large-Scale Scanning
```bash
# Optimize for large targets
./origin_ip_discovery.sh -t large_target \
  --rate 2000 \
  --threads 100 \
  --modules asn,prefix \
  --skip-services
```

### Memory Management
- Process ASNs in batches for very large targets
- Use parallel processing to reduce memory footprint
- Monitor system resources during execution

### Network Optimization
- Adjust rate limits based on network capacity
- Use masscan for ultra-fast port scanning
- Consider proxy rotation for API calls

## 🤝 Contributing

### Development Setup
```bash
# Clone repository
git clone <repository-url>
cd find_origin_ip

# Install development dependencies
./install.sh

# Run tests
./test.sh
```

### Code Style
- Use Bash 4.0+ features
- Follow shellcheck guidelines
- Modular function organization
- Comprehensive error handling

### Feature Requests
- Open GitHub issues for new features
- Provide detailed use cases
- Include example configurations

## 📚 API Documentation

### Supported APIs
- **Shodan**: Internet-wide device search
- **Censys**: Internet asset discovery
- **SecurityTrails**: DNS and infrastructure intelligence
- **BGPView**: BGP routing information
- **RIPE Stat**: Routing statistics

### Rate Limits
- Shodan: 1 request/second (free), 10+ (paid)
- Censys: 120 requests/minute (free), 1000+ (paid)
- SecurityTrails: 50 requests/minute (free), 1000+ (paid)
- BGPView: No official rate limit
- RIPE Stat: 30 requests/minute

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- [ProjectDiscovery](https://projectdiscovery.io/) - Excellent security tools
- [Shodan](https://shodan.io/) - Internet scanning platform
- [Censys](https://censys.io/) - Internet asset discovery
- [SecurityTrails](https://securitytrails.com/) - DNS intelligence
- All contributors and beta testers
---

**⚠️ Disclaimer**: This tool is for authorized security testing only. Users are responsible for ensuring compliance with applicable laws and regulations.
