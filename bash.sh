#!/bin/bash

# PCAP Auto Extractor - Advanced Terminal Automation for PCAP Analysis
# Author: AI Assistant
# Description: Automates tshark extractions from PCAP files with organized output

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration variables
BASE_OUT="$HOME/Documents/Pcap_Extracts/$(date +%Y%m%d_%H%M%S)"
TOOLS_ROOT="/tmp/tools"
PARALLEL=1
DRY_RUN=false
JSON_REPORT=false
PCAP_FILE=""

# Create timestamped output directory
mkdir -p "$BASE_OUT"

# Create subdirectories
mkdir -p "$BASE_OUT/logs"
mkdir -p "$BASE_OUT/files/http"
mkdir -p "$BASE_OUT/files/smb"
mkdir -p "$BASE_OUT/files/nfs"
mkdir -p "$BASE_OUT/files/tftp"
mkdir -p "$BASE_OUT/files/ftp"
mkdir -p "$BASE_OUT/http"
mkdir -p "$BASE_OUT/dns"
mkdir -p "$BASE_OUT/kerberos"
mkdir -p "$BASE_OUT/tcp"
mkdir -p "$BASE_OUT/creds"
mkdir -p "$BASE_OUT/meta"
mkdir -p "$BASE_OUT/other"

# Initialize log files
touch "$BASE_OUT/logs/run.log"
touch "$BASE_OUT/logs/errors.log"

# GitHub repositories
declare -A REPOS=(
    ["decrypt-winrm"]="https://github.com/h4sh5/decrypt-winrm"
    ["ctf-tools"]="https://github.com/truongkma/ctf-tools"
    ["john"]="https://github.com/openwall/john"
)

# Function to print colored header
print_header() {
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    PCAP Auto Extractor                        ║"
    echo "║          Advanced Terminal Automation for PCAP Analysis        ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Function to print section header
print_section() {
    echo -e "${BLUE}${BOLD}═══ $1 ═══${NC}"
    echo
}

# Function to print success message
print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

# Function to print error message
print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Function to print warning message
print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Function to print info message
print_info() {
    echo -e "${CYAN}[i]${NC} $1"
}

# Function to print running message
print_running() {
    echo -e "${PURPLE}[→]${NC} $1"
}

# Function to log messages
log() {
    local message="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $message" | tee -a "$BASE_OUT/logs/run.log"
}

# Function to log errors
log_error() {
    local message="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $message" | tee -a "$BASE_OUT/logs/errors.log"
}

# Function to check dependencies
check_dependencies() {
    local missing=()
    
    # Check required dependencies
    for cmd in tshark git awk sed grep sort uniq paste mktemp find xargs tee wc python3; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done
    
    # Check optional dependencies
    local optional_missing=()
    for cmd in exiftool file jq timeout; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            optional_missing+=("$cmd")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing required dependencies: ${missing[*]}"
        echo -e "${RED}Please install missing dependencies:${NC}"
        echo -e "  ${YELLOW}Ubuntu/Debian:${NC} sudo apt install ${missing[*]}"
        echo -e "  ${YELLOW}macOS:${NC} brew install ${missing[*]}"
        exit 1
    fi
    
    if [ ${#optional_missing[@]} -gt 0 ]; then
        log "Optional dependencies not found: ${optional_missing[*]}"
        log "Some features may not work without these tools."
    fi
    
    print_success "All required dependencies are available."
    log "All required dependencies are available."
}

# Function to display usage
show_usage() {
    echo -e "${CYAN}${BOLD}Usage:${NC} $0 <pcap-file> [options]"
    echo
    echo -e "${YELLOW}Options:${NC}"
    echo -e "  ${GREEN}--parallel N${NC}      Run up to N extractors in parallel (default: 1)"
    echo -e "  ${GREEN}--dry-run${NC}         Show commands that would be executed without running them"
    echo -e "  ${GREEN}--json-report${NC}     Generate a machine-readable JSON summary report"
    echo -e "  ${GREEN}--tools-root DIR${NC}  Set the root directory for cloned tools (default: /tmp/tools)"
    echo
    echo -e "${YELLOW}Example:${NC}"
    echo -e "  $0 capture.pcap"
    echo -e "  $0 capture.pcap --parallel 4 --json-report"
}

# Function to parse command line arguments
parse_args() {
    if [ $# -eq 0 ]; then
        show_usage
        exit 1
    fi
    
    PCAP_FILE="$1"
    shift
    
    while [ $# -gt 0 ]; do
        case "$1" in
            --parallel)
                PARALLEL="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --json-report)
                JSON_REPORT=true
                shift
                ;;
            --tools-root)
                TOOLS_ROOT="$2"
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Validate PCAP file
    if [ ! -f "$PCAP_FILE" ]; then
        log_error "PCAP file not found: $PCAP_FILE"
        exit 1
    fi
    
    if [ ! -r "$PCAP_FILE" ]; then
        log_error "PCAP file not readable: $PCAP_FILE"
        exit 1
    fi
    
    # Log information only once
    log "PCAP file: $PCAP_FILE"
    log "Output directory: $BASE_OUT"
    log "Tools root: $TOOLS_ROOT"
    
    # Only log parallel execution if it's actually implemented
    if [ "$PARALLEL" -gt 1 ]; then
        log "Parallel execution: $PARALLEL (Note: Parallel execution is not yet implemented)"
    fi
    
    if [ "$DRY_RUN" = true ]; then
        log "Dry run mode enabled - no commands will be executed"
    fi
}

# Function to run a command and save output if non-empty
run_and_save() {
    local cmd="$1"
    local output_file="$2"
    local description="$3"
    
    print_running "Running: $cmd"
    log "Running: $cmd"
    
    if [ "$DRY_RUN" = true ]; then
        echo -e "${YELLOW}[DRY RUN]${NC} Would run: $cmd > $output_file"
        return 0
    fi
    
    local tmpfile
    tmpfile=$(mktemp)
    
    # Execute command, display live output, and save to temp file
    if eval "$cmd" | tee "$tmpfile"; then
        if [ -s "$tmpfile" ]; then
            # Ensure output directory exists
            mkdir -p "$(dirname "$output_file")"
            mv "$tmpfile" "$output_file"
            print_success "Saved -> $output_file"
            log "[+] Saved -> $output_file"
            return 0
        else
            rm -f "$tmpfile"
            print_warning "No $description found"
            log "[!] No $description found"
            return 1
        fi
    else
        local exit_code=$?
        rm -f "$tmpfile"
        print_error "Command failed with exit code $exit_code"
        log_error "Command failed with exit code $exit_code: $cmd"
        return $exit_code
    fi
}

# Extractor functions
# Meta extractors
extract_interfaces() {
    run_and_save "tshark -D" "$BASE_OUT/meta/interfaces.txt" "interface list"
}

extract_linktypes() {
    run_and_save "tshark -r \"$PCAP_FILE\" -L" "$BASE_OUT/meta/linktypes.txt" "link types"
}

extract_io_stats() {
    run_and_save "tshark -r \"$PCAP_FILE\" -q -z io,phs" "$BASE_OUT/meta/io_phs.txt" "I/O stats"
}

extract_kerberos_fields() {
    run_and_save "tshark -G fields | grep -i kerberos" "$BASE_OUT/meta/fields_kerberos.txt" "Kerberos fields"
}

# HTTP extractors
extract_http_requests() {
    run_and_save "tshark -r \"$PCAP_FILE\" -Y \"http.request\" -T fields -e http.request.method -e http.host -e http.request.uri" "$BASE_OUT/http/http_requests.tsv" "HTTP requests"
}

extract_http_hosts() {
    run_and_save "tshark -r \"$PCAP_FILE\" -Y \"http.host\" -T fields -e http.host" "$BASE_OUT/http/hosts.txt" "HTTP hosts"
}

extract_http_post_bodies() {
    run_and_save "tshark -r \"$PCAP_FILE\" -Y \"http.request.method == POST\" -T fields -e http.file_data" "$BASE_OUT/http/post_bodies.txt" "HTTP POST bodies"
}

extract_http_auth() {
    run_and_save "tshark -r \"$PCAP_FILE\" -Y \"http.authorization\" -T fields -e http.authorization" "$BASE_OUT/creds/http_auth_headers.txt" "HTTP auth headers"
}

extract_http_cookies() {
    run_and_save "tshark -r \"$PCAP_FILE\" -Y \"http.cookie\" -T fields -e http.cookie" "$BASE_OUT/http/cookies.txt" "HTTP cookies"
}

extract_http_objects() {
    print_info "Exporting HTTP objects..."
    log "Exporting HTTP objects..."
    
    if [ "$DRY_RUN" = true ]; then
        echo -e "${YELLOW}[DRY RUN]${NC} Would run: tshark -r \"$PCAP_FILE\" --export-objects http,\"$BASE_OUT/files/http\""
        return 0
    fi
    
    local count_before
    count_before=$(find "$BASE_OUT/files/http" -type f | wc -l)
    
    if tshark -r "$PCAP_FILE" --export-objects http,"$BASE_OUT/files/http" 2>/dev/null; then
        local count_after
        count_after=$(find "$BASE_OUT/files/http" -type f | wc -l)
        
        if [ "$count_after" -gt "$count_before" ]; then
            local exported=$((count_after - count_before))
            print_success "Saved -> $exported HTTP objects to $BASE_OUT/files/http"
            log "[+] Saved -> $exported HTTP objects to $BASE_OUT/files/http"
            return 0
        else
            print_warning "No HTTP objects found"
            log "[!] No HTTP objects found"
            return 1
        fi
    else
        print_error "Failed to export HTTP objects"
        log_error "Failed to export HTTP objects"
        return 1
    fi
}

# DNS extractors
extract_dns_queries() {
    run_and_save "tshark -r \"$PCAP_FILE\" -Y \"dns.qry.name\" -T fields -e dns.qry.name" "$BASE_OUT/dns/dns_queries.txt" "DNS queries"
}

extract_dns_answers() {
    run_and_save "tshark -r \"$PCAP_FILE\" -Y \"dns.flags.response == 1\" -T fields -e dns.resp.name -e dns.a -e dns.aaaa -e dns.cname" "$BASE_OUT/dns/dns_answers.tsv" "DNS answers"
}

extract_dns_txt() {
    run_and_save "tshark -r \"$PCAP_FILE\" -Y \"dns.txt\" -T fields -e dns.txt" "$BASE_OUT/dns/txt_records.txt" "DNS TXT records"
}

extract_all_qnames() {
    run_and_save "tshark -r \"$PCAP_FILE\" -Y \"dns.qry.name\" -T fields -e dns.qry.name" "$BASE_OUT/dns/all_qnames.txt" "DNS QNames"
}

# TCP extractors
extract_synack_ports() {
    run_and_save "tshark -r \"$PCAP_FILE\" -Y \"tcp.flags.syn == 1 && tcp.flags.ack == 1\" -T fields -e tcp.srcport | sort -n | uniq | paste -sd ','" "$BASE_OUT/tcp/synack_srcports.txt" "SYN+ACK source ports"
}

extract_tcp_conversations() {
    run_and_save "tshark -r \"$PCAP_FILE\" -q -z conv,tcp" "$BASE_OUT/tcp/tcp_conversations.txt" "TCP conversations"
}

extract_ip_conversations() {
    run_and_save "tshark -r \"$PCAP_FILE\" -q -z conv,ip" "$BASE_OUT/tcp/ip_conversations.txt" "IP conversations"
}

# Kerberos extractors
extract_kerberos_users() {
    run_and_save "tshark -r \"$PCAP_FILE\" -Y \"kerberos\" -T fields -e kerberos.CNameString -e kerberos.crealm" "$BASE_OUT/kerberos/users_realms.tsv" "Kerberos users and realms"
}

extract_kerberos_ciphers() {
    run_and_save "tshark -r \"$PCAP_FILE\" -Y \"kerberos\" -T fields -e kerberos.cipher" "$BASE_OUT/kerberos/ciphers_all.txt" "Kerberos ciphers"
}

extract_asrep_candidates() {
    print_info "Building AS-REP candidates..."
    log "Building AS-REP candidates..."
    
    if [ "$DRY_RUN" = true ]; then
        echo -e "${YELLOW}[DRY RUN]${NC} Would build AS-REP candidates from Kerberos data"
        return 0
    fi
    
    local tmpfile
    tmpfile=$(mktemp)
    
    if tshark -r "$PCAP_FILE" -Y "kerberos" -T fields -e kerberos.cipher -e kerberos.CNameString -e kerberos.crealm > "$tmpfile"; then
        if [ -s "$tmpfile" ]; then
            awk -F'\t' '{
                split($1,a,","); 
                print "$krb5asrep$23$" $2 "@" $3 ":" a[2]
            }' "$tmpfile" | awk -F':' '{
                prefix_len=length($1) + 33; 
                print substr($0, 1, prefix_len) "$" substr($0, prefix_len+1)
            }' > "$BASE_OUT/kerberos/asrep_candidates.txt"
            
            rm -f "$tmpfile"
            print_success "Saved -> $BASE_OUT/kerberos/asrep_candidates.txt"
            log "[+] Saved -> $BASE_OUT/kerberos/asrep_candidates.txt"
            return 0
        else
            rm -f "$tmpfile"
            print_warning "No Kerberos data found for AS-REP candidates"
            log "[!] No Kerberos data found for AS-REP candidates"
            return 1
        fi
    else
        rm -f "$tmpfile"
        print_error "Failed to extract Kerberos data for AS-REP candidates"
        log_error "Failed to extract Kerberos data for AS-REP candidates"
        return 1
    fi
}

# Credentials extractors
extract_ftp_commands() {
    run_and_save "tshark -r \"$PCAP_FILE\" -Y \"ftp.request.command\" -T fields -e ftp.request.command -e ftp.request.arg" "$BASE_OUT/other/ftp_commands.tsv" "FTP commands"
}

extract_ftp_creds() {
    run_and_save "tshark -r \"$PCAP_FILE\" -Y 'ftp.request.command == \"USER\" || ftp.request.command == \"PASS\"' -T fields -e ftp.request.command -e ftp.request.arg" "$BASE_OUT/creds/ftp_user_pass.tsv" "FTP credentials"
}

extract_smtp_subjects() {
    run_and_save "tshark -r \"$PCAP_FILE\" -Y 'smtp.req.parameter == \"Subject\"' -T fields -e smtp.req.value" "$BASE_OUT/other/smtp_subjects.txt" "SMTP subjects"
}

# TLS extractors
extract_tls_ja3() {
    run_and_save "tshark -r \"$PCAP_FILE\" -Y \"tls.handshake.type == 1\" -T fields -e tls.handshake.ja3 -e tls.handshake.extensions_server_name" "$BASE_OUT/meta/tls_ja3.txt" "TLS JA3 fingerprints"
}

# DNS exfil detection
detect_dns_exfil() {
    print_info "Detecting DNS exfiltration heuristics..."
    log "Detecting DNS exfiltration heuristics..."
    
    if [ "$DRY_RUN" = true ]; then
        echo -e "${YELLOW}[DRY RUN]${NC} Would run DNS exfiltration detection"
        return 0
    fi
    
    # Check if we have DNS data
    if [ ! -f "$BASE_OUT/dns/all_qnames.txt" ]; then
        print_warning "No DNS QNames found, skipping exfil detection"
        log "[!] No DNS QNames found, skipping exfil detection"
        return 1
    fi
    
    # Create output file
    local exfil_file="$BASE_OUT/dns/exfil_suspicions.txt"
    touch "$exfil_file"
    
    # Detect long QNAMEs (>60 chars)
    awk 'length($0) > 60 {print "LONG_QNAME: " $0}' "$BASE_OUT/dns/all_qnames.txt" >> "$exfil_file"
    
    # Detect base64-like labels
    grep -oE '[a-zA-Z0-9+/=]{16,}' "$BASE_OUT/dns/all_qnames.txt" | sort | uniq | while read -r label; do
        echo "B64_LABEL: $label" >> "$exfil_file"
    done
    
    # Detect high cardinality of subdomains for a base domain
    awk -F. '{print $(NF-1)"."$NF}' "$BASE_OUT/dns/all_qnames.txt" | sort | uniq -c | sort -nr | awk '$1 > 10 {print "HIGH_FREQ: " $2 " (" $1 " queries)"}' >> "$exfil_file"
    
    # Check if we found anything suspicious
    if [ -s "$exfil_file" ]; then
        print_success "Saved -> $exfil_file"
        log "[+] Saved -> $exfil_file"
        return 0
    else
        rm -f "$exfil_file"
        print_warning "No DNS exfiltration indicators found"
        log "[!] No DNS exfiltration indicators found"
        return 1
    fi
}

# Chained analysis functions
analyze_http_hosts() {
    if [ ! -f "$BASE_OUT/http/hosts.txt" ]; then
        print_warning "No HTTP hosts found, skipping detailed analysis"
        log "[!] No HTTP hosts found, skipping detailed analysis"
        return 1
    fi
    
    print_info "Performing detailed analysis of HTTP hosts..."
    log "Performing detailed analysis of HTTP hosts..."
    
    local hosts
    hosts=$(sort "$BASE_OUT/http/hosts.txt" | uniq)
    
    for host in $hosts; do
        local safe_host
        safe_host=$(echo "$host" | tr -d '[:space:]/\\')
        local output_file="$BASE_OUT/http/uris_${safe_host}.txt"
        
        run_and_save "tshark -r \"$PCAP_FILE\" -Y \"http.host == \\\"$host\\\" && http.request.uri\" -T fields -e http.request.uri" "$output_file" "URIs for host $host"
        
        # Pretty print URIs if file exists and is not empty
        if [ -f "$output_file" ] && [ -s "$output_file" ]; then
            echo
            echo -e "${CYAN}URIs for ${BOLD}$host${NC}${CYAN}:${NC}"
            echo -e "${BLUE}---------------${NC}"
            sed 's/^/→ /' "$output_file"
        fi
    done
}

analyze_kerberos() {
    if [ ! -f "$BASE_OUT/kerberos/users_realms.tsv" ] || [ ! -f "$BASE_OUT/kerberos/ciphers_all.txt" ]; then
        print_warning "No Kerberos data found, skipping AS-REP analysis"
        log "[!] No Kerberos data found, skipping AS-REP analysis"
        return 1
    fi
    
    print_info "Analyzing Kerberos data for AS-REP candidates..."
    log "Analyzing Kerberos data for AS-REP candidates..."
    extract_asrep_candidates
}

analyze_post_bodies() {
    if [ ! -f "$BASE_OUT/http/post_bodies.txt" ]; then
        print_warning "No HTTP POST bodies found, skipping credential analysis"
        log "[!] No HTTP POST bodies found, skipping credential analysis"
        return 1
    fi
    
    print_info "Analyzing POST bodies for potential credentials..."
    log "Analyzing POST bodies for potential credentials..."
    
    local creds_file="$BASE_OUT/creds/post_body_creds.txt"
    touch "$creds_file"
    
    grep -iE 'password|pass|pwd' "$BASE_OUT/http/post_bodies.txt" > "$creds_file"
    
    if [ -s "$creds_file" ]; then
        print_success "Saved -> $creds_file"
        log "[+] Saved -> $creds_file"
        return 0
    else
        rm -f "$creds_file"
        print_warning "No credentials found in POST bodies"
        log "[!] No credentials found in POST bodies"
        return 1
    fi
}

# Function to run all extractors
run_all_extractors() {
    print_info "Running all extractors..."
    log "Running all extractors..."
    
    # Meta extractors
    extract_interfaces
    extract_linktypes
    extract_io_stats
    extract_kerberos_fields
    
    # HTTP extractors
    extract_http_requests
    extract_http_hosts
    extract_http_post_bodies
    extract_http_auth
    extract_http_cookies
    extract_http_objects
    
    # DNS extractors
    extract_dns_queries
    extract_dns_answers
    extract_dns_txt
    extract_all_qnames
    
    # TCP extractors
    extract_synack_ports
    extract_tcp_conversations
    extract_ip_conversations
    
    # Kerberos extractors
    extract_kerberos_users
    extract_kerberos_ciphers
    
    # Credentials extractors
    extract_ftp_commands
    extract_ftp_creds
    extract_smtp_subjects
    
    # TLS extractors
    extract_tls_ja3
    
    # DNS exfil detection
    detect_dns_exfil
    
    # Chained analysis
    analyze_http_hosts
    analyze_kerberos
    analyze_post_bodies
    
    print_success "All extractors completed."
    log "All extractors completed."
    
    # Ask user if they want to return to menu or exit
    echo
    read -p "Extraction complete. Return to menu? [Y/n] " ans
    if [[ "$ans" =~ ^[Nn]$ ]]; then
        print_info "User chose to exit after extraction"
        log "User chose to exit after extraction"
        exit 0
    fi
}

# Function to display the main menu
show_menu() {
    echo
    echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}║                         PCAP Auto Extractor - Main Menu                  ║${NC}"
    echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}1.${NC} Extract ALL (safe, modular)"
    echo -e "${GREEN}2.${NC} Run a specific extractor"
    echo -e "${GREEN}3.${NC} GitHub Tools"
    echo -e "${GREEN}4.${NC} Show Summary"
    echo -e "${RED}5.${NC} Exit"
    echo
}

# Function to display the extractor menu
show_extractor_menu() {
    echo
    echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}║                      Select an extractor to run:                       ║${NC}"
    echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN} 1.${NC} Meta - Interface listing"
    echo -e "${GREEN} 2.${NC} Meta - Link types"
    echo -e "${GREEN} 3.${NC} Meta - PCAP stats"
    echo -e "${GREEN} 4.${NC} Meta - Kerberos fields"
    echo -e "${YELLOW} 5.${NC} HTTP - Requests"
    echo -e "${YELLOW} 6.${NC} HTTP - Hosts"
    echo -e "${YELLOW} 7.${NC} HTTP - POST bodies"
    echo -e "${YELLOW} 8.${NC} HTTP - Auth headers"
    echo -e "${YELLOW} 9.${NC} HTTP - Cookies"
    echo -e "${YELLOW}10.${NC} HTTP - Export objects"
    echo -e "${BLUE}11.${NC} DNS - Queries"
    echo -e "${BLUE}12.${NC} DNS - Answers"
    echo -e "${BLUE}13.${NC} DNS - TXT records"
    echo -e "${BLUE}14.${NC} DNS - All QNames"
    echo -e "${PURPLE}15.${NC} TCP - SYN+ACK ports"
    echo -e "${PURPLE}16.${NC} TCP - Conversations"
    echo -e "${PURPLE}17.${NC} TCP - IP conversations"
    echo -e "${RED}18.${NC} Kerberos - Users and realms"
    echo -e "${RED}19.${NC} Kerberos - Ciphers"
    echo -e "${RED}20.${NC} Kerberos - AS-REP candidates"
    echo -e "${RED}21.${NC} Credentials - FTP commands"
    echo -e "${RED}22.${NC} Credentials - FTP credentials"
    echo -e "${RED}23.${NC} Credentials - SMTP subjects"
    echo -e "${PURPLE}24.${NC} TLS - JA3 fingerprints"
    echo -e "${BLUE}25.${NC} DNS - Exfiltration detection"
    echo -e "${YELLOW}26.${NC} Chained - HTTP hosts analysis"
    echo -e "${RED}27.${NC} Chained - Kerberos analysis"
    echo -e "${YELLOW}28.${NC} Chained - POST bodies analysis"
    echo -e "${WHITE}29.${NC} Back to main menu"
    echo
}

# Function to run a specific extractor
run_specific_extractor() {
    while true; do
        show_extractor_menu
        read -p "Please select an option: " choice
        
        case "$choice" in
            1) extract_interfaces ;;
            2) extract_linktypes ;;
            3) extract_io_stats ;;
            4) extract_kerberos_fields ;;
            5) extract_http_requests ;;
            6) extract_http_hosts ;;
            7) extract_http_post_bodies ;;
            8) extract_http_auth ;;
            9) extract_http_cookies ;;
            10) extract_http_objects ;;
            11) extract_dns_queries ;;
            12) extract_dns_answers ;;
            13) extract_dns_txt ;;
            14) extract_all_qnames ;;
            15) extract_synack_ports ;;
            16) extract_tcp_conversations ;;
            17) extract_ip_conversations ;;
            18) extract_kerberos_users ;;
            19) extract_kerberos_ciphers ;;
            20) extract_asrep_candidates ;;
            21) extract_ftp_commands ;;
            22) extract_ftp_creds ;;
            23) extract_smtp_subjects ;;
            24) extract_tls_ja3 ;;
            25) detect_dns_exfil ;;
            26) analyze_http_hosts ;;
            27) analyze_kerberos ;;
            28) analyze_post_bodies ;;
            29) break ;;
            *) echo -e "${RED}Invalid option, please try again.${NC}" ;;
        esac
        
        echo
        echo "Press Enter to continue..."
        read -r
    done
}

# Function to show GitHub tools menu
show_github_menu() {
    echo
    echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}║                            GitHub Tools Menu                           ║${NC}"
    echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
    
    local i=1
    for repo in "${!REPOS[@]}"; do
        echo -e "${GREEN}$i.${NC} $repo (${REPOS[$repo]})"
        ((i++))
    done
    
    echo -e "${WHITE}$i.${NC} Back to main menu"
    echo
}

# Function to clone and run a GitHub tool
clone_and_run_tool() {
    local repo_name="$1"
    local repo_url="${REPOS[$repo_name]}"
    
    print_info "Cloning $repo_name..."
    log "Cloning $repo_name..."
    
    if [ "$DRY_RUN" = true ]; then
        echo -e "${YELLOW}[DRY RUN]${NC} Would clone $repo_url to $TOOLS_ROOT/$repo_name"
        return 0
    fi
    
    # Create tools directory if it doesn't exist
    mkdir -p "$TOOLS_ROOT"
    
    # Clone the repository
    if git clone --depth 1 "$repo_url" "$TOOLS_ROOT/$repo_name"; then
        print_success "Cloned $repo_name to $TOOLS_ROOT/$repo_name"
        log "[+] Cloned $repo_name to $TOOLS_ROOT/$repo_name"
        
        # Create output directory for this tool
        local tool_out="$BASE_OUT/tools/$repo_name"
        mkdir -p "$tool_out"
        
        # Check if this is a Kerberos tool
        if [[ "$repo_name" == *"john"* ]] || [[ "$repo_name" == *"ctf-tools"* ]]; then
            run_krbpa2john_tool "$repo_name" "$tool_out"
        elif [[ "$repo_name" == *"decrypt-winrm"* ]]; then
            run_decrypt_winrm_tool "$repo_name" "$tool_out"
        else
            print_warning "No specific handler for $repo_name"
            log "[!] No specific handler for $repo_name"
        fi
    else
        print_error "Failed to clone $repo_name"
        log_error "Failed to clone $repo_name"
        return 1
    fi
}

# Function to run krbpa2john tool
run_krbpa2john_tool() {
    local repo_name="$1"
    local tool_out="$2"
    
    print_info "Running krbpa2john tool..."
    log "Running krbpa2john tool..."
    
    # Check if AS-REP candidates exist
    if [ ! -f "$BASE_OUT/kerberos/asrep_candidates.txt" ]; then
        print_warning "No AS-REP candidates found. Run Kerberos extractors first."
        return 1
    fi
    
    # Find the krbpa2john.py script
    local script_path=""
    if [ -f "$TOOLS_ROOT/$repo_name/run/krbpa2john.py" ]; then
        script_path="$TOOLS_ROOT/$repo_name/run/krbpa2john.py"
    elif [ -f "$TOOLS_ROOT/$repo_name/krbpa2john.py" ]; then
        script_path="$TOOLS_ROOT/$repo_name/krbpa2john.py"
    else
        print_error "krbpa2john.py not found in $TOOLS_ROOT/$repo_name"
        log_error "krbpa2john.py not found in $TOOLS_ROOT/$repo_name"
        return 1
    fi
    
    # Run the script
    local output_file="$tool_out/krbpa2john_output.txt"
    print_running "Running: python3 \"$script_path\" \"$BASE_OUT/kerberos/asrep_candidates.txt\""
    log "Running: python3 \"$script_path\" \"$BASE_OUT/kerberos/asrep_candidates.txt\""
    
    if python3 "$script_path" "$BASE_OUT/kerberos/asrep_candidates.txt" > "$output_file" 2>> "$BASE_OUT/logs/errors.log"; then
        if [ -s "$output_file" ]; then
            print_success "Saved -> $output_file"
            log "[+] Saved -> $output_file"
            
            # Also copy to kerberos directory for convenience
            cp "$output_file" "$BASE_OUT/kerberos/krbpa2john_output.txt"
            print_success "Also saved -> $BASE_OUT/kerberos/krbpa2john_output.txt"
            log "[+] Also saved -> $BASE_OUT/kerberos/krbpa2john_output.txt"
            
            return 0
        else
            print_warning "No output from krbpa2john.py"
            log "[!] No output from krbpa2john.py"
            return 1
        fi
    else
        print_error "Failed to run krbpa2john.py"
        log_error "Failed to run krbpa2john.py"
        return 1
    fi
}

# Function to run decrypt-winrm tool
run_decrypt_winrm_tool() {
    local repo_name="$1"
    local tool_out="$2"
    
    print_info "Running decrypt-winrm tool..."
    log "Running decrypt-winrm tool..."
    
    # Check if the script exists
    local script_path=""
    if [ -f "$TOOLS_ROOT/$repo_name/Decrypt-WinRM.ps1" ]; then
        script_path="$TOOLS_ROOT/$repo_name/Decrypt-WinRM.ps1"
    else
        print_error "Decrypt-WinRM.ps1 not found in $TOOLS_ROOT/$repo_name"
        log_error "Decrypt-WinRM.ps1 not found in $TOOLS_ROOT/$repo_name"
        return 1
    fi
    
    # This is a PowerShell script, so we need to check if we're on Windows or have PowerShell available
    if ! command -v powershell >/dev/null 2>&1 && ! command -v pwsh >/dev/null 2>&1; then
        print_error "PowerShell not available. Cannot run decrypt-winrm tool."
        log_error "PowerShell not available. Cannot run decrypt-winrm tool."
        return 1
    fi
    
    # Prompt user for required inputs
    echo -e "${YELLOW}Decrypt-WinRM requires the following inputs:${NC}"
    echo -e "${YELLOW}1. Path to the encrypted WinRM traffic file (PCAP)${NC}"
    echo -e "${YELLOW}2. Path to the server's certificate file (PEM format)${NC}"
    echo -e "${YELLOW}3. Path to the server's private key file (PEM format)${NC}"
    echo
    
    local cert_file=""
    local key_file=""
    
    read -p "Enter path to server certificate file: " cert_file
    read -p "Enter path to server private key file: " key_file
    
    # Validate inputs
    if [ ! -f "$cert_file" ]; then
        print_error "Certificate file not found: $cert_file"
        return 1
    fi
    
    if [ ! -f "$key_file" ]; then
        print_error "Private key file not found: $key_file"
        return 1
    fi
    
    # Run the script
    local output_file="$tool_out/decrypt_winrm_output.txt"
    local ps_command="& '$script_path' -PcapFile '$PCAP_FILE' -CertFile '$cert_file' -KeyFile '$key_file'"
    
    print_running "Running: $ps_command"
    log "Running: $ps_command"
    
    if command -v powershell >/dev/null 2>&1; then
        if powershell -Command "$ps_command" > "$output_file" 2>> "$BASE_OUT/logs/errors.log"; then
            if [ -s "$output_file" ]; then
                print_success "Saved -> $output_file"
                return 0
            else
                print_warning "No output from Decrypt-WinRM.ps1"
                return 1
            fi
        else
            print_error "Failed to run Decrypt-WinRM.ps1"
            return 1
        fi
    elif command -v pwsh >/dev/null 2>&1; then
        if pwsh -Command "$ps_command" > "$output_file" 2>> "$BASE_OUT/logs/errors.log"; then
            if [ -s "$output_file" ]; then
                print_success "Saved -> $output_file"
                return 0
            else
                print_warning "No output from Decrypt-WinRM.ps1"
                return 1
            fi
        else
            print_error "Failed to run Decrypt-WinRM.ps1"
            return 1
        fi
    fi
}

# Function to handle GitHub tools menu
handle_github_tools() {
    while true; do
        show_github_menu
        read -p "Please select a tool: " choice
        
        # Get the number of repos
        local num_repos=${#REPOS[@]}
        
        if [ "$choice" -eq "$((num_repos + 1))" ]; then
            break
        elif [ "$choice" -ge 1 ] && [ "$choice" -le "$num_repos" ]; then
            # Get the repo name from the choice
            local i=1
            for repo in "${!REPOS[@]}"; do
                if [ "$i" -eq "$choice" ]; then
                    clone_and_run_tool "$repo"
                    break
                fi
                ((i++))
            done
        else
            echo -e "${RED}Invalid option, please try again.${NC}"
        fi
        
        echo
        echo "Press Enter to continue..."
        read -r
    done
}

# Function to generate summary report
generate_summary() {
    print_info "Generating summary report..."
    log "Generating summary report..."
    
    local summary_file="$BASE_OUT/SUMMARY.txt"
    local json_file="$BASE_OUT/summary.json"
    
    # Create text summary
    {
        echo "PCAP Auto Extractor - Analysis Summary"
        echo "======================================"
        echo "PCAP File: $PCAP_FILE"
        echo "Analysis Date: $(date)"
        echo "Output Directory: $BASE_OUT"
        echo
        
        echo "Extracted Files:"
        echo "----------------"
        
        # Count files in each directory
        for dir in http dns kerberos tcp creds meta other files; do
            if [ -d "$BASE_OUT/$dir" ]; then
                local count
                count=$(find "$BASE_OUT/$dir" -type f | wc -l)
                if [ "$count" -gt 0 ]; then
                    echo "$dir/: $count files"
                    find "$BASE_OUT/$dir" -type f | while read -r file; do
                        echo "  - $(basename "$file")"
                    done
                fi
            fi
        done
        
        echo
        
        # Intelligence summary
        echo "Intelligence Summary:"
        echo "--------------------"
        
        # HTTP intelligence
        if [ -f "$BASE_OUT/http/hosts.txt" ]; then
            local host_count
            host_count=$(sort "$BASE_OUT/http/hosts.txt" | uniq | wc -l)
            echo "HTTP: $host_count unique hosts"
        fi
        
        if [ -f "$BASE_OUT/http/post_bodies.txt" ]; then
            local post_count
            post_count=$(grep -c '^' "$BASE_OUT/http/post_bodies.txt")
            echo "HTTP: $post_count POST requests"
        fi
        
        # DNS intelligence
        if [ -f "$BASE_OUT/dns/dns_queries.txt" ]; then
            local dns_count
            dns_count=$(grep -c '^' "$BASE_OUT/dns/dns_queries.txt")
            echo "DNS: $dns_count queries"
        fi
        
        if [ -f "$BASE_OUT/dns/exfil_suspicions.txt" ]; then
            local exfil_count
            exfil_count=$(grep -c '^' "$BASE_OUT/dns/exfil_suspicions.txt")
            echo "DNS: $exfil_count exfiltration indicators"
        fi
        
        # Kerberos intelligence
        if [ -f "$BASE_OUT/kerberos/users_realms.tsv" ]; then
            local krb_user_count
            krb_user_count=$(grep -c '^' "$BASE_OUT/kerberos/users_realms.tsv")
            echo "Kerberos: $krb_user_count user/realm pairs"
        fi
        
        if [ -f "$BASE_OUT/kerberos/asrep_candidates.txt" ]; then
            local asrep_count
            asrep_count=$(grep -c '^' "$BASE_OUT/kerberos/asrep_candidates.txt")
            echo "Kerberos: $asrep_count AS-REP candidates"
        fi
        
        # TCP intelligence
        if [ -f "$BASE_OUT/tcp/ip_conversations.txt" ]; then
            echo "TCP: Top conversations"
            head -n 10 "$BASE_OUT/tcp/ip_conversations.txt" | grep -E '^[[:space:]]*[0-9]' | head -5
        fi
        
        # Credentials intelligence
        if [ -f "$BASE_OUT/creds/http_auth_headers.txt" ]; then
            local auth_count
            auth_count=$(grep -c '^' "$BASE_OUT/creds/http_auth_headers.txt")
            echo "Credentials: $auth_count HTTP auth headers"
        fi
        
        if [ -f "$BASE_OUT/creds/ftp_user_pass.tsv" ]; then
            local ftp_creds_count
            ftp_creds_count=$(grep -c '^' "$BASE_OUT/creds/ftp_user_pass.tsv")
            echo "Credentials: $ftp_creds_count FTP credentials"
        fi
        
        # Exported objects
        if [ -d "$BASE_OUT/files/http" ]; then
            local http_files_count
            http_files_count=$(find "$BASE_OUT/files/http" -type f | wc -l)
            if [ "$http_files_count" -gt 0 ]; then
                echo "Files: $http_files_count HTTP objects exported"
            fi
        fi
        
    } > "$summary_file"
    
    print_success "Saved -> $summary_file"
    log "[+] Saved -> $summary_file"
    
    # Create JSON summary if requested
    if [ "$JSON_REPORT" = true ]; then
        print_info "Generating JSON summary report..."
        log "Generating JSON summary report..."
        
        # Start JSON structure
        {
            echo "{"
            echo "  \"pcap_file\": \"$PCAP_FILE\","
            echo "  \"analysis_date\": \"$(date)\","
            echo "  \"output_directory\": \"$BASE_OUT\","
            echo "  \"extracted_files\": {"
            
            # Add file counts for each directory
            local first_dir=true
            for dir in http dns kerberos tcp creds meta other files; do
                if [ -d "$BASE_OUT/$dir" ]; then
                    local count
                    count=$(find "$BASE_OUT/$dir" -type f | wc -l)
                    if [ "$count" -gt 0 ]; then
                        if [ "$first_dir" = true ]; then
                            first_dir=false
                        else
                            echo ","
                        fi
                        echo -n "    \"$dir\": {"
                        echo -n "\"count\": $count,"
                        echo -n "\"files\": ["
                        
                        # List files
                        local first_file=true
                        find "$BASE_OUT/$dir" -type f | while read -r file; do
                            if [ "$first_file" = true ]; then
                                first_file=false
                                echo -n "\"$(basename "$file")\""
                            else
                                echo -n ", \"$(basename "$file")\""
                            fi
                        done
                        
                        echo "]"
                        echo -n "    }"
                    fi
                fi
            done
            
            echo
            echo "  },"
            echo "  \"intelligence\": {"
            
            # Add intelligence summary
            local first_item=true
            
            # HTTP intelligence
            if [ -f "$BASE_OUT/http/hosts.txt" ]; then
                local host_count
                host_count=$(sort "$BASE_OUT/http/hosts.txt" | uniq | wc -l)
                if [ "$first_item" = true ]; then
                    first_item=false
                else
                    echo ","
                fi
                echo "    \"http_unique_hosts\": $host_count"
            fi
            
            if [ -f "$BASE_OUT/http/post_bodies.txt" ]; then
                local post_count
                post_count=$(grep -c '^' "$BASE_OUT/http/post_bodies.txt")
                if [ "$first_item" = true ]; then
                    first_item=false
                else
                    echo ","
                fi
                echo "    \"http_post_requests\": $post_count"
            fi
            
            # DNS intelligence
            if [ -f "$BASE_OUT/dns/dns_queries.txt" ]; then
                local dns_count
                dns_count=$(grep -c '^' "$BASE_OUT/dns/dns_queries.txt")
                if [ "$first_item" = true ]; then
                    first_item=false
                else
                    echo ","
                fi
                echo "    \"dns_queries\": $dns_count"
            fi
            
            if [ -f "$BASE_OUT/dns/exfil_suspicions.txt" ]; then
                local exfil_count
                exfil_count=$(grep -c '^' "$BASE_OUT/dns/exfil_suspicions.txt")
                if [ "$first_item" = true ]; then
                    first_item=false
                else
                    echo ","
                fi
                echo "    \"dns_exfil_indicators\": $exfil_count"
            fi
            
            # Kerberos intelligence
            if [ -f "$BASE_OUT/kerberos/users_realms.tsv" ]; then
                local krb_user_count
                krb_user_count=$(grep -c '^' "$BASE_OUT/kerberos/users_realms.tsv")
                if [ "$first_item" = true ]; then
                    first_item=false
                else
                    echo ","
                fi
                echo "    \"kerberos_user_realm_pairs\": $krb_user_count"
            fi
            
            if [ -f "$BASE_OUT/kerberos/asrep_candidates.txt" ]; then
                local asrep_count
                asrep_count=$(grep -c '^' "$BASE_OUT/kerberos/asrep_candidates.txt")
                if [ "$first_item" = true ]; then
                    first_item=false
                else
                    echo ","
                fi
                echo "    \"kerberos_asrep_candidates\": $asrep_count"
            fi
            
            # Credentials intelligence
            if [ -f "$BASE_OUT/creds/http_auth_headers.txt" ]; then
                local auth_count
                auth_count=$(grep -c '^' "$BASE_OUT/creds/http_auth_headers.txt")
                if [ "$first_item" = true ]; then
                    first_item=false
                else
                    echo ","
                fi
                echo "    \"http_auth_headers\": $auth_count"
            fi
            
            if [ -f "$BASE_OUT/creds/ftp_user_pass.tsv" ]; then
                local ftp_creds_count
                ftp_creds_count=$(grep -c '^' "$BASE_OUT/creds/ftp_user_pass.tsv")
                if [ "$first_item" = true ]; then
                    first_item=false
                else
                    echo ","
                fi
                echo "    \"ftp_credentials\": $ftp_creds_count"
            fi
            
            # Exported objects
            if [ -d "$BASE_OUT/files/http" ]; then
                local http_files_count
                http_files_count=$(find "$BASE_OUT/files/http" -type f | wc -l)
                if [ "$http_files_count" -gt 0 ]; then
                    if [ "$first_item" = true ]; then
                        first_item=false
                    else
                        echo ","
                    fi
                    echo "    \"http_objects_exported\": $http_files_count"
                fi
            fi
            
            echo
            echo "  }"
            echo "}"
        } > "$json_file"
        
        print_success "Saved -> $json_file"
        log "[+] Saved -> $json_file"
    fi
    
    # Display summary
    echo
    cat "$summary_file"
}

# Main program
main() {
    # Print header
    print_header
    
    # Parse command line arguments
    parse_args "$@"
    
    # Check dependencies
    check_dependencies
    
    # Confirm PCAP path
    echo -e "${CYAN}PCAP file:${NC} ${BOLD}$PCAP_FILE${NC}"
    echo -e "${CYAN}Output directory:${NC} ${BOLD}$BASE_OUT${NC}"
    echo
    read -p "Continue with these settings? [Y/n] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        print_info "User cancelled operation"
        log "User cancelled operation"
        exit 0
    fi
    
    # Main menu loop
    while true; do
        show_menu
        read -p "Please select an option: " choice
        
        case "$choice" in
            1) 
                run_all_extractors
                ;;
            2) 
                run_specific_extractor
                ;;
            3) 
                handle_github_tools
                ;;
            4) 
                generate_summary
                echo
                echo "Press Enter to continue..."
                read -r
                ;;
            5) 
                print_info "Exiting..."
                log "Exiting..."
                exit 0
                ;;
            *) 
                echo -e "${RED}Invalid option, please try again.${NC}"
                ;;
        esac
    done
}

# Run main function with all arguments
main "$@"