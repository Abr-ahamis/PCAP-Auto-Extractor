#!/bin/bash

# PCAP Auto Extractor - Advanced Terminal Automation for PCAP Analysis
# Author: AI Assistant
# Description: Automates tshark extractions from PCAP files with organized output

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
        echo "Please install missing dependencies:"
        echo "  Ubuntu/Debian: sudo apt install ${missing[*]}"
        echo "  macOS: brew install ${missing[*]}"
        exit 1
    fi
    
    if [ ${#optional_missing[@]} -gt 0 ]; then
        log "Optional dependencies not found: ${optional_missing[*]}"
        log "Some features may not work without these tools."
    fi
    
    log "All required dependencies are available."
}

# Function to display usage
show_usage() {
    echo "Usage: $0 <pcap-file> [options]"
    echo
    echo "Options:"
    echo "  --parallel N      Run up to N extractors in parallel (default: 1)"
    echo "  --dry-run         Show commands that would be executed without running them"
    echo "  --json-report     Generate a machine-readable JSON summary report"
    echo "  --tools-root DIR  Set the root directory for cloned tools (default: /tmp/tools)"
    echo
    echo "Example:"
    echo "  $0 capture.pcap"
    echo "  $0 capture.pcap --parallel 4 --json-report"
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
    
    log "Running: $cmd"
    
    if [ "$DRY_RUN" = true ]; then
        echo "[DRY RUN] Would run: $cmd > $output_file"
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
            log "[+] Saved -> $output_file"
            return 0
        else
            rm -f "$tmpfile"
            log "[!] No $description found"
            return 1
        fi
    else
        local exit_code=$?
        rm -f "$tmpfile"
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
    log "Exporting HTTP objects..."
    
    if [ "$DRY_RUN" = true ]; then
        echo "[DRY RUN] Would run: tshark -r \"$PCAP_FILE\" --export-objects http,\"$BASE_OUT/files/http\""
        return 0
    fi
    
    local count_before
    count_before=$(find "$BASE_OUT/files/http" -type f | wc -l)
    
    if tshark -r "$PCAP_FILE" --export-objects http,"$BASE_OUT/files/http" 2>/dev/null; then
        local count_after
        count_after=$(find "$BASE_OUT/files/http" -type f | wc -l)
        
        if [ "$count_after" -gt "$count_before" ]; then
            local exported=$((count_after - count_before))
            log "[+] Saved -> $exported HTTP objects to $BASE_OUT/files/http"
            return 0
        else
            log "[!] No HTTP objects found"
            return 1
        fi
    else
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
    log "Building AS-REP candidates..."
    
    if [ "$DRY_RUN" = true ]; then
        echo "[DRY RUN] Would build AS-REP candidates from Kerberos data"
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
            log "[+] Saved -> $BASE_OUT/kerberos/asrep_candidates.txt"
            return 0
        else
            rm -f "$tmpfile"
            log "[!] No Kerberos data found for AS-REP candidates"
            return 1
        fi
    else
        rm -f "$tmpfile"
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
    log "Detecting DNS exfiltration heuristics..."
    
    if [ "$DRY_RUN" = true ]; then
        echo "[DRY RUN] Would run DNS exfiltration detection"
        return 0
    fi
    
    # Check if we have DNS data
    if [ ! -f "$BASE_OUT/dns/all_qnames.txt" ]; then
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
        log "[+] Saved -> $exfil_file"
        return 0
    else
        rm -f "$exfil_file"
        log "[!] No DNS exfiltration indicators found"
        return 1
    fi
}

# Chained analysis functions
analyze_http_hosts() {
    if [ ! -f "$BASE_OUT/http/hosts.txt" ]; then
        log "[!] No HTTP hosts found, skipping detailed analysis"
        return 1
    fi
    
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
            echo "URIs for $host:"
            echo "---------------"
            sed 's/^/→ /' "$output_file"
        fi
    done
}

analyze_kerberos() {
    if [ ! -f "$BASE_OUT/kerberos/users_realms.tsv" ] || [ ! -f "$BASE_OUT/kerberos/ciphers_all.txt" ]; then
        log "[!] No Kerberos data found, skipping AS-REP analysis"
        return 1
    fi
    
    log "Analyzing Kerberos data for AS-REP candidates..."
    extract_asrep_candidates
}

analyze_post_bodies() {
    if [ ! -f "$BASE_OUT/http/post_bodies.txt" ]; then
        log "[!] No HTTP POST bodies found, skipping credential analysis"
        return 1
    fi
    
    log "Analyzing POST bodies for potential credentials..."
    
    local creds_file="$BASE_OUT/creds/post_body_creds.txt"
    touch "$creds_file"
    
    grep -iE 'password|pass|pwd' "$BASE_OUT/http/post_bodies.txt" > "$creds_file"
    
    if [ -s "$creds_file" ]; then
        log "[+] Saved -> $creds_file"
        return 0
    else
        rm -f "$creds_file"
        log "[!] No credentials found in POST bodies"
        return 1
    fi
}

# Function to run all extractors
run_all_extractors() {
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
    
    log "All extractors completed."
    
    # Ask user if they want to return to menu or exit
    echo
    read -p "Extraction complete. Return to menu? [Y/n] " ans
    if [[ "$ans" =~ ^[Nn]$ ]]; then
        log "User chose to exit after extraction"
        exit 0
    fi
}

# Function to display the main menu
show_menu() {
    echo
    echo "PCAP Auto Extractor - Main Menu"
    echo "==============================="
    echo "1. Extract ALL (safe, modular)"
    echo "2. Run a specific extractor"
    echo "3. GitHub Tools"
    echo "4. Show Summary"
    echo "5. Exit"
    echo
}

# Function to display the extractor menu
show_extractor_menu() {
    echo
    echo "Select an extractor to run:"
    echo "==========================="
    echo "1. Meta - Interface listing"
    echo "2. Meta - Link types"
    echo "3. Meta - PCAP stats"
    echo "4. Meta - Kerberos fields"
    echo "5. HTTP - Requests"
    echo "6. HTTP - Hosts"
    echo "7. HTTP - POST bodies"
    echo "8. HTTP - Auth headers"
    echo "9. HTTP - Cookies"
    echo "10. HTTP - Export objects"
    echo "11. DNS - Queries"
    echo "12. DNS - Answers"
    echo "13. DNS - TXT records"
    echo "14. DNS - All QNames"
    echo "15. TCP - SYN+ACK ports"
    echo "16. TCP - Conversations"
    echo "17. TCP - IP conversations"
    echo "18. Kerberos - Users and realms"
    echo "19. Kerberos - Ciphers"
    echo "20. Kerberos - AS-REP candidates"
    echo "21. Credentials - FTP commands"
    echo "22. Credentials - FTP credentials"
    echo "23. Credentials - SMTP subjects"
    echo "24. TLS - JA3 fingerprints"
    echo "25. DNS - Exfiltration detection"
    echo "26. Chained - HTTP hosts analysis"
    echo "27. Chained - Kerberos analysis"
    echo "28. Chained - POST bodies analysis"
    echo "29. Back to main menu"
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
            *) echo "Invalid option, please try again." ;;
        esac
        
        echo
        echo "Press Enter to continue..."
        read -r
    done
}

# Function to show GitHub tools menu
show_github_menu() {
    echo
    echo "GitHub Tools Menu"
    echo "================="
    
    local i=1
    for repo in "${!REPOS[@]}"; do
        echo "$i. $repo (${REPOS[$repo]})"
        ((i++))
    done
    
    echo "$i. Back to main menu"
    echo
}

# Function to clone and run a GitHub tool
clone_and_run_tool() {
    local repo_name="$1"
    local repo_url="${REPOS[$repo_name]}"
    
    log "Cloning $repo_name..."
    
    if [ "$DRY_RUN" = true ]; then
        echo "[DRY RUN] Would clone $repo_url to $TOOLS_ROOT/$repo_name"
        return 0
    fi
    
    # Create tools directory if it doesn't exist
    mkdir -p "$TOOLS_ROOT"
    
    # Clone the repository
    if git clone --depth 1 "$repo_url" "$TOOLS_ROOT/$repo_name"; then
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
            log "[!] No specific handler for $repo_name"
        fi
    else
        log_error "Failed to clone $repo_name"
        return 1
    fi
}

# Function to run krbpa2john tool
run_krbpa2john_tool() {
    local repo_name="$1"
    local tool_out="$2"
    
    log "Running krbpa2john tool..."
    
    # Check if AS-REP candidates exist
    if [ ! -f "$BASE_OUT/kerberos/asrep_candidates.txt" ]; then
        log "[!] No AS-REP candidates found. Run Kerberos extractors first."
        return 1
    fi
    
    # Find the krbpa2john.py script
    local script_path=""
    if [ -f "$TOOLS_ROOT/$repo_name/run/krbpa2john.py" ]; then
        script_path="$TOOLS_ROOT/$repo_name/run/krbpa2john.py"
    elif [ -f "$TOOLS_ROOT/$repo_name/krbpa2john.py" ]; then
        script_path="$TOOLS_ROOT/$repo_name/krbpa2john.py"
    else
        log_error "krbpa2john.py not found in $TOOLS_ROOT/$repo_name"
        return 1
    fi
    
    # Run the script
    local output_file="$tool_out/krbpa2john_output.txt"
    log "Running: python3 \"$script_path\" \"$BASE_OUT/kerberos/asrep_candidates.txt\""
    
    if python3 "$script_path" "$BASE_OUT/kerberos/asrep_candidates.txt" > "$output_file" 2>> "$BASE_OUT/logs/errors.log"; then
        if [ -s "$output_file" ]; then
            log "[+] Saved -> $output_file"
            
            # Also copy to kerberos directory for convenience
            cp "$output_file" "$BASE_OUT/kerberos/krbpa2john_output.txt"
            log "[+] Also saved -> $BASE_OUT/kerberos/krbpa2john_output.txt"
            
            return 0
        else
            log "[!] No output from krbpa2john.py"
            return 1
        fi
    else
        log_error "Failed to run krbpa2john.py"
        return 1
    fi
}

# Function to run decrypt-winrm tool
run_decrypt_winrm_tool() {
    local repo_name="$1"
    local tool_out="$2"
    
    log "Running decrypt-winrm tool..."
    
    # Check if the script exists
    local script_path=""
    if [ -f "$TOOLS_ROOT/$repo_name/Decrypt-WinRM.ps1" ]; then
        script_path="$TOOLS_ROOT/$repo_name/Decrypt-WinRM.ps1"
    else
        log_error "Decrypt-WinRM.ps1 not found in $TOOLS_ROOT/$repo_name"
        return 1
    fi
    
    # This is a PowerShell script, so we need to check if we're on Windows or have PowerShell available
    if ! command -v powershell >/dev/null 2>&1 && ! command -v pwsh >/dev/null 2>&1; then
        log_error "PowerShell not available. Cannot run decrypt-winrm tool."
        return 1
    fi
    
    # Prompt user for required inputs
    echo "Decrypt-WinRM requires the following inputs:"
    echo "1. Path to the encrypted WinRM traffic file (PCAP)"
    echo "2. Path to the server's certificate file (PEM format)"
    echo "3. Path to the server's private key file (PEM format)"
    echo
    
    local cert_file=""
    local key_file=""
    
    read -p "Enter path to server certificate file: " cert_file
    read -p "Enter path to server private key file: " key_file
    
    # Validate inputs
    if [ ! -f "$cert_file" ]; then
        log_error "Certificate file not found: $cert_file"
        return 1
    fi
    
    if [ ! -f "$key_file" ]; then
        log_error "Private key file not found: $key_file"
        return 1
    fi
    
    # Run the script
    local output_file="$tool_out/decrypt_winrm_output.txt"
    local ps_command="& '$script_path' -PcapFile '$PCAP_FILE' -CertFile '$cert_file' -KeyFile '$key_file'"
    
    log "Running: $ps_command"
    
    if command -v powershell >/dev/null 2>&1; then
        if powershell -Command "$ps_command" > "$output_file" 2>> "$BASE_OUT/logs/errors.log"; then
            if [ -s "$output_file" ]; then
                log "[+] Saved -> $output_file"
                return 0
            else
                log "[!] No output from Decrypt-WinRM.ps1"
                return 1
            fi
        else
            log_error "Failed to run Decrypt-WinRM.ps1"
            return 1
        fi
    elif command -v pwsh >/dev/null 2>&1; then
        if pwsh -Command "$ps_command" > "$output_file" 2>> "$BASE_OUT/logs/errors.log"; then
            if [ -s "$output_file" ]; then
                log "[+] Saved -> $output_file"
                return 0
            else
                log "[!] No output from Decrypt-WinRM.ps1"
                return 1
            fi
        else
            log_error "Failed to run Decrypt-WinRM.ps1"
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
            echo "Invalid option, please try again."
        fi
        
        echo
        echo "Press Enter to continue..."
        read -r
    done
}

# Function to generate summary report
generate_summary() {
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
    
    log "[+] Saved -> $summary_file"
    
    # Create JSON summary if requested
    if [ "$JSON_REPORT" = true ]; then
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
        
        log "[+] Saved -> $json_file"
    fi
    
    # Display summary
    echo
    cat "$summary_file"
}

# Main program
main() {
    # Parse command line arguments
    parse_args "$@"
    
    # Check dependencies
    check_dependencies
    
    # Confirm PCAP path
    echo "PCAP file: $PCAP_FILE"
    echo "Output directory: $BASE_OUT"
    echo
    read -p "Continue with these settings? [Y/n] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
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
                log "Exiting..."
                exit 0
                ;;
            *) 
                echo "Invalid option, please try again."
                ;;
        esac
    done
}

# Run main function with all arguments
main "$@"