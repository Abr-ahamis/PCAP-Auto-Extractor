# PCAP Auto Extractor

A robust, production-quality Bash tool that automates tshark extractions from PCAP files with organized output and on-demand GitHub tool integration.

## Features

- Automated extraction of various protocol data from PCAP files using tshark
- Organized output directory structure with timestamped folders
- Interactive menu system for selecting specific extractors
- On-demand cloning and execution of GitHub helper repositories
- Chained analysis capabilities (using outputs to refine later checks)
- Real-time output display during extraction
- Comprehensive summary reports (text and JSON)
- Cross-platform support (Linux, macOS, and Windows via WSL)
- Built-in dependency checker and installer
### Screenshot
![room-img3.png](https://github.com/Neo-virex/Neo-virex.github.io/blob/main/images/blogs/pcap-auto-extractor/room-img3.png)
## Requirements

### Required Dependencies

- tshark (from Wireshark)
- git
- awk, sed, grep, sort, uniq, paste, mktemp, find, xargs, tee, wc
- python3

### Optional Dependencies

- exiftool (for metadata extraction from exported files)
- file (for file type detection)
- jq (for JSON processing)
- timeout (for command timeouts)

## Installation

### Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/pcap-auto-extractor.git
   cd pcap-auto-extractor
   ```

2. Make the scripts executable:
   ```bash
   chmod +x pcap-auto-extractor.sh requirements.sh
   ```

3. Check and install dependencies:
   ```bash
   ./requirements.sh --install
   ```

4. Run the extractor:
   ```bash
   ./pcap-auto-extractor.sh <pcap-file>
   ```

### Manual Installation

#### Ubuntu/Debian

```bash
sudo apt update
sudo apt install wireshark-cli git python3
```

#### macOS

```bash
brew install wireshark git python3
```

#### Windows (WSL)

```bash
sudo apt update
sudo apt install wireshark-cli git python3
```

## Usage

### Basic Usage

```bash
./pcap-auto-extractor.sh <pcap-file>
```

### Advanced Options

```bash
./pcap-auto-extractor.sh <pcap-file> [options]
```

#### Options

- `--parallel N`: Run up to N extractors in parallel (default: 1)
- `--dry-run`: Show commands that would be executed without running them
- `--json-report`: Generate a machine-readable JSON summary report
- `--tools-root DIR`: Set the root directory for cloned tools (default: /tmp/tools)

### Examples

```bash
# Basic analysis
./pcap-auto-extractor.sh capture.pcap

# Run with 4 parallel extractors and generate JSON report
./pcap-auto-extractor.sh capture.pcap --parallel 4 --json-report

# Dry run to see what would be executed
./pcap-auto-extractor.sh capture.pcap --dry-run
```

## Output Structure

The script creates a timestamped output directory in `~/Documents/Pcap_Extracts/` with the following structure:

```
~/Documents/Pcap_Extracts/YYYYMMDD_HHMMSS/
├── logs/
│   ├── run.log          # Main execution log
│   └── errors.log       # Error log
├── files/               # Exported binary files
│   ├── http/            # HTTP objects (images, documents, etc.)
│   ├── smb/             # SMB files
│   ├── nfs/             # NFS files
│   ├── tftp/            # TFTP files
│   └── ftp/             # FTP files
├── http/                # HTTP textual outputs
│   ├── http_requests.tsv    # HTTP requests (method, host, URI)
│   ├── hosts.txt            # HTTP hosts
│   ├── post_bodies.txt      # HTTP POST bodies
│   ├── cookies.txt          # HTTP cookies
│   └── uris_<host>.txt     # URIs for specific hosts
├── dns/                 # DNS outputs
│   ├── dns_queries.txt     # DNS queries
│   ├── dns_answers.tsv     # DNS answers
│   ├── txt_records.txt     # DNS TXT records
│   ├── all_qnames.txt      # All QNames
│   └── exfil_suspicions.txt # DNS exfiltration indicators
├── kerberos/            # Kerberos outputs
│   ├── users_realms.tsv    # Kerberos users and realms
│   ├── ciphers_all.txt     # Kerberos ciphers
│   ├── asrep_candidates.txt # AS-REP candidates
│   └── krbpa2john_output.txt # Output from krbpa2john tool
├── tcp/                 # TCP outputs
│   ├── synack_srcports.txt # SYN+ACK source ports
│   ├── tcp_conversations.txt # TCP conversations
│   └── ip_conversations.txt  # IP conversations
├── creds/               # Credentials
│   ├── http_auth_headers.txt # HTTP auth headers
│   └── ftp_user_pass.tsv     # FTP credentials
├── meta/                # Metadata
│   ├── interfaces.txt       # Network interfaces
│   ├── linktypes.txt        # Link types
│   ├── io_phs.txt           # I/O stats
│   └── fields_kerberos.txt  # Kerberos fields
├── other/               # Other protocols
│   ├── ftp_commands.tsv     # FTP commands
│   └── smtp_subjects.txt    # SMTP subjects
├── tools/               # Cloned GitHub tools and outputs
│   └── <repo-name>/         # Each cloned repository
├── SUMMARY.txt          # Human-readable summary
└── summary.json         # Machine-readable summary (if requested)
```

## Menu System

The script provides an interactive menu system with the following options:

1. **Extract ALL (safe, modular)**: Run all available extractors
2. **Run a specific extractor**: Select and run a single extractor
3. **GitHub Tools**: Clone and run helper repositories
4. **Show Summary**: Display and save analysis summary
5. **Exit**: Exit the program

### Available Extractors

The script includes extractors for:

#### Meta Information
- Interface listing
- Link types
- PCAP stats
- Kerberos fields

#### HTTP
- Requests
- Hosts
- POST bodies
- Auth headers
- Cookies
- Export objects

#### DNS
- Queries
- Answers
- TXT records
- All QNames
- Exfiltration detection

#### TCP
- SYN+ACK ports
- Conversations
- IP conversations

#### Kerberos
- Users and realms
- Ciphers
- AS-REP candidates

#### Credentials
- FTP commands
- FTP credentials
- SMTP subjects

#### TLS
- JA3 fingerprints

#### Chained Analysis
- HTTP hosts analysis
- Kerberos analysis
- POST bodies analysis

## GitHub Tool Integration

The script can clone and run helper repositories on demand:

### Supported Repositories

1. **decrypt-winrm** (https://github.com/h4sh5/decrypt-winrm)
   - Decrypts WinRM traffic using server certificate and private key

2. **ctf-tools** (https://github.com/truongkma/ctf-tools)
   - Contains John the Ripper with krbpa2john.py for Kerberos cracking

3. **john** (https://github.com/openwall/john)
   - John the Ripper password cracker (bleeding-jumbo branch)

### Usage

1. Select "GitHub Tools" from the main menu
2. Choose a repository from the list
3. The script will clone the repository to `/tmp/tools/<repo-name>`
4. Follow prompts to provide required inputs
5. The tool will be executed and outputs saved to the appropriate directory

## Chained Analysis

The script performs automated follow-up analysis based on initial findings:

- If HTTP hosts are found, it extracts URIs for each unique host
- If Kerberos users and ciphers are found, it generates AS-REP candidates
- If DNS QNames are found, it performs exfiltration detection
- If HTTP POST bodies are found, it analyzes them for potential credentials

## Dependency Management

The included `requirements.sh` script helps manage dependencies:

### Checking Dependencies

```bash
./requirements.sh --check
```

### Installing Dependencies

```bash
./requirements.sh --install
```

The script automatically detects the operating system and installs the appropriate packages:

- **Debian/Ubuntu**: Uses `apt`
- **Red Hat/CentOS/Fedora**: Uses `yum`
- **Arch Linux**: Uses `pacman`
- **macOS**: Uses `Homebrew`
- **Windows**: Provides manual installation instructions

## Security Considerations

- The script validates the PCAP file path before processing
- GitHub repositories are only cloned when selected by the user
- User-provided credentials are handled securely
- All external commands are logged
- The script does not modify any system files

## Troubleshooting

### Common Issues

1. **Permission denied when running tshark**
   - On Linux, you may need to add your user to the wireshark group:
     ```bash
     sudo usermod -a -G wireshark $USER
     ```
   - Log out and log back in for changes to take effect

2. **Missing dependencies**
   - The script checks for required dependencies at startup
   - Use the `requirements.sh` script to install missing packages

3. **Large PCAP files**
   - Processing large files may take significant time
   - Consider using the `--dry-run` option to preview commands before execution

### Log Files

The script creates two log files in the output directory:

- `logs/run.log`: Main execution log with timestamps
- `logs/errors.log`: Error messages and diagnostic information

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- tshark and Wireshark for the powerful packet analysis capabilities
- The creators of the various GitHub tools integrated in this script
- The cybersecurity community for inspiration and feedback

## Support

If you encounter any issues or have questions, please file an issue on the GitHub repository.
