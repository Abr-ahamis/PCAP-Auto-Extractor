#!/bin/bash
# PCAP Auto Extractor - Requirements Checker and Installer
# This script checks for required dependencies and offers to install them

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to detect the operating system
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/debian_version ]; then
            echo "debian"
        elif [ -f /etc/redhat-release ]; then
            echo "redhat"
        elif [ -f /etc/arch-release ]; then
            echo "arch"
        elif [ -f /etc/SuSE-release ]; then
            echo "suse"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        echo "windows"
    else
        echo "unknown"
    fi
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check dependencies
check_dependencies() {
    print_status "Checking dependencies..."
    
    # Required dependencies
    REQUIRED_DEPS=(
        "tshark"
        "git"
        "awk"
        "sed"
        "grep"
        "sort"
        "uniq"
        "paste"
        "mktemp"
        "find"
        "xargs"
        "tee"
        "wc"
        "python3"
    )
    
    # Optional dependencies
    OPTIONAL_DEPS=(
        "exiftool"
        "file"
        "jq"
        "timeout"
    )
    
    # Check required dependencies
    MISSING_REQUIRED=()
    for dep in "${REQUIRED_DEPS[@]}"; do
        if command_exists "$dep"; then
            print_success "$dep is installed"
        else
            print_error "$dep is missing"
            MISSING_REQUIRED+=("$dep")
        fi
    done
    
    # Check optional dependencies
    MISSING_OPTIONAL=()
    for dep in "${OPTIONAL_DEPS[@]}"; do
        if command_exists "$dep"; then
            print_success "$dep is installed"
        else
            print_warning "$dep is missing (optional)"
            MISSING_OPTIONAL+=("$dep")
        fi
    done
    
    # Return status
    if [ ${#MISSING_REQUIRED[@]} -eq 0 ]; then
        print_success "All required dependencies are installed"
        return 0
    else
        print_error "Missing required dependencies: ${MISSING_REQUIRED[*]}"
        return 1
    fi
}

# Function to install dependencies on Debian/Ubuntu
install_debian() {
    print_status "Installing dependencies on Debian/Ubuntu..."
    
    # Update package lists
    print_status "Updating package lists..."
    sudo apt update || {
        print_error "Failed to update package lists"
        return 1
    }
    
    # Install required dependencies
    print_status "Installing required dependencies..."
    sudo apt install -y tshark git python3 || {
        print_error "Failed to install required dependencies"
        return 1
    }
    
    # Install optional dependencies
    print_status "Installing optional dependencies..."
    sudo apt install -y exiftool file jq timeout || {
        print_warning "Some optional dependencies could not be installed"
    }
    
    print_success "Dependencies installed successfully"
}

# Function to install dependencies on Red Hat/CentOS/Fedora
install_redhat() {
    print_status "Installing dependencies on Red Hat-based system..."
    
    # Install required dependencies
    print_status "Installing required dependencies..."
    sudo yum install -y wireshark git python3 || {
        print_error "Failed to install required dependencies"
        return 1
    }
    
    # Install optional dependencies
    print_status "Installing optional dependencies..."
    sudo yum install -y libexif util-linux jq || {
        print_warning "Some optional dependencies could not be installed"
    }
    
    print_success "Dependencies installed successfully"
}

# Function to install dependencies on Arch Linux
install_arch() {
    print_status "Installing dependencies on Arch Linux..."
    
    # Update package lists
    print_status "Updating package lists..."
    sudo pacman -Syu --noconfirm || {
        print_error "Failed to update package lists"
        return 1
    }
    
    # Install required dependencies
    print_status "Installing required dependencies..."
    sudo pacman -S --noconfirm wireshark-cli git python3 || {
        print_error "Failed to install required dependencies"
        return 1
    }
    
    # Install optional dependencies
    print_status "Installing optional dependencies..."
    sudo pacman -S --noconfirm exiftool file jq || {
        print_warning "Some optional dependencies could not be installed"
    }
    
    print_success "Dependencies installed successfully"
}

# Function to install dependencies on macOS
install_macos() {
    print_status "Installing dependencies on macOS..."
    
    # Check if Homebrew is installed
    if ! command_exists brew; then
        print_error "Homebrew not found. Please install Homebrew first: https://brew.sh/"
        return 1
    fi
    
    # Install required dependencies
    print_status "Installing required dependencies..."
    brew install wireshark git python3 || {
        print_error "Failed to install required dependencies"
        return 1
    }
    
    # Install optional dependencies
    print_status "Installing optional dependencies..."
    brew install exiftool file-formula jq || {
        print_warning "Some optional dependencies could not be installed"
    }
    
    print_success "Dependencies installed successfully"
}

# Function to show instructions for Windows
show_windows_instructions() {
    print_error "Automatic installation is not supported on Windows"
    echo
    echo "Please install the following dependencies manually:"
    echo "1. Wireshark (includes tshark): https://www.wireshark.org/download.html"
    echo "2. Git for Windows: https://git-scm.com/download/win"
    echo "3. Python: https://www.python.org/downloads/"
    echo ""
    echo "After installation, make sure all are added to your PATH."
    echo ""
    echo "For optional dependencies:"
    echo "- ExifTool: https://exiftool.org/"
    echo "- jq: https://stedolan.github.io/jq/download/"
}

# Function to show instructions for other systems
show_generic_instructions() {
    print_error "Automatic installation is not supported on this system"
    echo
    echo "Please install the following dependencies manually:"
    echo "- tshark (from Wireshark)"
    echo "- git"
    echo "- python3"
    echo "- awk, sed, grep, sort, uniq, paste, mktemp, find, xargs, tee, wc"
    echo ""
    echo "For optional dependencies:"
    echo "- exiftool"
    echo "- file"
    echo "- jq"
    echo "- timeout"
}

# Function to install dependencies based on OS
install_dependencies() {
    local os
    os=$(detect_os)
    
    print_status "Detected OS: $os"
    
    case "$os" in
        "debian")
            install_debian
            ;;
        "redhat")
            install_redhat
            ;;
        "arch")
            install_arch
            ;;
        "suse")
            print_status "Installing dependencies on SUSE..."
            sudo zypper install -y wireshark git python3 || {
                print_error "Failed to install dependencies"
                return 1
            }
            print_success "Dependencies installed successfully"
            ;;
        "macos")
            install_macos
            ;;
        "windows")
            show_windows_instructions
            return 1
            ;;
        *)
            show_generic_instructions
            return 1
            ;;
    esac
    
    # Check if installation was successful
    if check_dependencies; then
        print_success "All dependencies are now installed"
        return 0
    else
        print_error "Some dependencies are still missing"
        return 1
    fi
}

# Function to show usage
show_usage() {
    echo "PCAP Auto Extractor - Requirements Checker"
    echo "=========================================="
    echo
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  -c, --check     Only check dependencies, don't install"
    echo "  -i, --install   Install missing dependencies"
    echo "  -h, --help      Show this help message"
    echo
    echo "Examples:"
    echo "  $0 --check     # Check if dependencies are installed"
    echo "  $0 --install   # Install missing dependencies"
}

# Main function
main() {
    # Parse command line arguments
    local check_only=false
    local install_deps=false
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -c|--check)
                check_only=true
                shift
                ;;
            -i|--install)
                install_deps=true
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # If no arguments provided, default to check only
    if [[ "$check_only" == false && "$install_deps" == false ]]; then
        check_only=true
    fi
    
    # Check dependencies
    if check_dependencies; then
        print_success "All dependencies are satisfied"
        exit 0
    elif [[ "$check_only" == true ]]; then
        exit 1
    fi
    
    # Install dependencies if requested
    if [[ "$install_deps" == true ]]; then
        echo
        print_status "Some dependencies are missing. Attempting to install them..."
        
        # Ask for confirmation
        echo
        read -p "Do you want to install the missing dependencies? [Y/n] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Nn]$ ]]; then
            print_status "Installation cancelled"
            exit 1
        fi
        
        # Install dependencies
        if install_dependencies; then
            print_success "Dependencies installed successfully"
            exit 0
        else
            print_error "Failed to install dependencies"
            exit 1
        fi
    fi
}

# Run main function
main "$@"