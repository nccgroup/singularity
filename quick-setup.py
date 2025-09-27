#!/usr/bin/env python3
"""
Quick setup script for Singularity of Origin DNS rebinding framework.
Automates the setup process from: https://github.com/nccgroup/singularity/wiki/Setup-and-Installation

Usage: python3 quick-setup.py <domain> [--service] [--force]
Examples: 
  python3 quick-setup.py yourdomain.com
  python3 quick-setup.py yourdomain.com --service
  python3 quick-setup.py yourdomain.com --service --force
"""

import os
import sys
import subprocess
import platform
import json
import shutil
import argparse
from pathlib import Path

def run_command(cmd, check=True, shell=False, cwd=None):
    """Run a command and return the result."""
    print(f"Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    if cwd:
        print(f"  Working directory: {cwd}")
    try:
        result = subprocess.run(cmd, check=check, shell=shell, capture_output=True, text=True, cwd=cwd)
        if result.stdout:
            print(result.stdout)
        return result
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {e}")
        if e.stderr:
            print(f"Error output: {e.stderr}")
        sys.exit(1)

def check_go_installed():
    """Check if Go is already installed."""
    try:
        result = run_command(["go", "version"], check=False)
        if result.returncode == 0:
            print(f"Go is already installed: {result.stdout.strip()}")
            return True
    except FileNotFoundError:
        pass
    return False

def install_go():
    """Install Go 1.23+ based on the platform."""
    if check_go_installed():
        return
    
    system = platform.system().lower()
    arch = platform.machine().lower()
    
    # Map architecture names
    if arch in ['x86_64', 'amd64']:
        arch = 'amd64'
    elif arch in ['aarch64', 'arm64']:
        arch = 'arm64'
    elif arch in ['i386', 'i686']:
        arch = '386'
    
    go_version = "1.23.4"  # Use a recent stable version
    go_tar = f"go{go_version}.{system}-{arch}.tar.gz"
    go_url = f"https://go.dev/dl/{go_tar}"
    
    print(f"Installing Go {go_version} for {system}-{arch}")
    
    # Download Go
    run_command(["curl", "-L", "-o", go_tar, go_url])
    
    # Remove old Go installation if it exists
    go_path = "/usr/local/go"
    if os.path.exists(go_path):
        print("Removing existing Go installation...")
        run_command(["sudo", "rm", "-rf", go_path])
    
    # Extract Go
    run_command(["sudo", "tar", "-C", "/usr/local", "-xzf", go_tar])
    
    # Clean up
    os.remove(go_tar)
    
    # Add Go to PATH in current session
    os.environ["PATH"] = "/usr/local/go/bin:" + os.environ["PATH"]
    
    print("Go installation completed!")
    print("Note: You may need to add /usr/local/go/bin to your PATH in ~/.bashrc or ~/.zshrc")

def get_public_ip():
    """Get the public IPv4 address of the current machine."""
    try:
        result = run_command(["curl", "-4", "-s", "ifconfig.me"])
        ip = result.stdout.strip()
        if is_valid_ipv4(ip):
            return ip
    except:
        pass
    
    try:
        result = run_command(["curl", "-4", "-s", "ipinfo.io/ip"])
        ip = result.stdout.strip()
        if is_valid_ipv4(ip):
            return ip
    except:
        pass
    
    try:
        result = run_command(["curl", "-4", "-s", "icanhazip.com"])
        ip = result.stdout.strip()
        if is_valid_ipv4(ip):
            return ip
    except:
        pass
    
    print("Warning: Could not determine public IPv4 address")
    return "YOUR_PUBLIC_IP"

def is_valid_ipv4(ip):
    """Check if the given string is a valid IPv4 address."""
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit() or not 0 <= int(part) <= 255:
                return False
        return True
    except:
        return False

def update_manager_config(domain, public_ip=None):
    """Update manager-config.json with the provided domain and public IP."""
    config_path = Path("html/manager-config.json")
    
    if not config_path.exists():
        print(f"Error: {config_path} not found. Make sure you're in the singularity root directory.")
        sys.exit(1)
    
    # Read current config
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    # Get public IP if not provided
    if public_ip is None:
        public_ip = get_public_ip()

    attack_host_domain = f"dynamic.{domain}"
    
    # Update configuration
    config["attackHostDomain"] = attack_host_domain
    config["attackHostIPAddress"] = public_ip
    
    # Write updated config
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=4)
    
    print(f"Updated manager-config.json:")
    print(f"  Attack Host Domain: {attack_host_domain}")
    print(f"  Attack Host IP: {public_ip}")

def compile_singularity():
    """Compile the singularity-server binary."""
    print("Compiling singularity-server...")
    
    # Change to the server directory
    server_dir = Path("cmd/singularity-server")
    if not server_dir.exists():
        print(f"Error: {server_dir} not found. Make sure you're in the singularity root directory.")
        sys.exit(1)
    
    # Build the binary
    run_command(["go", "build", "-o", "singularity-server"], cwd=server_dir)
    
    # Move binary to root directory
    binary_src = server_dir / "singularity-server"
    binary_dst = Path("singularity-server")
    
    if binary_src.exists():
        shutil.move(str(binary_src), str(binary_dst))
        print("Compilation completed! singularity-server binary is ready.")
    else:
        print("Error: Compilation failed - binary not found")
        sys.exit(1)

def setup_directories():
    """Set up the required directory structure."""
    print("Setting up directory structure...")
    
    # Create singularity directory structure
    os.makedirs("html", exist_ok=True)
    
    # The html directory should already exist with the web files
    if not Path("html/manager.html").exists():
        print("Warning: HTML files not found in html/ directory")
        print("Make sure you've cloned the repository completely")

def check_and_fix_systemd_resolved():
    """Check for systemd-resolved conflict and fix it automatically."""
    print("Checking for systemd-resolved conflicts...")
    
    try:
        # Check if systemd-resolved is running
        result = run_command(["systemctl", "is-active", "systemd-resolved"], check=False)
        if result.returncode == 0 and "active" in result.stdout:
            print("systemd-resolved is active and may conflict with Singularity on port 53")
            print("Disabling systemd-resolved...")
            
            # Disable systemd-resolved
            run_command(["sudo", "systemctl", "disable", "--now", "systemd-resolved.service"])
            print("systemd-resolved disabled successfully")
            
            # Backup original resolv.conf
            resolv_conf = "/etc/resolv.conf"
            if os.path.exists(resolv_conf):
                run_command(["sudo", "cp", resolv_conf, f"{resolv_conf}.backup"])
                print(f"Backed up original resolv.conf to {resolv_conf}.backup")
            
            # Update resolv.conf to use a public DNS server
            # Try to detect if we're on a cloud provider first
            cloud_dns = detect_cloud_dns()
            dns_server = cloud_dns if cloud_dns else "8.8.8.8"
            
            print(f"Updating /etc/resolv.conf to use DNS server: {dns_server}")
            resolv_content = f"""# Generated by Singularity quick-setup.py
# Original backed up to resolv.conf.backup
nameserver {dns_server}
nameserver 1.1.1.1
"""
            
            # Write new resolv.conf
            with open("/tmp/resolv.conf.new", "w") as f:
                f.write(resolv_content)
            
            run_command(["sudo", "mv", "/tmp/resolv.conf.new", resolv_conf])
            run_command(["sudo", "chmod", "644", resolv_conf])
            print("resolv.conf updated successfully")
            
        else:
            print("systemd-resolved is not active - no conflicts detected")
            
    except Exception as e:
        print(f"Warning: Could not check/fix systemd-resolved: {e}")
        print("You may need to manually disable systemd-resolved if Singularity fails to start")

def detect_cloud_dns():
    """Detect if we're on a cloud provider and return appropriate DNS server."""
    try:
        # Check for cloud metadata services
        cloud_indicators = [
            ("/sys/class/dmi/id/product_name", ["Google Compute Engine", "Amazon EC2", "Microsoft Corporation"]),
            ("/sys/class/dmi/id/sys_vendor", ["Google", "Amazon", "Microsoft Corporation"]),
        ]
        
        for file_path, indicators in cloud_indicators:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    content = f.read().strip()
                    for indicator in indicators:
                        if indicator.lower() in content.lower():
                            if "google" in indicator.lower():
                                return "169.254.169.254"  # GCP metadata server
                            elif "amazon" in indicator.lower():
                                return "169.254.169.253"  # AWS metadata server
                            elif "microsoft" in indicator.lower():
                                return "168.63.129.16"    # Azure metadata server
        
        # Check for cloud-specific files
        if os.path.exists("/etc/cloud"):
            # Generic cloud environment, use a reliable public DNS
            return "8.8.8.8"
            
    except Exception:
        pass
    
    return None

def check_ports():
    """Check if required ports are available."""
    print("Checking required ports...")
    
    required_ports = [53, 8080]  # DNS and HTTP manager
    
    for port in required_ports:
        try:
            # Check if port is in use
            result = run_command(["netstat", "-tuln"], check=False)
            if f":{port}" in result.stdout:
                print(f"Warning: Port {port} appears to be in use")
                if port == 53:
                    print("  This may prevent Singularity from starting")
                    print("  The script has already attempted to fix systemd-resolved conflicts")
        except:
            pass

def print_dns_instructions(domain, public_ip):
    """Print DNS configuration instructions."""

    print("\n" + "="*60)
    print("DNS CONFIGURATION REQUIRED")
    print("="*60)
    print(f"Configure these DNS records for your domain '{domain}':")
    print()
    print("1. A Record:")
    print(f"   Name: rebinder.{domain}")
    print(f"   IPv4: {public_ip}")
    print()
    print("2. NS Record:")
    print(f"   Name: dynamic.{domain}")
    print(f"   Hostname: rebinder.{domain}.")
    print("   (Note the trailing dot is required)")
    print()
    print("Optional - for Hook and Control payload:")
    print("3. Wildcard A Record:")
    print(f"   Name: *.{domain}")
    print(f"   IPv4: {public_ip}")
    print()
    print("="*60)

def create_systemd_service(working_directory, http_port=8080):
    """Create a systemd service file for Singularity."""
    print("Creating systemd service file...")
    
    # Check if systemd is available
    try:
        result = run_command(["systemctl", "--version"], check=False)
        if result.returncode != 0:
            print("Warning: systemd not available, skipping service file creation")
            return False
    except:
        print("Warning: systemd not available, skipping service file creation")
        return False
    
    # Create service file content
    service_content = f"""[Unit]
Description=Singularity of Origin DNS Rebinding Framework
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=1
User=root
Group=root

WorkingDirectory={working_directory}
ExecStart={working_directory}/singularity-server --HTTPServerPort {http_port}

[Install]
WantedBy=multi-user.target
"""
    
    # Write service file
    service_file = "/etc/systemd/system/singularity.service"
    temp_service_file = "/tmp/singularity.service"
    
    try:
        with open(temp_service_file, 'w') as f:
            f.write(service_content)
        
        # Move to systemd directory
        run_command(["sudo", "mv", temp_service_file, service_file])
        run_command(["sudo", "chmod", "644", service_file])
        
        # Reload systemd and enable service
        run_command(["sudo", "systemctl", "daemon-reload"])
        run_command(["sudo", "systemctl", "enable", "singularity.service"])
        
        print(f"Service file created: {service_file}")
        print("Service enabled and ready to start")
        print("To start the service: sudo systemctl start singularity")
        print("To check status: sudo systemctl status singularity")
        return True
        
    except Exception as e:
        print(f"Error creating service file: {e}")
        return False

def print_usage_instructions(create_service=False):
    """Print usage instructions."""
    print("\n" + "="*60)
    print("USAGE INSTRUCTIONS")
    print("="*60)
    
    if create_service:
        print("1. Start Singularity (using systemd):")
        print("   sudo systemctl start singularity")
        print("   # OR start manually:")
        print("   sudo ./singularity-server --HTTPServerPort 8080")
    else:
        print("1. Start Singularity:")
        print("   sudo ./singularity-server --HTTPServerPort 8080")
    
    print()
    print("2. Access the manager:")
    print("   http://rebinder.<your-domain>:8080/manager.html")
    print()
    print("3. Test with a local service:")
    print("   python3 -c \"import http.server; http.server.HTTPServer(('127.0.0.1', 8080), http.server.SimpleHTTPRequestHandler).serve_forever()\"")
    print()
    print("4. In the manager, set:")
    print("   - Attack Host Domain: dynamic.<your-domain>")
    print("   - Target Port: 8080")
    print("   - Attack Payload: Simple Fetch Get")
    print()
    if create_service:
        print("5. Service management:")
        print("   - Check status: sudo systemctl status singularity")
        print("   - Stop service: sudo systemctl stop singularity")
        print("   - Restart service: sudo systemctl restart singularity")
        print("   - View logs: sudo journalctl -u singularity -f")
        print()
    print("="*60)

def main():
    parser = argparse.ArgumentParser(
        description="Quick setup script for Singularity of Origin DNS rebinding framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 quick-setup.py yourdomain.com
  python3 quick-setup.py yourdomain.com --service
  python3 quick-setup.py yourdomain.com --service --force
        """
    )
    
    parser.add_argument('domain', help='Domain for Singularity setup (e.g., dynamic.yourdomain.com)')
    parser.add_argument('--service', action='store_true', 
                       help='Create a systemd service file for automatic startup')
    parser.add_argument('--force', action='store_true',
                       help='Override domain validation checks')
    
    args = parser.parse_args()
    
    domain = args.domain
    create_service = args.service
    force = args.force
    
    print("Singularity of Origin - Quick Setup")
    print("="*40)

    if not force and domain.startswith(("dynamic.", "d.", "rebinder.", "r.")):
        print("Error: Domain should probably not start with dynamic. or d. or rebinder. or r.")
        print("Just provide the top level domain, and the script will add the dynamic. and rebinder. prefix for you.")
        print("Are you sure you're using the correct domain?")
        print("If this is intentional, override the check by adding the --force flag")
        sys.exit(1)

    print(f"Setting up for domain: {domain}")
    print()
    
    # Check if we're in the right directory
    if not Path("cmd/singularity-server/main.go").exists():
        print("Error: Not in the singularity root directory")
        print("Please run this script from the root of the cloned repository")
        sys.exit(1)
    
    # Step 1: Install Go
    install_go()
    
    # Step 2: Set up directories
    setup_directories()

    public_ip = get_public_ip()
    print(f"Public IP: {public_ip}")
    
    # Step 3: Update configuration
    update_manager_config(domain, public_ip)
    
    # Step 4: Fix systemd-resolved conflicts
    check_and_fix_systemd_resolved()
    
    # Step 5: Compile singularity
    compile_singularity()
    
    # Step 6: Check ports
    check_ports()
    
    # Step 7: Create systemd service (if requested)
    service_created = False
    if create_service:
        working_directory = os.getcwd()
        service_created = create_systemd_service(working_directory)
    
    # Step 8: Print DNS instructions
    print_dns_instructions(domain, public_ip)
    
    # Step 9: Print usage instructions
    print_usage_instructions(service_created)
    
    print("\nSetup completed! Remember to configure your DNS records before using Singularity!")

if __name__ == "__main__":
    main()
