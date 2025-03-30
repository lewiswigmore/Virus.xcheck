"""

██╗   ██╗██╗██████╗ ██╗   ██╗███████╗   ██╗  ██╗ ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
██║   ██║██║██╔══██╗██║   ██║██╔════╝   ╚██╗██╔╝██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
██║   ██║██║██████╔╝██║   ██║███████╗    ╚███╔╝ ██║     ███████║█████╗  ██║     █████╔╝ 
╚██╗ ██╔╝██║██╔══██╗██║   ██║╚════██║    ██╔██╗ ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ 
 ╚████╔╝ ██║██║  ██║╚██████╔╝███████║██╗██╔╝ ██╗╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
  ╚═══╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝
                                                                                        
"""

# Suppress all Python warnings and informational messages
import os
import sys
import warnings

# Completely disable warnings and redirect stderr before importing other modules
warnings.filterwarnings("ignore")
# Create a null device to suppress stderr
original_stderr = sys.stderr
null_device = open(os.devnull, 'w')
sys.stderr = null_device

# Now import the rest of the modules
import csv
import requests
import argparse
import json
import re
import concurrent.futures
import colorama
from colorama import Fore, Back, Style
from tqdm import tqdm
from ratelimit import limits, sleep_and_retry
from pathlib import Path
from datetime import datetime
from tabulate import tabulate
from dotenv import load_dotenv

# Initialize colorama for cross-platform colored terminal text
colorama.init(autoreset=True)

# Configuration settings
API_BASE_URL = "https://virus.exchange/api"

# Load environment variables from .env file
load_dotenv()

# Get API key from environment variables or command line
DEFAULT_API_KEY = os.getenv("VIRUSXCHECK_API_KEY", "")

def read_csv(file_path):
    """Read hashes from a CSV file"""
    hashes = []
    hex_pattern = re.compile(r'\b[a-fA-F0-9]{64}\b')  # Regex pattern for SHA256
    try:
        with open(file_path, mode='r', newline='', encoding='utf-8') as file:
            reader = csv.reader(file)
            for row in reader:
                for value in row:
                    match = hex_pattern.search(value)
                    if match:
                        hashes.append(match.group())
        return hashes
    except FileNotFoundError:
        print(f"{Fore.RED}Error: File not found - {file_path}{Style.RESET_ALL}")
        exit(1)
    except Exception as e:
        print(f"{Fore.RED}An error occurred while reading the file: {e}{Style.RESET_ALL}")
        exit(1)

class VirusExchangeAPI:
    def __init__(self, api_key):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {api_key}"})
    
    @sleep_and_retry
    @limits(calls=15, period=1)
    def get_sample_details(self, sha256_hash):
        """Get sample details using the Virus.Exchange API"""
        url = f"{API_BASE_URL}/samples/{sha256_hash}"
        try:
            response = self.session.get(url)
            if response.status_code == 200:
                return {
                    "status": "Found in VX database",
                    "details": response.json(),
                    "virustotal_url": f"https://www.virustotal.com/gui/file/{sha256_hash}"
                }
            elif response.status_code == 404:
                return {
                    "status": "Not found in VX database", 
                    "virustotal_url": f"https://www.virustotal.com/gui/file/{sha256_hash}"
                }
            else:
                return {
                    "status": f"Error: HTTP {response.status_code}",
                    "virustotal_url": f"https://www.virustotal.com/gui/file/{sha256_hash}"
                }
        except requests.RequestException as e:
            return {
                "status": f"Request Error: {e}",
                "virustotal_url": f"https://www.virustotal.com/gui/file/{sha256_hash}"
            }
    
    def fallback_check(self, sha256_hash):
        """Fallback to the old method if API fails"""
        vx_url = f"https://s3.us-east-1.wasabisys.com/vxugmwdb/{sha256_hash}"
        virustotal_url = f"https://www.virustotal.com/gui/file/{sha256_hash}"
        
        try:
            response = self.session.head(vx_url)
            if response.status_code == 200:
                return {
                    "status": "Found in VX database (fallback check)",
                    "vx_url": vx_url,
                    "virustotal_url": virustotal_url
                }
            elif response.status_code == 404:
                return {
                    "status": "Not found in VX database",
                    "virustotal_url": virustotal_url
                }
            else:
                return {
                    "status": f"Error: HTTP {response.status_code}",
                    "vx_url": None,
                    "virustotal_url": virustotal_url
                }
        except requests.RequestException as e:
            return {
                "status": f"Request Error: {e}",
                "virustotal_url": virustotal_url
            }

def check_hash(hash_value, api):
    """Check a hash using the Virus.Exchange API with fallback"""
    # Validate hash length and type
    if len(hash_value) == 64:  # SHA-256
        try:
            result = api.get_sample_details(hash_value)
            # If API fails, try fallback method
            if "Error" in result["status"]:
                return api.fallback_check(hash_value)
            return result
        except Exception as e:
            # If any exception occurs, use fallback
            return api.fallback_check(hash_value)
    
    # For other hash types (MD5, SHA-1, SHA-512)
    elif len(hash_value) in [32, 40, 128]:  # MD5, SHA-1, or SHA-512 (assuming 128 for SHA-512)
        virustotal_url = f"https://www.virustotal.com/gui/file/{hash_value}"
        return {"status": "Hash type not supported in VX database", "vx_url": None, "virustotal_url": virustotal_url}
    
    # If hash length doesn't match known formats
    else:
        return {"status": "Invalid hash length", "vx_url": None, "virustotal_url": None}

def write_to_csv(file_path, data):
    """Write results to a CSV file with enhanced metadata"""
    with open(file_path, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        # Enhanced headers for more metadata
        writer.writerow([
            'Hash', 'VX Status', 'File Type', 'Size', 'First Seen', 
            'Names', 'VX URL', 'Download Link', 'VirusTotal URL'
        ])
        
        for hash_value, details in data.items():
            # Extract detailed information if available
            file_type = details.get('details', {}).get('type', 'N/A')
            size = details.get('details', {}).get('size', 'N/A')
            first_seen = details.get('details', {}).get('first_seen', 'N/A')
            names = ', '.join(details.get('details', {}).get('names', ['N/A']))
            download_link = details.get('details', {}).get('download_link', 'N/A')
            vx_url = details.get('vx_url', details.get('details', {}).get('download_link', 'N/A'))
            
            writer.writerow([
                hash_value, 
                details['status'], 
                file_type,
                size, 
                first_seen, 
                names,
                vx_url,
                download_link,
                details.get('virustotal_url', 'N/A')
            ])

def write_to_json(file_path, data):
    """Write results to a JSON file"""
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

def pretty_print_results(results):
    """Print results with nice formatting and colors"""
    print()
    print(f"{Fore.CYAN}{'═'*80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Style.BRIGHT}{'VIRUS.XCHECK RESULTS':^80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═'*80}{Style.RESET_ALL}")
    print()
    
    for hash_value, details in results.items():
        status = details['status']
        
        # Set color based on status
        if "Found in VX database" in status:
            status_color = Fore.RED + Style.BRIGHT
            hash_color = Fore.RED
        elif "Not found" in status:
            status_color = Fore.GREEN
            hash_color = Fore.WHITE
        else:
            status_color = Fore.YELLOW
            hash_color = Fore.YELLOW
        
        # Print hash and status
        print(f"{hash_color}{Style.BRIGHT}Hash:{Style.RESET_ALL}{hash_color} {hash_value}{Style.RESET_ALL}")
        print(f"{Style.BRIGHT}Status:{Style.RESET_ALL} {status_color}{status}{Style.RESET_ALL}")
        
        # Print additional details if available
        if 'details' in details and details['details']:
            det = details['details']
            
            # Create a table of metadata
            metadata = []
            if 'type' in det:
                metadata.append([f"{Style.BRIGHT}File Type{Style.RESET_ALL}", det.get('type', 'Unknown')])
            if 'size' in det:
                size = det.get('size', 0)
                size_str = f"{size:,} bytes ({size / 1024:.1f} KB)" if size else "Unknown"
                metadata.append([f"{Style.BRIGHT}Size{Style.RESET_ALL}", size_str])
            if 'first_seen' in det:
                metadata.append([f"{Style.BRIGHT}First Seen{Style.RESET_ALL}", det.get('first_seen', 'Unknown')])
            if 'sha1' in det:
                metadata.append([f"{Style.BRIGHT}SHA-1{Style.RESET_ALL}", det.get('sha1', 'Unknown')])
            if 'md5' in det:
                metadata.append([f"{Style.BRIGHT}MD5{Style.RESET_ALL}", det.get('md5', 'Unknown')])
            
            if metadata:
                print(f"\n{Fore.CYAN}{Style.BRIGHT}File Metadata:{Style.RESET_ALL}")
                print(tabulate(metadata, tablefmt="simple"))
            
            # Show file names if available
            if 'names' in det and det['names']:
                print(f"\n{Fore.CYAN}{Style.BRIGHT}Known File Names:{Style.RESET_ALL}")
                for i, name in enumerate(det['names']):
                    print(f"  {i+1}. {Fore.WHITE}{name}{Style.RESET_ALL}")
            
            # Show tags if available
            if 'tags' in det and det['tags']:
                print(f"\n{Fore.CYAN}{Style.BRIGHT}Tags:{Style.RESET_ALL}")
                tags_str = ", ".join([f"{Fore.YELLOW}{tag}{Style.RESET_ALL}" for tag in det['tags']])
                print(f"  {tags_str}")
        
        # Print URLs
        print(f"\n{Fore.CYAN}{Style.BRIGHT}Links:{Style.RESET_ALL}")
        if 'details' in details and details['details'] and 'download_link' in details['details']:
            print(f"  {Style.BRIGHT}Download:{Style.RESET_ALL} {Fore.BLUE}{details['details']['download_link']}{Style.RESET_ALL}")
        if 'virustotal_url' in details:
            print(f"  {Style.BRIGHT}VirusTotal:{Style.RESET_ALL} {Fore.BLUE}{details['virustotal_url']}{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}{'─'*80}{Style.RESET_ALL}\n")

def update_env_file(api_key):
    """Update the .env file with a new API key"""
    env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    
    # Read existing content
    content = []
    if os.path.exists(env_file):
        with open(env_file, 'r') as f:
            content = f.readlines()
    
    # Update or add the API key
    api_key_line = f"VIRUSXCHECK_API_KEY={api_key}\n"
    api_key_found = False
    
    for i, line in enumerate(content):
        if line.startswith("VIRUSXCHECK_API_KEY="):
            content[i] = api_key_line
            api_key_found = True
            break
    
    if not api_key_found:
        if content and not content[-1].endswith('\n'):
            content.append('\n')
        if content:
            content.append('# Virus.Exchange API Key\n')
        content.append(api_key_line)
    
    # Write back to file
    with open(env_file, 'w') as f:
        f.writelines(content)

def main():
    # Restore stderr only for controlled output
    try:
        # First save original args for later use to avoid potential stderr output
        args_copy = sys.argv.copy()
        
        parser = argparse.ArgumentParser(description='Virus.xcheck CLI Tool')
        # Original options
        parser.add_argument('-f', '--file', help='Path to CSV file containing hashes')
        parser.add_argument('-o', '--output', help='Path to output file (CSV or JSON format)')
        parser.add_argument('-s', '--single', help='Single hash string to check')
        
        # API key option
        parser.add_argument('-k', '--apikey', help='Virus.Exchange API key')
        parser.add_argument('--save-config', action='store_true', help='Save API key to .env file')
        parser.add_argument('--no-color', action='store_true', help='Disable colored output')
        
        # Parse args with stderr still redirected to null_device
        args = parser.parse_args(args_copy[1:])
        
        # Now we can safely restore stderr for our controlled output
        sys.stderr = original_stderr
        
        # Check if no arguments were provided
        if len(args_copy) == 1:
            print(__doc__)  # Print ASCII art
            parser.print_help()  # Print help message
            sys.exit(1)  # Exit the script
        
        # Disable colors if requested
        if args.no_color:
            colorama.deinit()
        
        # Get API key from command line or .env file
        api_key = args.apikey if args.apikey else DEFAULT_API_KEY
        
        if not api_key:
            print(f"{Fore.RED}Error: No API key provided. Please specify an API key using the -k/--apikey option or add it to the .env file.{Style.RESET_ALL}")
            sys.exit(1)
        
        # Save API key to .env file if requested
        if args.save_config and args.apikey:
            update_env_file(api_key)
            print(f"{Fore.GREEN}API key saved to .env file{Style.RESET_ALL}")
        
        # Initialize API client
        api = VirusExchangeAPI(api_key)
        
        try:
            # Handle single hash string
            if args.single:
                results = {args.single: check_hash(args.single, api)}
            # Handle CSV file with hashes
            elif args.file:
                hash_values = read_csv(args.file)
                results = {}
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                    # Create a tqdm progress bar
                    tasks = {executor.submit(check_hash, hash_value, api): hash_value for hash_value in hash_values}
                    for future in tqdm(concurrent.futures.as_completed(tasks), total=len(tasks), desc="Processing"):
                        hash_value = tasks[future]
                        results[hash_value] = future.result()
            else:
                print(f"{Fore.RED}Error: Please provide a hash string or a path to a CSV file containing hashes.{Style.RESET_ALL}")
                exit(1)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Operation cancelled by user. Exiting.{Style.RESET_ALL}")
            sys.exit(0)

        # Output results
        if args.output:
            file_extension = args.output.split('.')[-1].lower()
            if file_extension == 'csv':
                write_to_csv(args.output, results)
                print(f"{Fore.GREEN}Results saved to {args.output}{Style.RESET_ALL}")
            elif file_extension == 'json':
                write_to_json(args.output, results)
                print(f"{Fore.GREEN}Results saved to {args.output}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Error: Output file must have a .csv or .json extension{Style.RESET_ALL}")
                exit(1)
        else:
            # Pretty print the results to the console
            pretty_print_results(results)

    finally:
        # Always restore stderr at the end
        sys.stderr = original_stderr
        # Close the null device
        null_device.close()

if __name__ == "__main__":
    main()
